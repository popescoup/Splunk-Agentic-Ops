"""
MABE Detector — Splunk Detection Run Entry Point
==================================================

End-to-end detection pipeline for the Splunk Agentic Ops Hackathon
submission. Wires together all components in detector-splunk/splunk/
and runs the full detection loop against MABE data ingested in Splunk.

USAGE
-----
    # Full batch run (all sessions in index)
    python -m splunk.main

    # Recent sessions only (near-real-time mode, last 30 minutes)
    python -m splunk.main --mode recent --lookback-minutes 30

    # Specific time window
    python -m splunk.main --mode window --earliest -24h --latest now

    # Force baseline refresh before detection
    python -m splunk.main --refresh-baseline

    # Skip narrative enhancement (faster, no API cost)
    python -m splunk.main --no-narrative

ENVIRONMENT VARIABLES
---------------------
    SPLUNK_HOST         Splunk instance hostname (default: localhost)
    SPLUNK_PORT         Splunk REST API port (default: 8089)
    SPLUNK_TOKEN        Token-based auth (preferred)
    SPLUNK_USERNAME     Basic auth fallback
    SPLUNK_PASSWORD     Basic auth fallback
    SPLUNK_INDEX        Index to query (default: mabe)
    ANTHROPIC_API_KEY   Required for narrative enhancement

SPLUNK MCP INTEGRATION
----------------------
This script surfaces the SPL queries it executes at each stage as INFO
log entries prefixed with [MCP_SPL]. These are the exact same queries
issued via the splunk_run_query MCP tool in the agentic demo context.

In the hackathon agentic demo, an orchestrating Claude instance with the
Splunk MCP Server connected would issue these queries directly via tool
calls rather than through the SDK. The detection logic is identical —
only the transport layer differs.

PIPELINE SEQUENCE
-----------------
1. Connect to Splunk
2. Ensure KV Store collection exists
3. Check baseline staleness — refresh if stale or forced
4. Compute dataset statistics (velocity + enumeration population stats)
5. Load all account baselines from KV Store
6. Enumerate session IDs from index
7. Build DetectionRunner (mechanisms instantiated once)
8. Detection loop — process sessions, collect CorrelationOutputs
9. Generate LLM narratives for alerted sessions
10. Format and write notable events to Splunk
11. Print run summary
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Logging setup — must happen before any module imports that log
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("mabe.splunk.main")


# ---------------------------------------------------------------------------
# Load .env if present
# ---------------------------------------------------------------------------

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Splunk specialization imports
# ---------------------------------------------------------------------------

from splunk.ingestion.session_enumerator import (
    SessionEnumerator,
    connect_to_splunk,
)
from splunk.ingestion.event_fetcher      import EventFetcher
from splunk.baseline.scheduled_search   import BaselineKVManager
from splunk.baseline.kv_reader          import KVBaselineReader
from splunk.detection.dataset_stats     import DatasetStatsComputer
from splunk.detection.runner            import DetectionRunner
from splunk.output.spl_ref_builder      import (
    SplRefBuilder,
    make_session_ref_builder,
)
from splunk.output.notable_event        import (
    NotableEventFormatter,
    NotableEventWriter,
)
from splunk.output.narrative            import NarrativeEnhancer


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MABE Detector — Splunk detection run"
    )
    parser.add_argument(
        "--mode",
        choices=["all", "recent", "window"],
        default="all",
        help=(
            "Session enumeration mode. "
            "'all': all sessions in index (default). "
            "'recent': sessions active in last --lookback-minutes. "
            "'window': sessions in --earliest to --latest window."
        ),
    )
    parser.add_argument(
        "--lookback-minutes",
        type=int,
        default=30,
        help="Lookback window in minutes for --mode recent. Default: 30.",
    )
    parser.add_argument(
        "--earliest",
        type=str,
        default="-24h",
        help="Earliest time for --mode window. Default: -24h.",
    )
    parser.add_argument(
        "--latest",
        type=str,
        default="now",
        help="Latest time for --mode window. Default: now.",
    )
    parser.add_argument(
        "--refresh-baseline",
        action="store_true",
        help="Force baseline refresh before detection, even if not stale.",
    )
    parser.add_argument(
        "--no-narrative",
        action="store_true",
        help="Skip LLM narrative enhancement. Faster, no API cost.",
    )
    parser.add_argument(
        "--index",
        type=str,
        default=None,
        help="Splunk index to query. Default: SPLUNK_INDEX env var or 'mabe'.",
    )
    parser.add_argument(
        "--alert-threshold",
        type=float,
        default=0.60,
        help="Alert confidence threshold. Default: 0.60 (Splunk SOC mode).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Run detection but do not write notable events to Splunk. "
            "Prints alert summaries to stdout instead."
        ),
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = _parse_args()

    index = (
        args.index
        or os.environ.get("SPLUNK_INDEX", "mabe")
    )

    run_start = _now_iso()
    logger.info("=" * 60)
    logger.info("MABE Detector — Splunk run started at %s", run_start)
    logger.info("Index: %s | Mode: %s | Alert threshold: %.2f",
                index, args.mode, args.alert_threshold)
    logger.info("=" * 60)

    # ── Step 1: Connect to Splunk ────────────────────────────────────
    logger.info("Step 1/10 — Connecting to Splunk...")
    try:
        service = connect_to_splunk()
    except Exception as exc:
        logger.error("Failed to connect to Splunk: %s", exc)
        return 1

    # ── Step 2: Ensure KV Store collection exists ────────────────────
    logger.info("Step 2/10 — Ensuring KV Store collection exists...")
    kv_manager = BaselineKVManager(service=service, index=index)
    if not kv_manager.ensure_collection_exists():
        logger.error(
            "Could not create KV Store collection 'mabe_baselines'. "
            "Check Splunk permissions."
        )
        return 1

    # ── Step 3: Baseline refresh check ──────────────────────────────
    logger.info("Step 3/10 — Checking baseline staleness...")
    kv_reader = KVBaselineReader(service=service)

    baseline_spl = kv_manager.get_baseline_spl()
    logger.info("[MCP_SPL] Baseline computation SPL:\n%s", baseline_spl)

    if args.refresh_baseline or kv_reader.is_stale():
        logger.info(
            "Baselines are stale or refresh forced — running baseline "
            "refresh (this may take 30–60 seconds)..."
        )
        if not kv_manager.run_baseline_refresh():
            logger.warning(
                "Baseline refresh encountered errors. "
                "Detection will proceed with existing baselines."
            )
    else:
        logger.info("Baselines are fresh — skipping refresh.")

    # ── Step 4: Compute dataset statistics ──────────────────────────
    logger.info("Step 4/10 — Computing dataset statistics...")
    stats_computer = DatasetStatsComputer(
        service=service,
        index=index,
        lookback_days=30,
    )

    logger.info(
        "[MCP_SPL] Velocity stats SPL:\n%s",
        stats_computer.get_velocity_spl()
    )
    logger.info(
        "[MCP_SPL] Enumeration stats SPL:\n%s",
        stats_computer.get_enumeration_spl()
    )

    stats_cache = stats_computer.compute()
    if stats_cache.is_empty():
        logger.error(
            "Dataset stats computation returned no data. "
            "Ensure MABE data is ingested in index '%s'.", index
        )
        return 1

    # ── Step 5: Load baselines from KV Store ────────────────────────
    logger.info("Step 5/10 — Loading account baselines from KV Store...")

    population_spl = kv_reader.get_lookup_spl("__population__")
    logger.info("[MCP_SPL] Population baseline lookup SPL:\n%s", population_spl)

    baselines = kv_reader.get_all_baselines()
    logger.info(
        "Loaded %d baseline row(s). Population fallback: %s",
        len(baselines),
        "available" if "__population__" in baselines else "absent"
    )

    # ── Step 6: Enumerate session IDs ───────────────────────────────
    logger.info("Step 6/10 — Enumerating session IDs...")
    enumerator = SessionEnumerator(service=service, index=index)

    if args.mode == "all":
        enum_spl = enumerator.get_enumeration_spl()
        logger.info("[MCP_SPL] Session enumeration SPL:\n%s", enum_spl)
        session_ids = enumerator.get_all_session_ids()

    elif args.mode == "recent":
        enum_spl = enumerator.get_enumeration_spl(
            earliest=f"-{args.lookback_minutes}m"
        )
        logger.info("[MCP_SPL] Session enumeration SPL:\n%s", enum_spl)
        session_ids = enumerator.get_recent_session_ids(
            lookback_minutes=args.lookback_minutes
        )

    else:  # window
        enum_spl = enumerator.get_enumeration_spl(
            earliest=args.earliest, latest=args.latest
        )
        logger.info("[MCP_SPL] Session enumeration SPL:\n%s", enum_spl)
        session_ids = enumerator.get_session_ids_in_window(
            earliest=args.earliest, latest=args.latest
        )

    if not session_ids:
        logger.warning(
            "No session IDs found in index '%s' for mode '%s'. "
            "Ensure MABE data is ingested and mabe_session_id is present.",
            index, args.mode
        )
        return 0

    logger.info("Found %d session(s) to evaluate.", len(session_ids))

    # ── Step 7: Build detection runner ──────────────────────────────
    logger.info("Step 7/10 — Building detection runner...")

    event_fetcher = EventFetcher(service=service, index=index)
    spl_builder   = SplRefBuilder(index=index)
    session_ref_builder = spl_builder.build

    # Log an example event fetch SPL
    if session_ids:
        example_spl = event_fetcher.get_event_spl(session_ids[0])
        logger.info(
            "[MCP_SPL] Example event fetch SPL (session %s):\n%s",
            session_ids[0], example_spl
        )

    runner = DetectionRunner(
        event_fetcher=event_fetcher,
        stats_cache=stats_cache,
        baselines=baselines,
        session_ref_builder=session_ref_builder,
        alert_threshold=args.alert_threshold,
    )

    # ── Step 8: Detection loop ───────────────────────────────────────
    logger.info(
        "Step 8/10 — Running detection loop (%d sessions)...",
        len(session_ids)
    )

    results = runner.run_sessions(session_ids)

    alerted  = [r for r in results if r.alert_triggered]
    cleared  = [r for r in results if not r.alert_triggered]

    logger.info(
        "Detection complete. Total: %d | Alerts: %d | Clear: %d",
        len(results), len(alerted), len(cleared)
    )

    if not results:
        logger.warning("No results produced — all sessions had no events.")
        return 0

    # ── Step 9: Generate narratives ──────────────────────────────────
    narratives: dict[str, str] = {}

    if alerted and not args.no_narrative:
        logger.info(
            "Step 9/10 — Generating LLM narratives for %d alert(s)...",
            len(alerted)
        )
        narrative_enabled = bool(os.environ.get("ANTHROPIC_API_KEY"))
        if not narrative_enabled:
            logger.warning(
                "ANTHROPIC_API_KEY not set — using programmatic narratives."
            )
        enhancer = NarrativeEnhancer(enabled=narrative_enabled)
        narratives = enhancer.enhance_batch(alerted)
    else:
        logger.info("Step 9/10 — Narrative generation skipped.")

    # ── Step 10: Format and write notable events ─────────────────────
    logger.info("Step 10/10 — Formatting and writing notable events...")

    formatter = NotableEventFormatter(spl_builder=spl_builder)
    notable_events = formatter.format_batch(alerted, narratives=narratives)

    if not notable_events:
        logger.info("No alerts triggered — no notable events to write.")
    elif args.dry_run:
        logger.info(
            "DRY RUN — %d notable event(s) would be written:",
            len(notable_events)
        )
        for ne in notable_events:
            _print_notable_summary(ne)
    else:
        writer = NotableEventWriter(service=service)
        success, failure = writer.write_batch(notable_events)
        logger.info(
            "Notable events written: %d success, %d failure.",
            success, failure
        )

    # ── Run summary ──────────────────────────────────────────────────
    _print_run_summary(results, alerted, narratives, run_start)

    return 0 if not notable_events or not args.dry_run else 0


# ---------------------------------------------------------------------------
# Summary output
# ---------------------------------------------------------------------------

def _print_run_summary(
    results: list,
    alerted: list,
    narratives: dict[str, str],
    run_start: str,
) -> None:
    """Print a concise end-of-run summary to stdout."""
    run_end = _now_iso()

    print("\n" + "=" * 60)
    print("MABE DETECTOR — RUN SUMMARY")
    print("=" * 60)
    print(f"Run started:    {run_start}")
    print(f"Run completed:  {run_end}")
    print(f"Sessions evaluated: {len(results)}")
    print(f"Alerts triggered:   {len(alerted)}")
    print(f"Clear (no alert):   {len(results) - len(alerted)}")

    if alerted:
        print("\n── ALERTED SESSIONS ────────────────────────────────────")
        for result in sorted(
            alerted, key=lambda r: r.overall_confidence, reverse=True
        ):
            tc = result.triage_card
            scores = tc.mechanism_scores
            print(
                f"\n  Session:    {result.session_id}"
                f"\n  Account:    {tc.account}"
                f"\n  Confidence: {result.overall_confidence:.4f} "
                f"(threshold: {result.alert_threshold:.2f})"
                f"\n  Velocity:   {scores.get('velocity', 0):.4f}  "
                f"Enumeration: {scores.get('enumeration', 0):.4f}  "
                f"Priv-esc:    {scores.get('priv_escalation', 0):.4f}"
                f"\n  Layers:     "
                + "  ".join(
                    f"{m}=L{l}"
                    for m, l in result.highest_layer_per_mechanism.items()
                )
                + f"\n  Narrative:  "
                + (narratives.get(result.session_id) or tc.plain_english)
                + f"\n  Drilldown:  {result.session_ref}"
            )

    print("\n" + "=" * 60)


def _print_notable_summary(notable: dict) -> None:
    """Print a one-line summary of a notable event (dry-run mode)."""
    print(
        f"  [{notable.get('severity', '?').upper():12s}] "
        f"session={notable.get('mabe_session_id', '?')[:8]}...  "
        f"account={notable.get('user', '?')}  "
        f"confidence={notable.get('mabe_overall_confidence', 0):.4f}  "
        f"rule={notable.get('rule_name', '?')}"
    )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())
