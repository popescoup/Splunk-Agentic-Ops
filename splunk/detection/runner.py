"""
MABE Detector — Splunk Detection Runner
========================================

Orchestrates per-session detection: fetches events, runs the three
mechanisms in streaming/gated mode, correlates results, and returns
a CorrelationOutput for each session.

DESIGN
------
The runner is instantiated once per detection run with pre-built shared
state (dataset stats, baselines, mechanism instances). It then processes
sessions one at a time via run_session().

Mechanism instances are created once at runner construction and reused
across sessions — they are stateless between evaluate() calls.

STREAMING MODE (SPLUNK)
-----------------------
In streaming/real-time mode, layer gating is a genuine compute gate:
Layer 2 does not run unless Layer 1 fires; Layer 3 does not run unless
Layer 2 fires. This is the primary behavioural difference from SIFT
forensic mode (where all layers always run for consistency).

The mechanisms already implement this gating internally — they return
early with a low-confidence MechanismOutput when a layer doesn't fire.
The runner honours this by checking output.fired and output.highest_layer
to decide whether to log the early exit, but does not need to bypass the
mechanism call itself. The compute savings are inside the mechanism.

ALERT THRESHOLD
---------------
Splunk deployment uses alert_threshold=0.60 (precision-optimised, SOC
real-time mode). This is injected via alert_threshold_override on the
CorrelationAgent. The SIFT forensic deployment uses 0.35.

INLINE EVIDENCE
---------------
EvidenceRef.inline is left None in Splunk streaming mode. The session_ref
SPL query (Level 3) is the drill-down path. This is consistent with the
design spec and avoids embedding full event records in the notable event.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from core.mechanisms.velocity      import VelocityMechanism
from core.mechanisms.enumeration   import EnumerationMechanism
from core.mechanisms.priv_escalation import PrivEscMechanism
from core.correlation.agent        import CorrelationAgent
from core.schema                   import (
    MechanismOutput,
    CorrelationOutput,
    MECHANISM_VELOCITY,
    MECHANISM_ENUMERATION,
    MECHANISM_PRIV_ESC,
)
from core.config_loader            import load_thresholds
from core.node_classifier          import NodeClassifier

from splunk.detection.dataset_stats import DatasetStatsCache
from splunk.ingestion.event_fetcher import EventFetcher

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Alert threshold for Splunk SOC deployment
# ---------------------------------------------------------------------------

SPLUNK_ALERT_THRESHOLD = 0.60


# ---------------------------------------------------------------------------
# DetectionRunner
# ---------------------------------------------------------------------------

class DetectionRunner:
    """
    Runs the three-mechanism detection pipeline for individual sessions.

    Parameters
    ----------
    event_fetcher : EventFetcher
        Configured event fetcher for retrieving session events from Splunk.
    stats_cache : DatasetStatsCache
        Pre-computed population statistics. Must not be empty.
    baselines : dict[str, AccountBaseline]
        Pre-loaded per-account baselines from KVBaselineReader.get_all_baselines().
        Passed to EnumerationMechanism at construction.
    session_ref_builder : callable
        Function (session_id: str) -> str that produces the Level 3 SPL
        drill-down query. Injected into CorrelationAgent.
    thresholds : dict | None
        Loaded thresholds config. If None, loads from config file.
    alert_threshold : float
        Override alert threshold. Default: 0.60 (Splunk SOC mode).
    """

    def __init__(
        self,
        event_fetcher: EventFetcher,
        stats_cache: DatasetStatsCache,
        baselines: dict,
        session_ref_builder: callable,
        thresholds: dict | None = None,
        alert_threshold: float = SPLUNK_ALERT_THRESHOLD,
    ) -> None:
        if stats_cache.is_empty():
            raise ValueError(
                "DatasetStatsCache is empty. Run DatasetStatsComputer.compute() "
                "before constructing DetectionRunner."
            )

        self._fetcher = event_fetcher
        self._stats_cache = stats_cache
        self._baselines = baselines

        cfg = thresholds or load_thresholds()

        # Shared NodeClassifier — one instance, reused across all mechanisms
        classifier = NodeClassifier()

        # Instantiate mechanisms once — reused across all sessions
        self._velocity = VelocityMechanism(
            dataset_stats=stats_cache.velocity_stats,
            thresholds=cfg,
        )
        self._enumeration = EnumerationMechanism(
            dataset_stats=stats_cache.enumeration_stats,
            baselines=baselines,
            thresholds=cfg,
            classifier=classifier,
        )
        self._priv_esc = PrivEscMechanism(
            thresholds=cfg,
            classifier=classifier,
        )

        # Correlation agent with Splunk-specific threshold and session ref
        self._agent = CorrelationAgent(
            thresholds=cfg,
            alert_threshold_override=alert_threshold,
            session_ref_builder=session_ref_builder,
        )

        logger.info(
            "DetectionRunner ready. Alert threshold: %.2f. "
            "Dataset: %d sessions.",
            alert_threshold,
            stats_cache.session_count,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run_session(
        self,
        session_id: str,
        account: Optional[str] = None,
    ) -> Optional[CorrelationOutput]:
        """
        Run the full detection pipeline for one session.

        Fetches events from Splunk, runs the three mechanisms in gated
        streaming mode, correlates results, and returns a CorrelationOutput.

        Parameters
        ----------
        session_id : str
            mabe_session_id to evaluate.
        account : str | None
            Account identifier. If None, inferred from session events.

        Returns
        -------
        CorrelationOutput | None
            None if no events are found for this session.
        """
        evaluated_at = _now_iso()

        # ── Fetch events ─────────────────────────────────────────────
        events = self._fetcher.fetch_session_events(session_id)
        if not events:
            logger.warning(
                "Session %s: no events found — skipping.", session_id
            )
            return None

        # Resolve account from events if not provided
        if not account:
            account = _infer_account(events)
        if not account:
            logger.warning(
                "Session %s: could not determine account — "
                "using '__unknown__'.",
                session_id
            )
            account = "__unknown__"

        logger.info(
            "Session %s (%s): %d events — running detection.",
            session_id, account, len(events)
        )

        # ── Run mechanisms ────────────────────────────────────────────
        mechanism_outputs = self._run_mechanisms(
            session_id, account, events, evaluated_at
        )

        # ── Correlate ─────────────────────────────────────────────────
        result = self._agent.correlate(
            session_id=session_id,
            account=account,
            mechanism_outputs=mechanism_outputs,
        )

        self._log_result(result, account)
        return result

    def run_sessions(
        self,
        session_ids: list[str],
        accounts: Optional[dict[str, str]] = None,
    ) -> list[CorrelationOutput]:
        """
        Run detection across a list of session IDs.

        Parameters
        ----------
        session_ids : list[str]
            Ordered list of session IDs to process.
        accounts : dict[str, str] | None
            Optional pre-known mapping of session_id → account.
            If provided, skips account inference from events.

        Returns
        -------
        list[CorrelationOutput]
            Results for sessions that had events. Sessions with no
            events are silently skipped.
        """
        results: list[CorrelationOutput] = []
        total = len(session_ids)

        for i, session_id in enumerate(session_ids, start=1):
            account = (accounts or {}).get(session_id)
            logger.info(
                "Processing session %d/%d: %s", i, total, session_id
            )
            result = self.run_session(session_id, account=account)
            if result is not None:
                results.append(result)

        alerts = sum(1 for r in results if r.alert_triggered)
        logger.info(
            "Detection run complete. Sessions processed: %d, "
            "alerts triggered: %d.",
            len(results), alerts
        )
        return results

    # ------------------------------------------------------------------
    # Mechanism execution (gated streaming mode)
    # ------------------------------------------------------------------

    def _run_mechanisms(
        self,
        session_id: str,
        account: str,
        events: list[dict],
        evaluated_at: str,
    ) -> list[MechanismOutput]:
        """
        Run all three mechanisms and collect their outputs.

        In streaming mode, each mechanism gates internally — Layer 2
        does not compute unless Layer 1 fires, etc. The runner collects
        all non-None outputs regardless of whether they fired, so that
        the correlation agent can distinguish absent from present-but-weak.

        Parameters
        ----------
        session_id : str
        account : str
        events : list[dict]
        evaluated_at : str

        Returns
        -------
        list[MechanismOutput]
            All non-None outputs. Absent mechanisms (None return) are
            excluded — the correlation agent treats them as absent.
        """
        outputs: list[MechanismOutput] = []

        # ── Velocity ──────────────────────────────────────────────────
        try:
            vel_output = self._velocity.evaluate(
                session_id=session_id,
                events=events,
                evaluated_at=evaluated_at,
            )
            if vel_output is not None:
                outputs.append(vel_output)
                logger.debug(
                    "Session %s velocity: fired=%s, confidence=%.4f, "
                    "highest_layer=%d",
                    session_id,
                    vel_output.fired,
                    vel_output.confidence,
                    vel_output.highest_layer,
                )
        except Exception as exc:
            logger.error(
                "Session %s velocity mechanism error: %s",
                session_id, exc, exc_info=True
            )

        # ── Enumeration ───────────────────────────────────────────────
        try:
            enum_output = self._enumeration.evaluate(
                session_id=session_id,
                account=account,
                events=events,
                evaluated_at=evaluated_at,
            )
            if enum_output is not None:
                outputs.append(enum_output)
                logger.debug(
                    "Session %s enumeration: fired=%s, confidence=%.4f, "
                    "highest_layer=%d",
                    session_id,
                    enum_output.fired,
                    enum_output.confidence,
                    enum_output.highest_layer,
                )
        except Exception as exc:
            logger.error(
                "Session %s enumeration mechanism error: %s",
                session_id, exc, exc_info=True
            )

        # ── Privilege escalation ──────────────────────────────────────
        try:
            pe_output = self._priv_esc.evaluate(
                session_id=session_id,
                account=account,
                events=events,
                evaluated_at=evaluated_at,
                initial_privilege="standard_user",
            )
            if pe_output is not None:
                outputs.append(pe_output)
                logger.debug(
                    "Session %s priv_esc: fired=%s, confidence=%.4f, "
                    "highest_layer=%d",
                    session_id,
                    pe_output.fired,
                    pe_output.confidence,
                    pe_output.highest_layer,
                )
        except Exception as exc:
            logger.error(
                "Session %s priv_esc mechanism error: %s",
                session_id, exc, exc_info=True
            )

        fired_count = sum(1 for o in outputs if o.fired)
        logger.debug(
            "Session %s: %d mechanism(s) produced output, "
            "%d fired.",
            session_id, len(outputs), fired_count
        )
        return outputs

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log_result(
        self,
        result: CorrelationOutput,
        account: str,
    ) -> None:
        """Log a concise summary of the correlation result."""
        if result.alert_triggered:
            logger.warning(
                "ALERT  session=%s account=%s confidence=%.4f "
                "mechanisms_fired=%s",
                result.session_id,
                account,
                result.overall_confidence,
                result.mechanisms_fired,
            )
        else:
            logger.info(
                "CLEAR  session=%s account=%s confidence=%.4f",
                result.session_id,
                account,
                result.overall_confidence,
            )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _infer_account(events: list[dict]) -> Optional[str]:
    """Return the first non-empty 'user' value from a list of events."""
    for event in events:
        user = event.get("user")
        if user and isinstance(user, str) and user.strip():
            return user.strip()
    return None


def _now_iso() -> str:
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
