"""
MABE Detector — Dataset Statistics
=====================================

Computes the population-level statistics that the velocity and enumeration
mechanisms use for dynamic threshold derivation. Runs once at startup,
before the session detection loop begins.

WHY THIS EXISTS
---------------
VelocityMechanism and EnumerationMechanism derive their Layer 1 thresholds
dynamically from the observed dataset distribution rather than using fixed
values. This means they need population-level stats before they can be
instantiated:

    VelocityMechanism(dataset_stats=velocity_stats, ...)
    EnumerationMechanism(dataset_stats=enumeration_stats, ...)

In the SIFT (batch) deployment these stats are computed by passing the
full session corpus directly to compute_velocity_dataset_stats() and
compute_enumeration_dataset_stats(). In the Splunk deployment, the corpus
lives in Splunk — this module fetches just enough data to compute the
same statistics without pulling every event record.

QUERY STRATEGY
--------------
Two targeted SPL queries, each scoped to the minimum fields needed:

Query 1 — Velocity stats:
    Needs per-session ordered timestamps to compute:
      - events/second rate per session (aggregate_rate)
      - median inter-event gap per session
    Fetches: _time, mabe_session_id only. Sorted by session + time.
    Returns lightweight session structs with timestamp-only events.

Query 2 — Enumeration stats:
    Needs per-session distinct destination count to compute:
      - mean and std of destination counts across sessions
    Uses SPL aggregation (dc(dest) by mabe_session_id) — no raw event
    retrieval needed. Returns one row per session.

Both queries use the same lookback window as the baseline scheduled search
(default 30 days) so that stats and baselines are computed from the same
population.

PAGINATION
----------
Query 1 (timestamps) can return many rows for large datasets. It uses
the same PAGE_SIZE/offset pagination as EventFetcher.

Query 2 (dest counts) returns one row per session and never hits the cap.

CACHING
-------
Both stats dicts are computed once and stored in the DatasetStatsCache
object. The cache is passed to the mechanism constructors and reused for
the entire detection run. It is not persisted between runs — recomputed
at each startup. Stats computation typically takes a few seconds on a
200-session MABE dataset.
"""

from __future__ import annotations

import logging
import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import splunklib.client as splunk_client
import splunklib.results as splunk_results

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_INDEX          = "mabe"
DEFAULT_SOURCETYPE     = "mabe:*"
DEFAULT_LOOKBACK_DAYS  = 30
PAGE_SIZE              = 900


# ---------------------------------------------------------------------------
# DatasetStatsCache
# ---------------------------------------------------------------------------

@dataclass
class DatasetStatsCache:
    """
    Holds the population-level statistics for one detection run.

    Both dicts are passed directly to the mechanism constructors:
        VelocityMechanism(dataset_stats=cache.velocity_stats, ...)
        EnumerationMechanism(dataset_stats=cache.enumeration_stats, ...)

    Fields
    ------
    velocity_stats : dict
        Output of compute_velocity_dataset_stats() equivalent.
        Keys: mean_aggregate_rate, std_aggregate_rate,
              all_median_gaps_ms, median_gap_percentiles
    enumeration_stats : dict
        Output of compute_enumeration_dataset_stats() equivalent.
        Keys: mean_destination_count, std_destination_count,
              all_destination_counts
    session_count : int
        Total sessions used to compute these stats.
    computed_at : str
        ISO 8601 timestamp of when stats were computed.
    """
    velocity_stats:    dict = field(default_factory=dict)
    enumeration_stats: dict = field(default_factory=dict)
    session_count:     int  = 0
    computed_at:       str  = ""

    def is_empty(self) -> bool:
        """True if no stats have been computed yet."""
        return self.session_count == 0


# ---------------------------------------------------------------------------
# DatasetStatsComputer
# ---------------------------------------------------------------------------

class DatasetStatsComputer:
    """
    Fetches session data from Splunk and computes dataset-level statistics.

    Parameters
    ----------
    service : splunklib.client.Service
        Connected and authenticated Splunk SDK service.
    index : str
    sourcetype_filter : str
    lookback_days : int
        How far back to look when computing population stats.
        Should match the baseline lookback window.
    page_size : int
        Events per page for timestamp retrieval pagination.
    """

    def __init__(
        self,
        service: splunk_client.Service,
        index: str = DEFAULT_INDEX,
        sourcetype_filter: str = DEFAULT_SOURCETYPE,
        lookback_days: int = DEFAULT_LOOKBACK_DAYS,
        page_size: int = PAGE_SIZE,
    ) -> None:
        self._service = service
        self._index = index
        self._sourcetype = sourcetype_filter
        self._lookback_days = lookback_days
        self._page_size = page_size

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def compute(self) -> DatasetStatsCache:
        """
        Compute all dataset statistics and return a populated cache.

        Runs both queries sequentially. Logs progress at INFO level.

        Returns
        -------
        DatasetStatsCache
            Populated cache ready to pass to mechanism constructors.
            Falls back to safe defaults on query failure so the
            detection run can continue with degraded thresholds.
        """
        logger.info(
            "Computing dataset statistics (lookback=%dd)...",
            self._lookback_days
        )

        velocity_stats    = self._compute_velocity_stats()
        enumeration_stats = self._compute_enumeration_stats()

        session_count = len(
            enumeration_stats.get("all_destination_counts", [])
        )

        cache = DatasetStatsCache(
            velocity_stats=velocity_stats,
            enumeration_stats=enumeration_stats,
            session_count=session_count,
            computed_at=_now_iso(),
        )

        logger.info(
            "Dataset stats computed. Sessions: %d, "
            "mean rate: %.4f eps, mean dest count: %.2f",
            cache.session_count,
            velocity_stats.get("mean_aggregate_rate", 0.0),
            enumeration_stats.get("mean_destination_count", 0.0),
        )
        return cache

    # ------------------------------------------------------------------
    # Velocity stats
    # ------------------------------------------------------------------

    def _compute_velocity_stats(self) -> dict:
        """
        Fetch per-session timestamps and compute velocity statistics.

        Retrieves _time and mabe_session_id for all events in the
        lookback window, reconstructs per-session timestamp lists,
        then computes aggregate rates and inter-event gaps — exactly
        mirroring what compute_velocity_dataset_stats() does from
        a local session corpus.

        Returns
        -------
        dict with keys: mean_aggregate_rate, std_aggregate_rate,
                        all_median_gaps_ms, median_gap_percentiles
        """
        spl = self._build_velocity_spl()
        logger.debug("Velocity stats SPL: %s", spl)

        raw_rows = self._run_paginated_query(spl, "velocity_stats")
        if not raw_rows:
            logger.warning(
                "No data for velocity stats — using safe defaults."
            )
            return _default_velocity_stats()

        # Group timestamps by session
        sessions_ts: dict[str, list[str]] = {}
        for row in raw_rows:
            sid = row.get("mabe_session_id", "").strip()
            ts  = row.get("_time", "").strip()
            if sid and ts:
                sessions_ts.setdefault(sid, []).append(ts)

        # Sort timestamps within each session
        for sid in sessions_ts:
            sessions_ts[sid].sort()

        # Compute per-session stats
        aggregate_rates: list[float] = []
        median_gaps:     list[float] = []

        for sid, timestamps in sessions_ts.items():
            if len(timestamps) < 2:
                continue

            try:
                duration_s = (
                    _parse_ts(timestamps[-1]) - _parse_ts(timestamps[0])
                ).total_seconds()
            except Exception:
                continue

            if duration_s > 0:
                aggregate_rates.append(len(timestamps) / duration_s)

            gaps = []
            for i in range(len(timestamps) - 1):
                try:
                    gap = (
                        _parse_ts(timestamps[i + 1]) -
                        _parse_ts(timestamps[i])
                    ).total_seconds() * 1000.0
                    if gap > 0:
                        gaps.append(gap)
                except Exception:
                    continue

            if gaps:
                median_gaps.append(statistics.median(gaps))

        if not aggregate_rates:
            logger.warning(
                "No usable sessions for velocity stats — using defaults."
            )
            return _default_velocity_stats()

        mean_rate = _mean(aggregate_rates)
        std_rate  = _std(aggregate_rates, mean_rate)

        percentiles: dict[int, float] = {}
        if median_gaps:
            sorted_gaps = sorted(median_gaps)
            n = len(sorted_gaps)
            for p in (5, 10, 25):
                idx = max(0, int(math.ceil(p / 100 * n)) - 1)
                percentiles[p] = sorted_gaps[idx]

        logger.info(
            "Velocity stats: %d sessions, mean_rate=%.4f, "
            "std_rate=%.4f, median_gaps=%d",
            len(aggregate_rates), mean_rate, std_rate, len(median_gaps)
        )

        return {
            "mean_aggregate_rate":    mean_rate,
            "std_aggregate_rate":     std_rate,
            "all_median_gaps_ms":     median_gaps,
            "median_gap_percentiles": percentiles,
        }

    def _build_velocity_spl(self) -> str:
        """
        SPL to retrieve ordered timestamps per session.

        Returns _time and mabe_session_id only — minimal payload.
        Sorted by session then time to simplify grouping on read.
        """
        return (
            f"search index={self._index}"
            f" sourcetype={self._sourcetype}"
            f" earliest=-{self._lookback_days}d@d latest=now"
            f" | table _time mabe_session_id"
            f" | sort mabe_session_id _time"
        )

    # ------------------------------------------------------------------
    # Enumeration stats
    # ------------------------------------------------------------------

    def _compute_enumeration_stats(self) -> dict:
        """
        Fetch per-session destination counts and compute enumeration stats.

        Uses SPL aggregation to compute dc(dest) per session —
        one result row per session, never hitting the event cap.

        Returns
        -------
        dict with keys: mean_destination_count, std_destination_count,
                        all_destination_counts
        """
        spl = self._build_enumeration_spl()
        logger.debug("Enumeration stats SPL: %s", spl)

        try:
            job = self._service.jobs.create(
                spl,
                exec_mode="blocking",
                count=0,
            )
        except Exception as exc:
            logger.error(
                "Failed to create enumeration stats job: %s", exc
            )
            return _default_enumeration_stats()

        dest_counts: list[int] = []
        try:
            reader = splunk_results.JSONResultsReader(
                job.results(output_mode="json", count=0)
            )
            for item in reader:
                if isinstance(item, dict):
                    raw_count = item.get("distinct_dest_count", 0)
                    try:
                        dest_counts.append(int(float(raw_count)))
                    except (ValueError, TypeError):
                        continue

        except Exception as exc:
            logger.error("Failed to read enumeration stats: %s", exc)
            return _default_enumeration_stats()
        finally:
            try:
                job.cancel()
            except Exception:
                pass

        if not dest_counts:
            logger.warning(
                "No enumeration stats data — using defaults."
            )
            return _default_enumeration_stats()

        mean_dc = _mean([float(c) for c in dest_counts])
        std_dc  = _std([float(c) for c in dest_counts], mean_dc)

        logger.info(
            "Enumeration stats: %d sessions, "
            "mean_dest=%.2f, std_dest=%.2f",
            len(dest_counts), mean_dc, std_dc
        )

        return {
            "mean_destination_count": mean_dc,
            "std_destination_count":  std_dc,
            "all_destination_counts": dest_counts,
        }

    def _build_enumeration_spl(self) -> str:
        """
        SPL to compute distinct destination count per session.

        Returns one row per session — safely under the event cap.
        """
        return (
            f"search index={self._index}"
            f" sourcetype={self._sourcetype}"
            f" earliest=-{self._lookback_days}d@d latest=now"
            f" | stats dc(dest) as distinct_dest_count"
            f"   by mabe_session_id"
        )

    # ------------------------------------------------------------------
    # Paginated query (for velocity timestamps)
    # ------------------------------------------------------------------

    def _run_paginated_query(
        self,
        spl: str,
        label: str,
    ) -> list[dict]:
        """
        Run a Splunk query with offset-based pagination.

        Same pattern as EventFetcher._run_paginated_query.
        Used for the velocity timestamp query which can return
        O(n_events) rows across all sessions.

        Parameters
        ----------
        spl : str
        label : str
            Used in log messages.

        Returns
        -------
        list[dict]
            All result rows.
        """
        try:
            job = self._service.jobs.create(
                spl,
                exec_mode="blocking",
                count=0,
            )
        except Exception as exc:
            logger.error(
                "Failed to create %s job: %s", label, exc
            )
            return []

        all_rows: list[dict] = []
        offset = 0

        try:
            while True:
                try:
                    results_stream = job.results(
                        output_mode="json",
                        count=self._page_size,
                        offset=offset,
                    )
                    reader = splunk_results.JSONResultsReader(
                        results_stream
                    )
                    page: list[dict] = [
                        item for item in reader
                        if isinstance(item, dict)
                    ]
                except Exception as exc:
                    logger.error(
                        "%s: error reading page at offset %d: %s",
                        label, offset, exc
                    )
                    break

                all_rows.extend(page)

                if len(page) < self._page_size:
                    break

                offset += len(page)

        finally:
            try:
                job.cancel()
            except Exception:
                pass

        logger.debug("%s: retrieved %d rows", label, len(all_rows))
        return all_rows

    # ------------------------------------------------------------------
    # SPL accessors (for MCP demo layer)
    # ------------------------------------------------------------------

    def get_velocity_spl(self) -> str:
        """Return velocity stats SPL without executing it."""
        return self._build_velocity_spl()

    def get_enumeration_spl(self) -> str:
        """Return enumeration stats SPL without executing it."""
        return self._build_enumeration_spl()


# ---------------------------------------------------------------------------
# Safe defaults
# ---------------------------------------------------------------------------

def _default_velocity_stats() -> dict:
    """
    Safe fallback velocity stats when Splunk query fails.

    Uses MABE's documented benign user parameters as defaults:
        inter_event_ms_median: 180,000ms (3 minutes)
    This produces conservative thresholds that avoid false positives
    at the cost of reduced sensitivity.
    """
    return {
        "mean_aggregate_rate":    0.01,    # ~1 event per 100 seconds
        "std_aggregate_rate":     0.005,
        "all_median_gaps_ms":     [180_000.0],
        "median_gap_percentiles": {5: 5_000.0, 10: 10_000.0, 25: 30_000.0},
    }


def _default_enumeration_stats() -> dict:
    """
    Safe fallback enumeration stats when Splunk query fails.

    Uses MABE's documented benign user typical_host_count: 4.
    """
    return {
        "mean_destination_count": 4.0,
        "std_destination_count":  2.0,
        "all_destination_counts": [4],
    }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _parse_ts(ts: str) -> datetime:
    """Parse ISO 8601 timestamp with Z suffix."""
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )


def _now_iso() -> str:
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: list[float], mean: float) -> float:
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)
