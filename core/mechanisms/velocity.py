"""
MABE Detector — Velocity Detection Mechanism
=============================================
Version: 1.0.0

Detects machine-speed inter-event timing inconsistent with human operation.

EMPIRICAL BASIS
---------------
GTG-1002: "Peak activity included thousands of requests, representing
sustained request rates of multiple operations per second."
SANS/Lee: 47–158x velocity differential between AI agents and human
operators. Conservative lower bound 47x applied.

THREE LAYERS
------------
L1 — Aggregate session rate (events/second)
     O(n): two timestamp reads + one division.
     Fires when session rate > mean + N*std of observed distribution.

L2 — Median inter-event gap (milliseconds)
     O(n log n): requires sorting.
     Fires when median gap < Nth percentile of observed distribution.

L3 — Distributional consistency (coefficient of variation)
     O(n): single pass after L2 sort.
     Fires when session is fast (L2 fired) AND timing is consistent
     (low CV). Combination of speed + consistency is the strongest signal.

CONFIDENCE FORMULA
------------------
confidence = (w_L1 * intensity_L1) + (w_L2 * intensity_L2) + (w_L3 * intensity_L3)

Layer intensities use linear ramp between calibration points:
    intensity = clamp((observed - lower) / (upper - lower), 0.0, 1.0)
Direction of anomaly varies per signal (low gap = anomalous for velocity).
"""

from __future__ import annotations

import math
import statistics
from datetime import datetime, timezone
from typing import Optional

from core.schema import (
    MechanismOutput,
    Signal,
    EvidenceRef,
    TimeWindow,
    MECHANISM_VELOCITY,
)
from core.config_loader import load_thresholds, get_layer_weights

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

MECHANISM_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

def _parse_ts(ts: str) -> datetime:
    """Parse ISO 8601 timestamp with Z suffix."""
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )


def _gap_ms(ts_a: str, ts_b: str) -> float:
    """Return milliseconds between two ISO 8601 timestamps."""
    return (_parse_ts(ts_b) - _parse_ts(ts_a)).total_seconds() * 1000.0


# ---------------------------------------------------------------------------
# Dataset-level statistics (preprocessing)
# ---------------------------------------------------------------------------

def compute_velocity_dataset_stats(sessions: list[dict]) -> dict:
    """
    Compute dataset-level velocity statistics for dynamic threshold derivation.

    Must be called once before running the mechanism on individual sessions.
    Pass the returned stats dict to VelocityMechanism.

    Parameters
    ----------
    sessions : list[dict]
        All sessions in the dataset. Each session must have:
            - "events": list[dict] with "timestamp" fields

    Returns
    -------
    dict with keys:
        mean_aggregate_rate     float  events/second mean across sessions
        std_aggregate_rate      float  events/second std
        all_median_gaps_ms      list   per-session median inter-event gaps
        median_gap_percentiles  dict   {5: val, 10: val, 25: val}
    """
    aggregate_rates: list[float] = []
    median_gaps: list[float] = []

    for session in sessions:
        events = session.get("events", [])
        if len(events) < 2:
            continue

        timestamps = sorted(
            e.get("timestamp", "") for e in events if e.get("timestamp")
        )
        if len(timestamps) < 2:
            continue

        # Aggregate rate: events / session_duration_seconds
        try:
            duration_s = (
                _parse_ts(timestamps[-1]) - _parse_ts(timestamps[0])
            ).total_seconds()
        except Exception:
            continue

        if duration_s > 0:
            rate = len(timestamps) / duration_s
            aggregate_rates.append(rate)

        # Per-session inter-event gaps
        gaps = [
            _gap_ms(timestamps[i], timestamps[i + 1])
            for i in range(len(timestamps) - 1)
            if _gap_ms(timestamps[i], timestamps[i + 1]) > 0
        ]
        if gaps:
            median_gaps.append(statistics.median(gaps))

    mean_rate = _trimmed_mean(aggregate_rates)
    std_rate = _trimmed_std(aggregate_rates, mean_rate)

    percentiles = {}
    if median_gaps:
        sorted_gaps = sorted(median_gaps)
        n = len(sorted_gaps)
        for p in (5, 10, 25):
            idx = max(0, int(math.ceil(p / 100 * n)) - 1)
            percentiles[p] = sorted_gaps[idx]

    return {
        "mean_aggregate_rate":    mean_rate,
        "std_aggregate_rate":     std_rate,
        "all_median_gaps_ms":     median_gaps,
        "median_gap_percentiles": percentiles,
    }


# ---------------------------------------------------------------------------
# VelocityMechanism
# ---------------------------------------------------------------------------

class VelocityMechanism:
    """
    Three-layer velocity detection mechanism.

    Parameters
    ----------
    dataset_stats : dict
        Output of compute_velocity_dataset_stats(). Required for dynamic
        threshold derivation.
    thresholds : dict | None
        Loaded thresholds config. If None, loads from config file.
    layer_weights : dict | None
        Layer weights {"L1": float, "L2": float, "L3": float}.
        If None, loads from config.
    """

    def __init__(
        self,
        dataset_stats: dict,
        thresholds: dict | None = None,
        layer_weights_override: dict | None = None,
    ) -> None:
        cfg = thresholds or load_thresholds()
        self._v_cfg = cfg.get("velocity", {})
        self._layer_weights = layer_weights_override or get_layer_weights(cfg)
        self._stats = dataset_stats

        # Derive dynamic thresholds from dataset stats
        self._l1_threshold = self._derive_l1_threshold()
        self._l2_threshold = self._derive_l2_threshold()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def evaluate(
        self,
        session_id: str,
        events: list[dict],
        evaluated_at: str,
    ) -> Optional[MechanismOutput]:
        """
        Evaluate velocity for a single session.

        Parameters
        ----------
        session_id : str
            Session UUID.
        events : list[dict]
            All events for this session, in any order.
            Each event must have a "timestamp" field.
        evaluated_at : str
            ISO 8601 timestamp of evaluation time.

        Returns
        -------
        MechanismOutput | None
            None if the session has fewer than 2 events (not evaluable).
            Otherwise always returns a MechanismOutput, even if no layer fires.
        """
        if len(events) < 2:
            return None

        timestamps = sorted(
            e.get("timestamp", "")
            for e in events
            if e.get("timestamp")
        )
        if len(timestamps) < 2:
            return None

        data_window = TimeWindow(start=timestamps[0], end=timestamps[-1])

        # Compute inter-event gaps
        gaps_ms = [
            _gap_ms(timestamps[i], timestamps[i + 1])
            for i in range(len(timestamps) - 1)
            if _gap_ms(timestamps[i], timestamps[i + 1]) > 0
        ]
        if not gaps_ms:
            return None

        try:
            duration_s = (
                _parse_ts(timestamps[-1]) - _parse_ts(timestamps[0])
            ).total_seconds()
        except Exception:
            return None

        aggregate_rate = len(timestamps) / duration_s if duration_s > 0 else 0.0

        # ── Layer 1 ───────────────────────────────────────────────────
        l1_intensity, l1_fired, l1_signals = self._evaluate_l1(
            aggregate_rate, duration_s, len(timestamps)
        )

        if not l1_fired:
            return self._no_fire_output(
                session_id, evaluated_at, data_window,
                aggregate_rate, duration_s, len(timestamps), gaps_ms
            )

        # ── Layer 2 ───────────────────────────────────────────────────
        median_gap = statistics.median(gaps_ms)
        l2_intensity, l2_fired, l2_signals = self._evaluate_l2(
            median_gap, gaps_ms
        )

        if not l2_fired:
            confidence = self._layer_weights["L1"] * l1_intensity
            signals = l1_signals
            evidence = self._build_evidence(timestamps, gaps_ms, events, 1)
            return self._build_output(
                session_id, evaluated_at, data_window,
                confidence, self._l1_threshold, True, 1, signals, evidence
            )

        # ── Layer 3 ───────────────────────────────────────────────────
        l3_intensity, l3_fired, l3_signals = self._evaluate_l3(
            gaps_ms, median_gap
        )

        highest_layer = 3 if l3_fired else 2
        confidence = (
            self._layer_weights["L1"] * l1_intensity
            + self._layer_weights["L2"] * l2_intensity
            + (self._layer_weights["L3"] * l3_intensity if l3_fired else 0.0)
        )
        confidence = min(confidence, 1.0)

        all_signals = l1_signals + l2_signals + (l3_signals if l3_fired else [])
        all_signals.sort(key=lambda s: s.contribution, reverse=True)
        evidence = self._build_evidence(timestamps, gaps_ms, events, highest_layer)

        return self._build_output(
            session_id, evaluated_at, data_window,
            confidence, self._l1_threshold, True,
            highest_layer, all_signals, evidence
        )

    # ------------------------------------------------------------------
    # Layer evaluators
    # ------------------------------------------------------------------

    def _evaluate_l1(
        self,
        aggregate_rate: float,
        duration_s: float,
        event_count: int,
    ) -> tuple[float, bool, list[Signal]]:
        """
        Layer 1: aggregate session rate (events/second).

        Returns (intensity, fired, signals).
        """
        if aggregate_rate <= self._l1_threshold:
            return 0.0, False, []

        # Intensity: linear ramp from threshold to upper calibration
        upper_ratio = float(
            self._v_cfg.get("L1_intensity_upper_ratio", 10.0)
        )
        baseline_rate = self._stats.get("mean_aggregate_rate", 1.0)
        upper_rate = self._l1_threshold * upper_ratio

        intensity = _linear_ramp(
            aggregate_rate,
            lower=self._l1_threshold,
            upper=upper_rate,
        )

        signal = Signal(
            name="aggregate_rate_eps",
            observed=round(aggregate_rate, 4),
            baseline=round(baseline_rate, 4),
            ratio=round(aggregate_rate / baseline_rate, 4) if baseline_rate > 0 else 0.0,
            contribution=1.0,
        )
        return intensity, True, [signal]

    def _evaluate_l2(
        self,
        median_gap: float,
        gaps_ms: list[float],
    ) -> tuple[float, bool, list[Signal]]:
        """
        Layer 2: median inter-event gap (milliseconds).

        Anomaly direction: LOW gap is suspicious.
        Returns (intensity, fired, signals).
        """
        if median_gap >= self._l2_threshold:
            return 0.0, False, []

        # Intensity: linear ramp — lower gap = higher intensity
        floor_ms = float(self._v_cfg.get("L2_intensity_floor_ms", 100.0))
        # At floor_ms or below: intensity = 1.0
        # At threshold: intensity = 0.0
        intensity = _linear_ramp(
            value=median_gap,
            lower=self._l2_threshold,  # at threshold, intensity = 0
            upper=floor_ms,            # at floor, intensity = 1
            invert=True,               # lower value = higher intensity
        )

        baseline_gap = (
            statistics.median(self._stats.get("all_median_gaps_ms", [180000.0]))
            if self._stats.get("all_median_gaps_ms")
            else 180000.0
        )

        signal = Signal(
            name="median_inter_event_ms",
            observed=round(median_gap, 2),
            baseline=round(baseline_gap, 2),
            ratio=round(median_gap / baseline_gap, 6) if baseline_gap > 0 else 0.0,
            contribution=1.0,
        )
        return intensity, True, [signal]

    def _evaluate_l3(
        self,
        gaps_ms: list[float],
        median_gap: float,
    ) -> tuple[float, bool, list[Signal]]:
        """
        Layer 3: coefficient of variation of inter-event gaps.

        Low CV = machine-like consistency.
        Fires only when called after L2 has already fired.
        Returns (intensity, fired, signals).
        """
        if len(gaps_ms) < 3:
            return 0.0, False, []

        mean_gap = _mean(gaps_ms)
        if mean_gap <= 0:
            return 0.0, False, []

        std_gap = _std(gaps_ms, mean_gap)
        cv = std_gap / mean_gap

        upper_cv = float(
            self._v_cfg.get("L3_cv_upper_calibration_point", 0.30)
        )
        lower_cv = float(
            self._v_cfg.get("L3_cv_lower_calibration_point", 1.20)
        )

        if cv >= lower_cv:
            # Human-like irregularity — layer does not fire
            return 0.0, False, []

        # Intensity: lower CV = higher intensity
        intensity = _linear_ramp(
            value=cv,
            lower=lower_cv,   # at lower_cv: intensity = 0
            upper=upper_cv,   # at upper_cv: intensity = 1
            invert=True,
        )

        signal = Signal(
            name="timing_cv",
            observed=round(cv, 4),
            baseline=round(lower_cv, 4),
            ratio=round(cv / lower_cv, 4) if lower_cv > 0 else 0.0,
            contribution=1.0,
        )
        return intensity, True, [signal]

    # ------------------------------------------------------------------
    # Evidence builder
    # ------------------------------------------------------------------

    def _build_evidence(
        self,
        timestamps: list[str],
        gaps_ms: list[float],
        events: list[dict],
        highest_layer: int,
    ) -> list[EvidenceRef]:
        """Select the most diagnostic events as evidence references."""
        evidence: list[EvidenceRef] = []

        if not gaps_ms or not timestamps:
            return evidence

        min_gap = min(gaps_ms)
        min_gap_idx = gaps_ms.index(min_gap)

        # The event pair with the smallest gap
        ts_a = timestamps[min_gap_idx]
        ts_b = timestamps[min_gap_idx + 1]

        # Find the event records matching these timestamps
        event_a = next(
            (e for e in events if e.get("timestamp") == ts_a), None
        )
        event_b = next(
            (e for e in events if e.get("timestamp") == ts_b), None
        )

        if event_a:
            evidence.append(EvidenceRef(
                event_id=f"{event_a.get('session_id', '')}:{ts_a}",
                timestamp=ts_a,
                event_type=event_a.get("event_type", "unknown"),
                significance=f"fastest inter-event gap: {min_gap:.0f}ms to next event",
                inline=event_a,
            ))
        if event_b:
            evidence.append(EvidenceRef(
                event_id=f"{event_b.get('session_id', '')}:{ts_b}",
                timestamp=ts_b,
                event_type=event_b.get("event_type", "unknown"),
                significance=f"event following {min_gap:.0f}ms gap",
                inline=event_b,
            ))

        # First and last events as session bookends
        first_event = next(
            (e for e in events if e.get("timestamp") == timestamps[0]), None
        )
        last_event = next(
            (e for e in events if e.get("timestamp") == timestamps[-1]), None
        )
        if first_event and first_event != event_a:
            evidence.append(EvidenceRef(
                event_id=f"{first_event.get('session_id', '')}:{timestamps[0]}",
                timestamp=timestamps[0],
                event_type=first_event.get("event_type", "unknown"),
                significance="session start event",
                inline=first_event,
            ))
        if last_event and last_event != event_b:
            evidence.append(EvidenceRef(
                event_id=f"{last_event.get('session_id', '')}:{timestamps[-1]}",
                timestamp=timestamps[-1],
                event_type=last_event.get("event_type", "unknown"),
                significance="session end event",
                inline=last_event,
            ))

        return evidence[:5]  # Cap at 5 most diagnostic

    # ------------------------------------------------------------------
    # Output builders
    # ------------------------------------------------------------------

    def _no_fire_output(
        self,
        session_id: str,
        evaluated_at: str,
        data_window: TimeWindow,
        aggregate_rate: float,
        duration_s: float,
        event_count: int,
        gaps_ms: list[float],
    ) -> MechanismOutput:
        """Return a MechanismOutput when no layer fired."""
        baseline_rate = self._stats.get("mean_aggregate_rate", 1.0)
        signal = Signal(
            name="aggregate_rate_eps",
            observed=round(aggregate_rate, 4),
            baseline=round(baseline_rate, 4),
            ratio=round(aggregate_rate / baseline_rate, 4) if baseline_rate > 0 else 0.0,
            contribution=1.0,
        )
        return MechanismOutput(
            mechanism_id=MECHANISM_VELOCITY,
            session_id=session_id,
            evaluated_at=evaluated_at,
            confidence=0.0,
            threshold_used=self._l1_threshold,
            fired=False,
            highest_layer=0,
            signals=[signal],
            evidence=[],
            mechanism_version=MECHANISM_VERSION,
            data_window=data_window,
        )

    def _build_output(
        self,
        session_id: str,
        evaluated_at: str,
        data_window: TimeWindow,
        confidence: float,
        threshold_used: float,
        fired: bool,
        highest_layer: int,
        signals: list[Signal],
        evidence: list[EvidenceRef],
    ) -> MechanismOutput:
        return MechanismOutput(
            mechanism_id=MECHANISM_VELOCITY,
            session_id=session_id,
            evaluated_at=evaluated_at,
            confidence=round(confidence, 4),
            threshold_used=threshold_used,
            fired=fired,
            highest_layer=highest_layer,
            signals=signals,
            evidence=evidence,
            mechanism_version=MECHANISM_VERSION,
            data_window=data_window,
        )

    # ------------------------------------------------------------------
    # Dynamic threshold derivation
    # ------------------------------------------------------------------

    def _derive_l1_threshold(self) -> float:
        """L1 threshold: mean + N*std of aggregate rate distribution."""
        mean_rate = self._stats.get("mean_aggregate_rate", 0.0)
        std_rate = self._stats.get("std_aggregate_rate", 1.0)
        n = float(self._v_cfg.get("L1_dynamic_threshold_stddev_multiplier", 3.0))
        return mean_rate + n * std_rate

    def _derive_l2_threshold(self) -> float:
        """L2 threshold: Nth percentile of per-session median gaps."""
        p = int(self._v_cfg.get("L2_dynamic_threshold_percentile", 5))
        percentiles = self._stats.get("median_gap_percentiles", {})
        # Use closest available percentile
        if p in percentiles:
            return float(percentiles[p])
        # Fallback: 1/47 of the median gap (47x speed differential)
        all_gaps = self._stats.get("all_median_gaps_ms", [])
        if all_gaps:
            overall_median = statistics.median(all_gaps)
            return overall_median / 47.0
        return 5000.0  # 5 second fallback


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _linear_ramp(
    value: float,
    lower: float,
    upper: float,
    invert: bool = False,
) -> float:
    """
    Normalize value to [0.0, 1.0] using a linear ramp.

    If invert=False: lower → 0.0, upper → 1.0
    If invert=True:  lower → 1.0, upper → 0.0
    Values outside [lower, upper] are clamped.
    """
    if upper == lower:
        return 1.0 if value >= upper else 0.0
    raw = (value - lower) / (upper - lower)
    raw = max(0.0, min(1.0, raw))
    return 1.0 - raw if invert else raw


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: list[float], mean: float) -> float:
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)

def _trimmed_mean(values: list[float], trim: float = 0.05) -> float:
    """
    Mean after removing the top `trim` fraction of values.
    trim=0.05 removes the top 5%, making the statistic robust
    against extreme outlier sessions (e.g. attack sessions in a
    mixed dataset). The bottom is not trimmed — low values are
    benign and should anchor the baseline.
    """
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    cut = max(1, int(len(sorted_vals) * (1 - trim)))
    trimmed = sorted_vals[:cut]
    return sum(trimmed) / len(trimmed)


def _trimmed_std(values: list[float], mean: float, trim: float = 0.05) -> float:
    """
    Standard deviation computed over the same trimmed population
    as _trimmed_mean. Must use the same trim fraction and the
    trimmed mean for consistency.
    """
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    cut = max(1, int(len(sorted_vals) * (1 - trim)))
    trimmed = sorted_vals[:cut]
    if len(trimmed) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in trimmed) / len(trimmed)
    return variance ** 0.5
