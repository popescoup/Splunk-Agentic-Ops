"""
MABE Detector — Comprehensive Enumeration Detection Mechanism
==============================================================
Version: 1.0.0

Detects exhaustive, role-inappropriate access across unusually many
distinct destinations. Topology-agnostic: traversal order (BFS, DFS,
or other) is irrelevant. The signal is breadth of access.

EMPIRICAL BASIS
---------------
GTG-1002 Phase 2: Claude "systematically catalog[ed] target infrastructure,
analyze[d] authentication mechanisms, and identif[ied] potential
vulnerabilities... simultaneously across multiple targets."
Dragos: AI "spontaneously identified and probed OT-adjacent assets that
were not part of the stated objective."

THREE LAYERS
------------
L1 — Raw destination count
     O(n): single pass building a set of unique dst_host values.
     Fires when count > mean + N*std of observed distribution.

L2 — Cross-segment and node-type anomaly
     O(n) with hash lookup against node_type_mapping.
     Fires when session contacts unusual segments or high-value nodes
     outside the account's historical pattern.

L3 — Behavioral baseline deviation
     O(n): deviation from per-account behavioral baseline.
     Three components: new host ratio, node type distribution shift,
     session breadth z-score. All fully unsupervised, no labels.

CONFIDENCE FORMULA
------------------
confidence = (w_L1 * intensity_L1) + (w_L2 * intensity_L2) + (w_L3 * intensity_L3)
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from typing import Optional

from core.schema import (
    MechanismOutput,
    Signal,
    EvidenceRef,
    TimeWindow,
    MECHANISM_ENUMERATION,
)
from core.config_loader import load_thresholds, get_layer_weights
from core.node_classifier import NodeClassifier
from core.baseline import AccountBaseline, compute_baseline_deviation

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

MECHANISM_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Dataset-level statistics (preprocessing)
# ---------------------------------------------------------------------------

def compute_enumeration_dataset_stats(sessions: list[dict]) -> dict:
    """
    Compute dataset-level enumeration statistics for dynamic thresholds.

    Parameters
    ----------
    sessions : list[dict]
        All sessions. Each must have "events": list[dict] with
        "dst_host" (or "dest") fields.

    Returns
    -------
    dict with keys:
        mean_destination_count  float
        std_destination_count   float
        all_destination_counts  list[int]  per-session values
    """
    dest_counts: list[int] = []

    for session in sessions:
        events = session.get("events", [])
        dests = {
            e.get("dst_host") or e.get("dest")
            for e in events
            if e.get("dst_host") or e.get("dest")
        }
        dest_counts.append(len(dests))

    mean_dc = _trimmed_mean(dest_counts)
    std_dc = _trimmed_std(dest_counts, mean_dc)

    return {
        "mean_destination_count": mean_dc,
        "std_destination_count":  std_dc,
        "all_destination_counts": dest_counts,
    }


# ---------------------------------------------------------------------------
# EnumerationMechanism
# ---------------------------------------------------------------------------

class EnumerationMechanism:
    """
    Three-layer comprehensive enumeration detection mechanism.

    Parameters
    ----------
    dataset_stats : dict
        Output of compute_enumeration_dataset_stats(). Required.
    baselines : dict[str, AccountBaseline]
        Per-account baselines from BaselineBuilder.build().
    thresholds : dict | None
        Loaded thresholds config. If None, loads from config file.
    classifier : NodeClassifier | None
        Node type classifier. If None, instantiates default.
    """

    def __init__(
        self,
        dataset_stats: dict,
        baselines: dict,
        thresholds: dict | None = None,
        layer_weights_override: dict | None = None,
        classifier: NodeClassifier | None = None,
    ) -> None:
        cfg = thresholds or load_thresholds()
        self._e_cfg = cfg.get("enumeration", {})
        self._layer_weights = layer_weights_override or get_layer_weights(cfg)
        self._stats = dataset_stats
        self._baselines = baselines
        self._classifier = classifier or NodeClassifier()

        self._l1_threshold = self._derive_l1_threshold()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def evaluate(
        self,
        session_id: str,
        account: str,
        events: list[dict],
        evaluated_at: str,
    ) -> Optional[MechanismOutput]:
        """
        Evaluate comprehensive enumeration for a single session.

        Parameters
        ----------
        session_id : str
        account : str
            Username / account identifier.
        events : list[dict]
            All events for this session.
        evaluated_at : str
            ISO 8601 evaluation timestamp.

        Returns
        -------
        MechanismOutput | None
            None if events is empty.
        """
        if not events:
            return None

        timestamps = sorted(
            e.get("timestamp", "")
            for e in events if e.get("timestamp")
        )
        data_window = TimeWindow(
            start=timestamps[0] if timestamps else evaluated_at,
            end=timestamps[-1] if timestamps else evaluated_at,
        )

        # Distinct destinations
        session_dests = {
            e.get("dst_host") or e.get("dest")
            for e in events
            if e.get("dst_host") or e.get("dest")
        }
        dest_count = len(session_dests)

        # ── Layer 1 ───────────────────────────────────────────────────
        l1_intensity, l1_fired, l1_signals = self._evaluate_l1(dest_count)

        if not l1_fired:
            return self._no_fire_output(
                session_id, evaluated_at, data_window,
                dest_count, l1_signals
            )

        # ── Layer 2 ───────────────────────────────────────────────────
        l2_intensity, l2_fired, l2_signals = self._evaluate_l2(
            events, account
        )

        if not l2_fired:
            confidence = self._layer_weights["L1"] * l1_intensity
            evidence = self._build_evidence(events, session_dests, 1)
            return self._build_output(
                session_id, evaluated_at, data_window,
                confidence, self._l1_threshold, True, 1,
                l1_signals, evidence
            )

        # ── Layer 3 ───────────────────────────────────────────────────
        baseline = self._baselines.get(account)
        l3_intensity, l3_fired, l3_signals = (
            self._evaluate_l3(events, baseline)
            if baseline is not None
            else (0.0, False, [])
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
        evidence = self._build_evidence(events, session_dests, highest_layer)

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
        dest_count: int,
    ) -> tuple[float, bool, list[Signal]]:
        """Layer 1: raw destination count vs. dynamic threshold."""
        if dest_count <= self._l1_threshold:
            baseline_mean = self._stats.get("mean_destination_count", 4.0)
            signal = Signal(
                name="distinct_destination_count",
                observed=float(dest_count),
                baseline=round(baseline_mean, 2),
                ratio=round(dest_count / baseline_mean, 4) if baseline_mean > 0 else 0.0,
                contribution=1.0,
            )
            return 0.0, False, [signal]

        # Intensity: linear ramp from L1_threshold to upper_threshold
        upper_multiplier = float(
            self._e_cfg.get("L1_intensity_upper_stddev_multiplier", 6.0)
        )
        mean_dc = self._stats.get("mean_destination_count", 4.0)
        std_dc = self._stats.get("std_destination_count", 2.0)
        upper_threshold = mean_dc + upper_multiplier * std_dc

        intensity = _linear_ramp(
            float(dest_count),
            lower=self._l1_threshold,
            upper=upper_threshold,
        )

        signal = Signal(
            name="distinct_destination_count",
            observed=float(dest_count),
            baseline=round(mean_dc, 2),
            ratio=round(dest_count / mean_dc, 4) if mean_dc > 0 else 0.0,
            contribution=1.0,
        )
        return intensity, True, [signal]

    def _evaluate_l2(
        self,
        events: list[dict],
        account: str,
    ) -> tuple[float, bool, list[Signal]]:
        """
        Layer 2: cross-segment and high-value node type anomaly.

        Two sub-signals:
        A — segment diversity: distinct segments contacted
        B — high-value node contact: contacted high-value node type
        """
        # Classify all events by node type
        node_types = [self._classifier.classify_event(e) for e in events]
        contacted_types = set(node_types)

        # Count distinct segments (approximated from node types)
        segments = set()
        for nt in contacted_types:
            if nt in ("domain_controller", "container_registry",
                      "logging_infrastructure"):
                segments.add("infrastructure")
            elif nt == "database":
                segments.add("data_tier")
            elif nt in ("api_endpoint", "file_server", "workstation"):
                segments.add("corporate")

        n_segments = len(segments)
        seg_threshold = int(
            self._e_cfg.get("L2_segment_diversity_threshold", 2)
        )
        seg_upper = int(
            self._e_cfg.get("L2_segment_diversity_upper", 4)
        )

        # Sub-signal A: segment diversity
        seg_fired = n_segments >= seg_threshold
        seg_intensity = _linear_ramp(
            float(n_segments), lower=float(seg_threshold), upper=float(seg_upper)
        ) if seg_fired else 0.0

        # Sub-signal B: high-value node type contact
        hv_types_contacted = {
            nt for nt in contacted_types
            if self._classifier.is_high_value(nt)
        }
        hv_fired = len(hv_types_contacted) > 0
        hv_intensity = min(len(hv_types_contacted) / 4.0, 1.0)

        l2_fired = seg_fired or hv_fired
        if not l2_fired:
            return 0.0, False, []

        # Combine sub-signal intensities
        if seg_fired and hv_fired:
            l2_intensity = (seg_intensity + hv_intensity) / 2.0
        elif seg_fired:
            l2_intensity = seg_intensity * 0.7  # partial credit
        else:
            l2_intensity = hv_intensity * 0.8

        signals = []
        if seg_fired:
            signals.append(Signal(
                name="distinct_segment_count",
                observed=float(n_segments),
                baseline=1.0,
                ratio=float(n_segments),
                contribution=0.5 if hv_fired else 1.0,
            ))
        if hv_fired:
            signals.append(Signal(
                name="high_value_node_contacts",
                observed=float(len(hv_types_contacted)),
                baseline=0.0,
                ratio=float(len(hv_types_contacted)),
                contribution=0.5 if seg_fired else 1.0,
            ))

        return l2_intensity, True, signals

    def _evaluate_l3(
        self,
        events: list[dict],
        baseline: AccountBaseline,
    ) -> tuple[float, bool, list[Signal]]:
        """
        Layer 3: behavioral baseline deviation.

        Three components: new host ratio, node type distribution shift,
        session breadth z-score.
        """
        deviations = compute_baseline_deviation(
            events, baseline, self._classifier
        )

        new_host_ratio = deviations["new_host_ratio"]
        nt_shift = deviations["node_type_distribution_shift"]
        breadth_z = deviations["session_breadth_zscore"]

        # Per-component thresholds and upper calibration
        nhr_thresh = float(self._e_cfg.get("L3_new_host_ratio_threshold", 0.50))
        nhr_upper  = float(self._e_cfg.get("L3_new_host_ratio_upper", 0.90))
        nts_thresh = float(self._e_cfg.get("L3_nt_shift_threshold", 0.40))
        nts_upper  = float(self._e_cfg.get("L3_nt_shift_upper", 1.20))
        bz_thresh  = float(self._e_cfg.get("L3_breadth_zscore_threshold", 2.0))
        bz_upper   = float(self._e_cfg.get("L3_breadth_zscore_upper", 5.0))

        comp_weights = self._e_cfg.get("L3_component_weights", {})
        w_nhr = float(comp_weights.get("new_host_ratio", 0.40))
        w_nts = float(comp_weights.get("node_type_distribution_shift", 0.35))
        w_bz  = float(comp_weights.get("session_breadth_zscore", 0.25))

        # Component intensities
        nhr_intensity = _linear_ramp(new_host_ratio, nhr_thresh, nhr_upper)
        nts_intensity = _linear_ramp(nt_shift, nts_thresh, nts_upper)
        bz_intensity  = _linear_ramp(breadth_z, bz_thresh, bz_upper)

        # Weighted combination
        l3_intensity = (
            w_nhr * nhr_intensity
            + w_nts * nts_intensity
            + w_bz  * bz_intensity
        )

        l3_fired = l3_intensity > 0.0

        if not l3_fired:
            return 0.0, False, []

        # Build signals for fired components
        signals = []
        if nhr_intensity > 0:
            baseline_nhr = 0.05  # typical benign new-host fraction
            signals.append(Signal(
                name="new_host_ratio",
                observed=round(new_host_ratio, 4),
                baseline=baseline_nhr,
                ratio=round(new_host_ratio / baseline_nhr, 4) if baseline_nhr > 0 else 0.0,
                contribution=round(w_nhr, 4),
            ))
        if nts_intensity > 0:
            signals.append(Signal(
                name="node_type_distribution_shift",
                observed=round(nt_shift, 4),
                baseline=0.0,
                ratio=round(nt_shift / nts_thresh, 4) if nts_thresh > 0 else 0.0,
                contribution=round(w_nts, 4),
            ))
        if bz_intensity > 0:
            signals.append(Signal(
                name="session_breadth_zscore",
                observed=round(breadth_z, 4),
                baseline=0.0,
                ratio=round(breadth_z / bz_thresh, 4) if bz_thresh > 0 else 0.0,
                contribution=round(w_bz, 4),
            ))

        return l3_intensity, True, signals

    # ------------------------------------------------------------------
    # Evidence builder
    # ------------------------------------------------------------------

    def _build_evidence(
        self,
        events: list[dict],
        session_dests: set,
        highest_layer: int,
    ) -> list[EvidenceRef]:
        """Select the most diagnostic events as evidence references."""
        evidence: list[EvidenceRef] = []

        # High-value node contacts are most diagnostic
        hv_events = [
            e for e in events
            if self._classifier.is_high_value(
                self._classifier.classify_event(e)
            )
        ]
        for e in hv_events[:3]:
            ts = e.get("timestamp", "")
            dst = e.get("dst_host") or e.get("dest", "")
            nt = self._classifier.classify_event(e)
            evidence.append(EvidenceRef(
                event_id=f"{e.get('session_id', '')}:{ts}",
                timestamp=ts,
                event_type=e.get("event_type", "unknown"),
                significance=f"access to high-value node type: {nt} ({dst})",
                inline=e,
            ))

        # Auth attempts to new (unseen) destinations
        if highest_layer >= 3:
            auth_events = [
                e for e in events
                if e.get("event_type") == "auth_attempt"
                and e.get("success")
            ]
            for e in auth_events[:2]:
                ts = e.get("timestamp", "")
                dst = e.get("dst_host") or e.get("dest", "")
                evidence.append(EvidenceRef(
                    event_id=f"{e.get('session_id', '')}:{ts}",
                    timestamp=ts,
                    event_type="auth_attempt",
                    significance=f"successful auth to {dst}",
                    inline=e,
                ))

        return evidence[:5]

    # ------------------------------------------------------------------
    # Output builders
    # ------------------------------------------------------------------

    def _no_fire_output(
        self,
        session_id: str,
        evaluated_at: str,
        data_window: TimeWindow,
        dest_count: int,
        signals: list[Signal],
    ) -> MechanismOutput:
        return MechanismOutput(
            mechanism_id=MECHANISM_ENUMERATION,
            session_id=session_id,
            evaluated_at=evaluated_at,
            confidence=0.0,
            threshold_used=self._l1_threshold,
            fired=False,
            highest_layer=0,
            signals=signals,
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
            mechanism_id=MECHANISM_ENUMERATION,
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
        """L1 threshold: mean + N*std of destination count distribution."""
        mean_dc = self._stats.get("mean_destination_count", 4.0)
        std_dc = self._stats.get("std_destination_count", 2.0)
        n = float(
            self._e_cfg.get("L1_dynamic_threshold_stddev_multiplier", 2.0)
        )
        return mean_dc + n * std_dc


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _linear_ramp(
    value: float,
    lower: float,
    upper: float,
    invert: bool = False,
) -> float:
    if upper == lower:
        return 1.0 if value >= upper else 0.0
    raw = (value - lower) / (upper - lower)
    raw = max(0.0, min(1.0, raw))
    return 1.0 - raw if invert else raw


def _mean(values: list) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: list, mean: float) -> float:
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
