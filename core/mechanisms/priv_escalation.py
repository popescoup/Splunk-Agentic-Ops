"""
MABE Detector — Privilege Escalation Chaining Detection Mechanism
==================================================================
Version: 1.0.0

Detects the harvest→escalation sequence: a credential access indicator
followed within a bounded time window by successful authentication to a
node whose required privilege exceeds the session's starting level.

EMPIRICAL BASIS
---------------
GTG-1002 Phase 4: "Claude independently determined which credentials
provided access to which services, mapping privilege levels and access
boundaries without human direction."
arXiv 2502.04227: AS-REP Roasting → password cracking → account
compromise as the prototype credential chaining sequence.
arXiv 2310.11409: file-based credential discovery as a primary path.

THE OBSERVABLE SIGNAL
---------------------
The harvest event itself is partially unobservable (cracking happens
off-device). What IS observable:
  - File access to file servers (possible credential content)
  - Kerberos anomalies (AS-REP roasting indicator)
  - Auth failure → success transitions on high-privilege nodes
The before/after transition is the primary signal.

THREE LAYERS
------------
L1 — High-privilege node contact
     O(n): single pass, check for high-value node auth success.
     Fires when standard-user-started session succeeds at high-priv node.

L2 — Sequence validation
     O(k²) where k = candidate events (small in practice).
     Confirms credential access indicator precedes high-priv auth
     within the configured time window.

L3 — Chain depth and privilege gap analysis
     O(n): reconstruct credential state timeline.
     Three sub-signals: chain depth, privilege gap, escalation velocity.

PRIVILEGE HIERARCHY
-------------------
standard_user < service_account < domain_admin
Represented as integer levels: 0, 1, 2
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Optional

from core.schema import (
    MechanismOutput,
    Signal,
    EvidenceRef,
    TimeWindow,
    MECHANISM_PRIV_ESC,
)
from core.config_loader import load_thresholds, get_layer_weights
from core.node_classifier import NodeClassifier, HIGH_VALUE_NODE_TYPES

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

MECHANISM_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Privilege hierarchy
# ---------------------------------------------------------------------------

PRIVILEGE_LEVELS = {
    "standard_user":  0,
    "service_account": 1,
    "domain_admin":   2,
}

HIGH_PRIVILEGE_NODE_TYPES = {
    "domain_controller":      "domain_admin",
    "database":               "service_account",
    "container_registry":     "service_account",
    "logging_infrastructure": "service_account",
}

# Credential access indicator event patterns
# These are observable proxies for credential harvesting activity
CREDENTIAL_ACCESS_PATTERNS = {
    "file_access_file_server": (
        lambda e, clf: (
            e.get("event_type") == "file_access"
            and clf.classify_event(e) == "file_server"
        )
    ),
    "kerberos_tgt_request": (
        lambda e, clf: e.get("event_type") == "kerberos_tgt_request"
    ),
    "auth_failure_spray": None,  # handled separately — requires sequence analysis
}


# ---------------------------------------------------------------------------
# Timestamp utilities
# ---------------------------------------------------------------------------

def _parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )


def _delta_seconds(ts_a: str, ts_b: str) -> float:
    return (_parse_ts(ts_b) - _parse_ts(ts_a)).total_seconds()


# ---------------------------------------------------------------------------
# PrivEscMechanism
# ---------------------------------------------------------------------------

class PrivEscMechanism:
    """
    Three-layer privilege escalation chaining detection mechanism.

    Parameters
    ----------
    thresholds : dict | None
    classifier : NodeClassifier | None
    """

    def __init__(
        self,
        thresholds: dict | None = None,
        layer_weights_override: dict | None = None,
        classifier: NodeClassifier | None = None,
    ) -> None:
        cfg = thresholds or load_thresholds()
        self._p_cfg = cfg.get("priv_escalation", {})
        self._layer_weights = layer_weights_override or get_layer_weights(cfg)
        self._classifier = classifier or NodeClassifier()
        self._time_window_s = float(
            self._p_cfg.get("L2_time_window_seconds", 300.0)
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def evaluate(
        self,
        session_id: str,
        account: str,
        events: list[dict],
        evaluated_at: str,
        initial_privilege: str = "standard_user",
    ) -> Optional[MechanismOutput]:
        """
        Evaluate privilege escalation chaining for a single session.

        Parameters
        ----------
        session_id : str
        account : str
        events : list[dict]
            All events for this session, in any order.
        evaluated_at : str
        initial_privilege : str
            Privilege level at session start. Default: "standard_user".
            In MABE: always standard_user (assumed breach framing).
            In real deployment: infer from account's known role.

        Returns
        -------
        MechanismOutput | None
            None if events is empty.
        """
        if not events:
            return None

        # Sort events by timestamp for sequential analysis
        try:
            sorted_events = sorted(
                events,
                key=lambda e: _parse_ts(e.get("timestamp", "1970-01-01T00:00:00.000Z"))
            )
        except Exception:
            sorted_events = events

        timestamps = [e.get("timestamp", "") for e in sorted_events]
        data_window = TimeWindow(
            start=timestamps[0] if timestamps else evaluated_at,
            end=timestamps[-1] if timestamps else evaluated_at,
        )

        initial_level = PRIVILEGE_LEVELS.get(initial_privilege, 0)

        # ── Layer 1 ───────────────────────────────────────────────────
        l1_intensity, l1_fired, l1_signals, hv_events = self._evaluate_l1(
            sorted_events, initial_level
        )

        if not l1_fired:
            return self._no_fire_output(
                session_id, evaluated_at, data_window
            )

        # ── Layer 2 ───────────────────────────────────────────────────
        l2_intensity, l2_fired, l2_signals, harvest_events = self._evaluate_l2(
            sorted_events, hv_events
        )

        if not l2_fired:
            confidence = self._layer_weights["L1"] * l1_intensity
            evidence = self._build_evidence(hv_events, [], 1)
            return self._build_output(
                session_id, evaluated_at, data_window,
                confidence, True, 1, l1_signals, evidence
            )

        # ── Layer 3 ───────────────────────────────────────────────────
        l3_intensity, l3_fired, l3_signals = self._evaluate_l3(
            sorted_events, initial_level, harvest_events, hv_events
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
        evidence = self._build_evidence(hv_events, harvest_events, highest_layer)

        return self._build_output(
            session_id, evaluated_at, data_window,
            confidence, True, highest_layer, all_signals, evidence
        )

    # ------------------------------------------------------------------
    # Layer evaluators
    # ------------------------------------------------------------------

    def _evaluate_l1(
        self,
        sorted_events: list[dict],
        initial_level: int,
    ) -> tuple[float, bool, list[Signal], list[dict]]:
        """
        Layer 1: successful auth to high-privilege node type.

        Returns (intensity, fired, signals, hv_events).
        hv_events: events that triggered this layer (for L2 use).
        """
        hv_success_events = []
        hv_types_hit: set[str] = set()

        for e in sorted_events:
            if e.get("event_type") != "auth_attempt":
                continue
            if not e.get("success"):
                continue

            node_type = self._classifier.classify_event(e)
            required_priv = HIGH_PRIVILEGE_NODE_TYPES.get(node_type)
            if required_priv is None:
                continue

            required_level = PRIVILEGE_LEVELS.get(required_priv, 0)
            if required_level > initial_level:
                hv_success_events.append(e)
                hv_types_hit.add(node_type)

        if not hv_success_events:
            return 0.0, False, [], []

        # Intensity: number of distinct high-value types contacted
        # 1 type → moderate intensity; 3+ types → high intensity
        intensity = _linear_ramp(
            float(len(hv_types_hit)),
            lower=0.0,
            upper=4.0,
        )
        intensity = max(intensity, 0.25)  # minimum intensity for any L1 fire

        signal = Signal(
            name="high_priv_node_types_contacted",
            observed=float(len(hv_types_hit)),
            baseline=0.0,
            ratio=float(len(hv_types_hit)),
            contribution=1.0,
        )
        return intensity, True, [signal], hv_success_events

    def _evaluate_l2(
        self,
        sorted_events: list[dict],
        hv_events: list[dict],
    ) -> tuple[float, bool, list[Signal], list[dict]]:
        """
        Layer 2: credential access indicator precedes high-privilege auth.

        Returns (intensity, fired, signals, harvest_indicator_events).
        """
        # Identify credential access indicators
        harvest_indicators: list[tuple[float, dict]] = []  # (timestamp_float, event)

        for e in sorted_events:
            ts = e.get("timestamp", "")
            if not ts:
                continue

            # File access to file server (primary indicator)
            if (e.get("event_type") == "file_access"
                    and self._classifier.classify_event(e) == "file_server"):
                try:
                    harvest_indicators.append((_parse_ts(ts).timestamp(), e))
                except Exception:
                    pass
                continue

            # Kerberos TGT request (AS-REP roasting proxy)
            if e.get("event_type") == "kerberos_tgt_request":
                try:
                    harvest_indicators.append((_parse_ts(ts).timestamp(), e))
                except Exception:
                    pass
                continue

            # Auth failure followed by success on same destination
            # (password spray indicator — handled below)

        # Check auth failure sprays: multiple failures then success on same dst
        spray_indicators = self._detect_spray_indicators(sorted_events)
        harvest_indicators.extend(spray_indicators)

        if not harvest_indicators:
            return 0.0, False, [], []

        # For each high-value auth success, check if any harvest indicator
        # preceded it within the time window
        best_delta: Optional[float] = None
        best_harvest_event: Optional[dict] = None
        triggering_hv_event: Optional[dict] = None

        for hv_event in hv_events:
            hv_ts = hv_event.get("timestamp", "")
            if not hv_ts:
                continue
            try:
                hv_ts_float = _parse_ts(hv_ts).timestamp()
            except Exception:
                continue

            for harvest_ts_float, harvest_event in harvest_indicators:
                delta = hv_ts_float - harvest_ts_float
                if 0 < delta <= self._time_window_s:
                    if best_delta is None or delta < best_delta:
                        best_delta = delta
                        best_harvest_event = harvest_event
                        triggering_hv_event = hv_event

        if best_delta is None:
            return 0.0, False, [], []

        # Intensity: tighter proximity = higher intensity
        # At delta=0: intensity=1.0; at delta=time_window: intensity=0.0
        intensity = _linear_ramp(
            best_delta,
            lower=self._time_window_s,
            upper=0.0,
            invert=True,
        )
        intensity = max(intensity, 0.10)  # minimum intensity for sequence confirmation

        harvest_events_list = [
            e for _, e in harvest_indicators
        ] if best_harvest_event else []

        signals = [Signal(
            name="harvest_to_escalation_delta_s",
            observed=round(best_delta, 2),
            baseline=self._time_window_s,
            ratio=round(best_delta / self._time_window_s, 4),
            contribution=1.0,
        )]

        return intensity, True, signals, harvest_events_list

    def _evaluate_l3(
        self,
        sorted_events: list[dict],
        initial_level: int,
        harvest_events: list[dict],
        hv_events: list[dict],
    ) -> tuple[float, bool, list[Signal]]:
        """
        Layer 3: chain depth, privilege gap, escalation velocity.
        """
        # Reconstruct privilege level timeline
        priv_timeline: list[tuple[float, int]] = []  # (timestamp_float, priv_level)

        for e in sorted_events:
            if e.get("event_type") != "auth_attempt" or not e.get("success"):
                continue
            ts = e.get("timestamp", "")
            node_type = self._classifier.classify_event(e)
            required_priv = HIGH_PRIVILEGE_NODE_TYPES.get(node_type)
            if required_priv:
                try:
                    priv_timeline.append((
                        _parse_ts(ts).timestamp(),
                        PRIVILEGE_LEVELS.get(required_priv, 0)
                    ))
                except Exception:
                    pass

        if not priv_timeline:
            return 0.0, False, []

        # Chain depth: distinct privilege levels above initial_level reached
        reached_levels = {level for _, level in priv_timeline
                         if level > initial_level}
        chain_depth = len(reached_levels)

        # Max privilege gap: largest single-step jump in one escalation event
        max_priv_gap = max(
            (level - initial_level for level in reached_levels),
            default=0
        )

        # Escalation velocity: seconds from session start to first
        # high-privilege auth
        if priv_timeline and sorted_events:
            try:
                session_start = _parse_ts(
                    sorted_events[0].get("timestamp", "")
                ).timestamp()
                first_hv_ts = min(ts for ts, _ in priv_timeline)
                escalation_velocity_s = first_hv_ts - session_start
            except Exception:
                escalation_velocity_s = self._time_window_s
        else:
            escalation_velocity_s = self._time_window_s

        # Sub-signal weights
        w_depth = float(self._p_cfg.get("L3_depth_weight", 0.45))
        w_gap   = float(self._p_cfg.get("L3_gap_weight", 0.35))
        w_vel   = float(self._p_cfg.get("L3_velocity_weight", 0.20))

        depth_upper = float(self._p_cfg.get("L3_depth_upper", 3.0))
        gap_upper   = float(self._p_cfg.get("L3_gap_upper", 2.0))
        vel_upper   = float(self._p_cfg.get("L3_velocity_upper_seconds", 60.0))

        # Component intensities
        depth_intensity = _linear_ramp(float(chain_depth), 0.0, depth_upper)
        gap_intensity   = _linear_ramp(float(max_priv_gap), 0.0, gap_upper)
        # Velocity: lower time = higher intensity (faster = more suspicious)
        vel_intensity   = _linear_ramp(
            escalation_velocity_s,
            lower=vel_upper,
            upper=0.0,
            invert=True,
        )

        l3_intensity = (
            w_depth * depth_intensity
            + w_gap   * gap_intensity
            + w_vel   * vel_intensity
        )

        if l3_intensity <= 0.0:
            return 0.0, False, []

        signals = []
        if chain_depth > 0:
            signals.append(Signal(
                name="chain_depth",
                observed=float(chain_depth),
                baseline=0.0,
                ratio=float(chain_depth),
                contribution=round(w_depth, 4),
            ))
        if max_priv_gap > 0:
            signals.append(Signal(
                name="max_privilege_gap",
                observed=float(max_priv_gap),
                baseline=0.0,
                ratio=float(max_priv_gap),
                contribution=round(w_gap, 4),
            ))
        if vel_intensity > 0:
            signals.append(Signal(
                name="escalation_velocity_s",
                observed=round(escalation_velocity_s, 2),
                baseline=round(vel_upper, 2),
                ratio=round(escalation_velocity_s / vel_upper, 4) if vel_upper > 0 else 0.0,
                contribution=round(w_vel, 4),
            ))

        return l3_intensity, True, signals

    # ------------------------------------------------------------------
    # Spray indicator detection
    # ------------------------------------------------------------------

    def _detect_spray_indicators(
        self,
        sorted_events: list[dict],
    ) -> list[tuple[float, dict]]:
        """
        Detect auth failure sprays: multiple failures → success on same dst.

        Returns list of (timestamp_float, spray_indicator_event) tuples
        for the failure sequence start event.
        """
        indicators: list[tuple[float, dict]] = []

        # Group auth attempts by destination
        by_dst: dict[str, list[dict]] = {}
        for e in sorted_events:
            if e.get("event_type") != "auth_attempt":
                continue
            dst = e.get("dst_host") or e.get("dest", "")
            if dst not in by_dst:
                by_dst[dst] = []
            by_dst[dst].append(e)

        for dst, dst_events in by_dst.items():
            failures = [e for e in dst_events if not e.get("success")]
            successes = [e for e in dst_events if e.get("success")]

            # At least 2 failures followed by a success = spray indicator
            if len(failures) >= 2 and successes:
                # Find last failure before first success
                try:
                    first_success_ts = _parse_ts(
                        successes[0].get("timestamp", "")
                    ).timestamp()
                    failures_before = [
                        f for f in failures
                        if _parse_ts(
                            f.get("timestamp", "")
                        ).timestamp() < first_success_ts
                    ]
                    if len(failures_before) >= 2:
                        # Use first failure as harvest indicator timestamp
                        first_failure = failures_before[0]
                        ts = first_failure.get("timestamp", "")
                        if ts:
                            indicators.append((
                                _parse_ts(ts).timestamp(),
                                first_failure,
                            ))
                except Exception:
                    pass

        return indicators

    # ------------------------------------------------------------------
    # Evidence builder
    # ------------------------------------------------------------------

    def _build_evidence(
        self,
        hv_events: list[dict],
        harvest_events: list[dict],
        highest_layer: int,
    ) -> list[EvidenceRef]:
        evidence: list[EvidenceRef] = []

        for e in hv_events[:2]:
            ts = e.get("timestamp", "")
            dst = e.get("dst_host") or e.get("dest", "")
            nt = self._classifier.classify_event(e)
            evidence.append(EvidenceRef(
                event_id=f"{e.get('session_id', '')}:{ts}",
                timestamp=ts,
                event_type=e.get("event_type", "unknown"),
                significance=f"successful auth to high-privilege node type: {nt} ({dst})",
                inline=e,
            ))

        if highest_layer >= 2:
            for e in harvest_events[:2]:
                ts = e.get("timestamp", "")
                evidence.append(EvidenceRef(
                    event_id=f"{e.get('session_id', '')}:{ts}",
                    timestamp=ts,
                    event_type=e.get("event_type", "unknown"),
                    significance="credential access indicator preceding privilege escalation",
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
    ) -> MechanismOutput:
        return MechanismOutput(
            mechanism_id=MECHANISM_PRIV_ESC,
            session_id=session_id,
            evaluated_at=evaluated_at,
            confidence=0.0,
            threshold_used=1.0,  # L1 is binary — no numeric threshold
            fired=False,
            highest_layer=0,
            signals=[],
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
        fired: bool,
        highest_layer: int,
        signals: list[Signal],
        evidence: list[EvidenceRef],
    ) -> MechanismOutput:
        return MechanismOutput(
            mechanism_id=MECHANISM_PRIV_ESC,
            session_id=session_id,
            evaluated_at=evaluated_at,
            confidence=round(confidence, 4),
            threshold_used=1.0,
            fired=fired,
            highest_layer=highest_layer,
            signals=signals,
            evidence=evidence,
            mechanism_version=MECHANISM_VERSION,
            data_window=data_window,
        )


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
