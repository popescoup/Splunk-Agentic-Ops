"""
MABE Detector — Core Schema
============================
Version: 1.0.0

Defines the immutable interface contract between detection mechanisms and
the correlation agent. Every mechanism produces MechanismOutput. The
correlation agent consumes a list of MechanismOutput and produces
CorrelationOutput.

IMMUTABILITY POLICY
-------------------
Do not add fields without updating DETECTOR_DESIGN.md and incrementing
the version in this module. Downstream code must not add fields to
instances at runtime.

FIELD CONVENTIONS
-----------------
- confidence: always 0.0–1.0, normalized scalar
- timestamps: always ISO 8601 with millisecond precision and Z suffix
- absent mechanism: mechanism produced no MechanismOutput at all
- fired=False: mechanism ran but no layer triggered (confidence=0.0)
- fired=True: at least Layer 1 triggered (confidence > 0.0)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Mechanism identifiers
# ---------------------------------------------------------------------------

MECHANISM_VELOCITY      = "velocity"
MECHANISM_ENUMERATION   = "enumeration"
MECHANISM_PRIV_ESC      = "priv_escalation"

VALID_MECHANISM_IDS = {
    MECHANISM_VELOCITY,
    MECHANISM_ENUMERATION,
    MECHANISM_PRIV_ESC,
}

# ---------------------------------------------------------------------------
# Sub-structures
# ---------------------------------------------------------------------------

@dataclass
class TimeWindow:
    """
    Inclusive time range examined by a mechanism or session.

    Fields
    ------
    start : str
        ISO 8601 timestamp of first event in window.
    end : str
        ISO 8601 timestamp of last event in window.
    """
    start: str
    end:   str

    def __post_init__(self) -> None:
        if not self.start or not self.end:
            raise ValueError("TimeWindow start and end must be non-empty strings.")


@dataclass
class Signal:
    """
    A single measured behavioral signal within a detection layer.

    The ratio field provides a unit-free, immediately interpretable
    measure: observed / baseline. A ratio of 0.004 on inter-event timing
    means the session moved 250x faster than baseline. This is the value
    that appears in analyst-facing output.

    Fields
    ------
    name : str
        Signal identifier, e.g. "median_inter_event_ms", "max_fan_out".
    observed : float
        The value measured in the session under analysis.
    baseline : float
        The expected benign value for comparison. Derived from the
        observed dataset distribution without labels.
    ratio : float
        observed / baseline. Values < 1.0 mean the session is faster/
        lower than baseline; values > 1.0 mean higher than baseline.
        Which direction is anomalous depends on the signal.
    contribution : float
        This signal's fractional contribution to its layer's intensity
        score. All contributions within a layer sum to 1.0.
    """
    name:         str
    observed:     float
    baseline:     float
    ratio:        float
    contribution: float

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Signal name must be non-empty.")
        if not 0.0 <= self.contribution <= 1.0:
            raise ValueError(
                f"Signal contribution must be in [0.0, 1.0]; got {self.contribution}"
            )


@dataclass
class EvidenceRef:
    """
    A reference to a specific event that contributed to a detection.

    The inline field is optional — populated in SIFT forensic mode where
    the full event record is available, empty in Splunk streaming mode
    where the event_id is a Splunk event key the analyst can retrieve.

    Fields
    ------
    event_id : str
        References a specific event. In MABE: session_id + timestamp.
        In Splunk: Splunk _cd field or equivalent.
    timestamp : str
        ISO 8601 event timestamp.
    event_type : str
        e.g. "auth_attempt", "file_access", "kerberos_tgt_request".
    significance : str
        One-line plain English description of why this event is notable.
        e.g. "first successful domain controller auth after 4 failures"
    inline : dict | None
        Full event record. Populated in SIFT mode; None in streaming mode.
    """
    event_id:     str
    timestamp:    str
    event_type:   str
    significance: str
    inline:       Optional[dict] = None

    def __post_init__(self) -> None:
        if not self.event_id:
            raise ValueError("EvidenceRef event_id must be non-empty.")
        if not self.significance:
            raise ValueError("EvidenceRef significance must be non-empty.")


# ---------------------------------------------------------------------------
# MechanismOutput
# ---------------------------------------------------------------------------

@dataclass
class MechanismOutput:
    """
    The output of a single detection mechanism for a single session.

    One output per mechanism per session (Option A). The confidence scalar
    reflects how far up the layer stack the session progressed AND how
    strongly it fired at each level:

        confidence = Σ (layer_weight × layer_intensity)

    where layer_intensity is a normalized distance from the layer threshold,
    using a linear ramp between lower calibration point (intensity=0.0) and
    upper calibration point (intensity=1.0).

    Default layer weights: L1=0.20, L2=0.35, L3=0.45 (configurable).

    The distinction between absent and present-but-low-confidence is
    preserved at the CorrelationOutput level:
        - Absent mechanism: not present in the correlation agent's input list
        - fired=False: mechanism ran, no layer triggered, confidence=0.0
        - fired=True: at least L1 triggered, confidence > 0.0

    Fields
    ------
    mechanism_id : str
        One of MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC.
    session_id : str
        UUID matching MABE session manifest.
    evaluated_at : str
        ISO 8601 timestamp of when this mechanism ran.
    confidence : float
        0.0–1.0 normalized scalar for correlation weighting.
    threshold_used : float
        The configured threshold for this mechanism's Layer 1 trip-wire.
    fired : bool
        True if confidence > 0.0 (any layer triggered).
    highest_layer : int
        0 if no layer fired; 1, 2, or 3 for the highest layer that fired.
    signals : list[Signal]
        All measured signals, ordered by contribution descending.
    evidence : list[EvidenceRef]
        Supporting events, ordered by diagnostic relevance descending.
    mechanism_version : str
        Semver of the mechanism implementation.
    data_window : TimeWindow
        Time range of events examined by this mechanism.
    """
    mechanism_id:      str
    session_id:        str
    evaluated_at:      str
    confidence:        float
    threshold_used:    float
    fired:             bool
    highest_layer:     int
    signals:           list
    evidence:          list
    mechanism_version: str
    data_window:       TimeWindow

    def __post_init__(self) -> None:
        if self.mechanism_id not in VALID_MECHANISM_IDS:
            raise ValueError(
                f"Invalid mechanism_id '{self.mechanism_id}'. "
                f"Valid: {sorted(VALID_MECHANISM_IDS)}"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be in [0.0, 1.0]; got {self.confidence}"
            )
        if self.highest_layer not in (0, 1, 2, 3):
            raise ValueError(
                f"highest_layer must be 0, 1, 2, or 3; got {self.highest_layer}"
            )
        if self.fired and self.confidence == 0.0:
            raise ValueError("fired=True requires confidence > 0.0")
        if not self.fired and self.confidence > 0.0:
            raise ValueError("fired=False requires confidence == 0.0")
        if self.fired and self.highest_layer == 0:
            raise ValueError("fired=True requires highest_layer >= 1")
        if not self.session_id:
            raise ValueError("session_id must be non-empty.")


# ---------------------------------------------------------------------------
# CorrelationOutput sub-structures
# ---------------------------------------------------------------------------

@dataclass
class TriageCard:
    """
    Level 1 analyst output — everything needed for rapid triage in ≤5 lines.

    Designed for a senior analyst triaging dozens of alerts in a shift.
    The plain_english field is a programmatically generated one-sentence
    characterization in core; LLM-enhanced narrative is a platform-specific
    enhancement.

    Fields
    ------
    account : str
        The user account associated with the flagged session.
    time_window : TimeWindow
        Session start and end times.
    overall_confidence : float
        Weighted combined confidence score (0.0–1.0).
    plain_english : str
        One-sentence characterization of the anomalous behavior.
    mechanism_scores : dict
        Per-mechanism confidence scores.
        e.g. {"velocity": 0.91, "enumeration": 0.73, "priv_escalation": 0.0}
        Keys are always all three mechanism IDs; absent mechanisms have 0.0.
    """
    account:            str
    time_window:        TimeWindow
    overall_confidence: float
    plain_english:      str
    mechanism_scores:   dict

    def __post_init__(self) -> None:
        if not self.account:
            raise ValueError("TriageCard account must be non-empty.")
        if not 0.0 <= self.overall_confidence <= 1.0:
            raise ValueError(
                f"overall_confidence must be in [0.0, 1.0]; "
                f"got {self.overall_confidence}"
            )


@dataclass
class EvidenceSummary:
    """
    Level 2 analyst output — per-mechanism evidence breakdown.

    What the analyst uses to assess whether a triage card is a true
    positive before escalating to full investigation. Contains the
    top 2–3 signals by contribution and 3–5 most diagnostic events.

    Fields
    ------
    mechanism_id : str
        Which mechanism produced this summary.
    headline : str
        One-sentence summary of the mechanism's finding.
        e.g. "14 distinct hosts contacted in 4 minutes"
    top_signals : list[Signal]
        Top 2–3 signals ordered by contribution descending.
    top_events : list[EvidenceRef]
        Top 3–5 most diagnostic events ordered by significance.
    """
    mechanism_id: str
    headline:     str
    top_signals:  list
    top_events:   list

    def __post_init__(self) -> None:
        if self.mechanism_id not in VALID_MECHANISM_IDS:
            raise ValueError(
                f"Invalid mechanism_id '{self.mechanism_id}'."
            )
        if not self.headline:
            raise ValueError("EvidenceSummary headline must be non-empty.")


# ---------------------------------------------------------------------------
# CorrelationOutput
# ---------------------------------------------------------------------------

@dataclass
class CorrelationOutput:
    """
    The output of the correlation agent for a single session.

    Produced after combining all MechanismOutput objects for a session.
    Contains the three-level analyst-facing report.

    CONFIDENCE COMBINATION
    ----------------------
    overall_confidence = Σ (mechanism_weight × mechanism_confidence)

    Default weights: velocity=0.25, enumeration=0.35, priv_escalation=0.40

    HIGH-CONFIDENCE FLOOR RULE
    --------------------------
    If any single mechanism produces confidence > high_confidence_trigger
    (default 0.90), overall_confidence is set to:
        max(overall_confidence, high_confidence_floor)
    (default floor: 0.75)

    This ensures a near-certain single-mechanism signal triggers an alert
    even without corroboration from other mechanisms.

    ABSENT VS. PRESENT-BUT-WEAK
    ---------------------------
    Mechanisms absent from the input list contribute 0 to the weighted sum
    and appear as "no signal detected" in analyst output.
    Mechanisms present with fired=False contribute 0.0 and appear as
    "no signal detected."
    Mechanisms present with fired=True appear as "signal detected" with
    their confidence score, even if confidence is very low.

    Fields
    ------
    session_id : str
        UUID matching MABE session manifest.
    overall_confidence : float
        Weighted combination of mechanism confidences (0.0–1.0).
    alert_triggered : bool
        overall_confidence >= alert_threshold.
    alert_threshold : float
        The threshold used to determine alert_triggered.
    weights_used : dict
        Cross-mechanism weights applied.
    mechanisms_fired : list[str]
        mechanism_ids that produced fired=True output.
    mechanisms_absent : list[str]
        mechanism_ids that produced no MechanismOutput at all.
    highest_layer_per_mechanism : dict
        e.g. {"velocity": 2, "enumeration": 1, "priv_escalation": 0}
    high_confidence_floor_applied : bool
        True if the floor rule was applied to this session.
    triage_card : TriageCard
        Level 1 — rapid triage summary.
    evidence_summary : list[EvidenceSummary]
        Level 2 — per-mechanism evidence breakdown.
        Only populated when alert_triggered is True.
    session_ref : str
        Level 3 — file path (SIFT) or SPL query string (Splunk).
    """
    session_id:                    str
    overall_confidence:            float
    alert_triggered:               bool
    alert_threshold:               float
    weights_used:                  dict
    mechanisms_fired:              list
    mechanisms_absent:             list
    highest_layer_per_mechanism:   dict
    high_confidence_floor_applied: bool
    triage_card:                   TriageCard
    evidence_summary:              list
    session_ref:                   str

    def __post_init__(self) -> None:
        if not 0.0 <= self.overall_confidence <= 1.0:
            raise ValueError(
                f"overall_confidence must be in [0.0, 1.0]; "
                f"got {self.overall_confidence}"
            )
        if not self.session_id:
            raise ValueError("session_id must be non-empty.")
        expected_alert = self.overall_confidence >= self.alert_threshold
        if self.alert_triggered != expected_alert:
            raise ValueError(
                f"alert_triggered={self.alert_triggered} is inconsistent with "
                f"overall_confidence={self.overall_confidence} and "
                f"alert_threshold={self.alert_threshold}"
            )
