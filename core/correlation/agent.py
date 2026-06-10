"""
MABE Detector — Correlation Agent
===================================
Version: 1.0.0

Receives MechanismOutput objects from all mechanisms for a single session,
applies weighted confidence combination, and produces a CorrelationOutput
with a three-level analyst-facing report.

ROLE
----
The correlation agent does NOT perform detection. It synthesizes and
triages. Detection is the mechanisms' responsibility.

CONFIDENCE COMBINATION
----------------------
overall_confidence = Σ (mechanism_weight × mechanism_confidence)

HIGH-CONFIDENCE FLOOR RULE
--------------------------
If any single mechanism produces confidence > trigger_threshold (0.90),
overall_confidence = max(overall_confidence, floor_value) (0.75).

This ensures a near-certain single-mechanism signal triggers an alert
even without corroboration.

THREE-LEVEL OUTPUT
------------------
Level 1 — TriageCard: rapid triage in ≤5 lines
Level 2 — EvidenceSummary: per-mechanism breakdown (only when alert fires)
Level 3 — session_ref: file path (SIFT) or SPL query (Splunk)

PLAIN ENGLISH GENERATION
------------------------
In core, the plain_english field is generated programmatically from
signal values. LLM-enhanced narrative is a platform-specific enhancement.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from core.schema import (
    MechanismOutput,
    CorrelationOutput,
    TriageCard,
    EvidenceSummary,
    TimeWindow,
    Signal,
    EvidenceRef,
    MECHANISM_VELOCITY,
    MECHANISM_ENUMERATION,
    MECHANISM_PRIV_ESC,
    VALID_MECHANISM_IDS,
)
from core.config_loader import (
    load_thresholds,
    get_mechanism_weights,
    get_alert_threshold,
    get_high_confidence_floor_params,
)

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

AGENT_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# CorrelationAgent
# ---------------------------------------------------------------------------

class CorrelationAgent:
    """
    Combines mechanism outputs and produces analyst-facing reports.

    Parameters
    ----------
    thresholds : dict | None
        Loaded thresholds config. If None, loads from config file.
    alert_threshold_override : float | None
        Override the configured alert threshold. Use for deployment-
        specific calibration (SIFT: 0.35, Splunk: 0.60).
    session_ref_builder : callable | None
        Function (session_id: str) -> str that produces the Level 3
        session reference. Platform-specific — SIFT builds a file path,
        Splunk builds an SPL query. If None, returns a placeholder.
    """

    def __init__(
        self,
        thresholds: dict | None = None,
        alert_threshold_override: float | None = None,
        session_ref_builder: Optional[callable] = None,
    ) -> None:
        cfg = thresholds or load_thresholds()
        self._weights = get_mechanism_weights(cfg)
        self._alert_threshold = (
            alert_threshold_override
            if alert_threshold_override is not None
            else get_alert_threshold(cfg)
        )
        self._hcf_trigger, self._hcf_floor = get_high_confidence_floor_params(cfg)
        self._session_ref_builder = (
            session_ref_builder or _default_session_ref_builder
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def correlate(
        self,
        session_id: str,
        account: str,
        mechanism_outputs: list[MechanismOutput],
    ) -> CorrelationOutput:
        """
        Correlate mechanism outputs for a session and produce a report.

        Parameters
        ----------
        session_id : str
            Session UUID.
        account : str
            Username / account identifier for this session.
        mechanism_outputs : list[MechanismOutput]
            All MechanismOutput objects produced for this session.
            May be empty (produces zero-confidence output).
            Mechanisms that produced no output are absent from this list.

        Returns
        -------
        CorrelationOutput
        """
        evaluated_at = _now_iso()

        # Index outputs by mechanism_id
        outputs_by_id: dict[str, MechanismOutput] = {
            o.mechanism_id: o for o in mechanism_outputs
        }

        # Determine absent mechanisms (no output produced at all)
        mechanisms_absent = sorted(
            VALID_MECHANISM_IDS - set(outputs_by_id.keys())
        )

        # Mechanisms that fired (confidence > 0)
        mechanisms_fired = sorted(
            mid for mid, output in outputs_by_id.items()
            if output.fired
        )

        # Per-mechanism confidence scores (0.0 for absent or not fired)
        mechanism_scores = {
            mid: (
                outputs_by_id[mid].confidence
                if mid in outputs_by_id and outputs_by_id[mid].fired
                else 0.0
            )
            for mid in VALID_MECHANISM_IDS
        }

        # Weighted confidence combination
        overall_confidence = sum(
            self._weights.get(mid, 0.0) * score
            for mid, score in mechanism_scores.items()
        )
        overall_confidence = min(overall_confidence, 1.0)

        # High-confidence floor rule
        floor_applied = False
        max_single_confidence = max(mechanism_scores.values()) if mechanism_scores else 0.0
        if max_single_confidence > self._hcf_trigger:
            if overall_confidence < self._hcf_floor:
                overall_confidence = self._hcf_floor
                floor_applied = True

        overall_confidence = round(overall_confidence, 4)

        # Alert decision
        alert_triggered = overall_confidence >= self._alert_threshold

        # Highest layer per mechanism
        highest_layer_per_mechanism = {
            mid: (outputs_by_id[mid].highest_layer if mid in outputs_by_id else 0)
            for mid in VALID_MECHANISM_IDS
        }

        # Determine data window for triage card
        data_window = self._compute_session_window(outputs_by_id)

        # Level 1 — Triage card
        triage_card = self._build_triage_card(
            account=account,
            data_window=data_window,
            overall_confidence=overall_confidence,
            mechanism_scores=mechanism_scores,
            outputs_by_id=outputs_by_id,
        )

        # Level 2 — Evidence summaries (only when alert fires)
        evidence_summary = []
        if alert_triggered:
            evidence_summary = self._build_evidence_summaries(
                outputs_by_id, mechanisms_fired
            )

        # Level 3 — Session reference
        session_ref = self._session_ref_builder(session_id)

        return CorrelationOutput(
            session_id=session_id,
            overall_confidence=overall_confidence,
            alert_triggered=alert_triggered,
            alert_threshold=self._alert_threshold,
            weights_used=dict(self._weights),
            mechanisms_fired=mechanisms_fired,
            mechanisms_absent=mechanisms_absent,
            highest_layer_per_mechanism=highest_layer_per_mechanism,
            high_confidence_floor_applied=floor_applied,
            triage_card=triage_card,
            evidence_summary=evidence_summary,
            session_ref=session_ref,
        )

    # ------------------------------------------------------------------
    # Triage card builder
    # ------------------------------------------------------------------

    def _build_triage_card(
        self,
        account: str,
        data_window: TimeWindow,
        overall_confidence: float,
        mechanism_scores: dict[str, float],
        outputs_by_id: dict[str, MechanismOutput],
    ) -> TriageCard:
        plain_english = self._generate_plain_english(
            account, data_window, mechanism_scores, outputs_by_id
        )
        return TriageCard(
            account=account,
            time_window=data_window,
            overall_confidence=overall_confidence,
            plain_english=plain_english,
            mechanism_scores={
                mid: round(score, 4)
                for mid, score in mechanism_scores.items()
            },
        )

    def _generate_plain_english(
        self,
        account: str,
        data_window: TimeWindow,
        mechanism_scores: dict[str, float],
        outputs_by_id: dict[str, MechanismOutput],
    ) -> str:
        """
        Programmatically generate a one-sentence session characterization.

        In core, this uses templates populated from signal values.
        Platform-specific specializations may override with LLM-generated
        narrative.
        """
        parts: list[str] = []

        # Velocity component
        vel_score = mechanism_scores.get(MECHANISM_VELOCITY, 0.0)
        if vel_score > 0 and MECHANISM_VELOCITY in outputs_by_id:
            vel_output = outputs_by_id[MECHANISM_VELOCITY]
            rate_signal = next(
                (s for s in vel_output.signals if s.name == "aggregate_rate_eps"),
                None
            )
            if rate_signal and rate_signal.baseline > 0:
                ratio = rate_signal.ratio
                parts.append(
                    f"event rate {ratio:.0f}x above baseline"
                )
            else:
                parts.append("machine-speed event timing")

        # Enumeration component
        enum_score = mechanism_scores.get(MECHANISM_ENUMERATION, 0.0)
        if enum_score > 0 and MECHANISM_ENUMERATION in outputs_by_id:
            enum_output = outputs_by_id[MECHANISM_ENUMERATION]
            dest_signal = next(
                (s for s in enum_output.signals
                 if s.name == "distinct_destination_count"),
                None
            )
            hv_signal = next(
                (s for s in enum_output.signals
                 if s.name == "high_value_node_contacts"),
                None
            )
            if dest_signal:
                desc = f"{int(dest_signal.observed)} distinct hosts contacted"
                if hv_signal and hv_signal.observed > 0:
                    desc += f" including {int(hv_signal.observed)} high-value node type(s)"
                parts.append(desc)
            else:
                parts.append("unusually broad network access")

        # Privilege escalation component
        pe_score = mechanism_scores.get(MECHANISM_PRIV_ESC, 0.0)
        if pe_score > 0 and MECHANISM_PRIV_ESC in outputs_by_id:
            pe_output = outputs_by_id[MECHANISM_PRIV_ESC]
            depth_signal = next(
                (s for s in pe_output.signals if s.name == "chain_depth"),
                None
            )
            delta_signal = next(
                (s for s in pe_output.signals
                 if s.name == "harvest_to_escalation_delta_s"),
                None
            )
            if depth_signal and delta_signal:
                parts.append(
                    f"privilege escalated {int(depth_signal.observed)} level(s) "
                    f"within {delta_signal.observed:.0f}s of credential access"
                )
            elif depth_signal:
                parts.append(
                    f"privilege escalated to {int(depth_signal.observed)} level(s) "
                    "above session start"
                )
            else:
                parts.append("credential harvest followed by privilege escalation")

        if not parts:
            return (
                f"Account {account} generated no significant anomaly signals "
                f"between {data_window.start} and {data_window.end}."
            )

        findings = "; ".join(parts)
        return (
            f"Account {account} showed: {findings} "
            f"between {data_window.start} and {data_window.end}."
        )

    # ------------------------------------------------------------------
    # Evidence summary builder
    # ------------------------------------------------------------------

    def _build_evidence_summaries(
        self,
        outputs_by_id: dict[str, MechanismOutput],
        mechanisms_fired: list[str],
    ) -> list[EvidenceSummary]:
        summaries: list[EvidenceSummary] = []

        for mid in mechanisms_fired:
            output = outputs_by_id.get(mid)
            if not output:
                continue

            # Top 3 signals by contribution
            top_signals = sorted(
                output.signals, key=lambda s: s.contribution, reverse=True
            )[:3]

            # Top 5 evidence events
            top_events = output.evidence[:5]

            # Generate headline from top signal
            headline = self._generate_headline(mid, output, top_signals)

            summaries.append(EvidenceSummary(
                mechanism_id=mid,
                headline=headline,
                top_signals=top_signals,
                top_events=top_events,
            ))

        return summaries

    def _generate_headline(
        self,
        mechanism_id: str,
        output: MechanismOutput,
        top_signals: list[Signal],
    ) -> str:
        """Generate a one-sentence headline for a mechanism's findings."""
        if not top_signals:
            return f"{mechanism_id} mechanism: anomalous behavior detected"

        top = top_signals[0]

        if mechanism_id == MECHANISM_VELOCITY:
            if top.name == "aggregate_rate_eps":
                return (
                    f"Event rate {top.ratio:.0f}x above baseline "
                    f"({top.observed:.2f} events/sec vs "
                    f"{top.baseline:.2f} baseline)"
                )
            if top.name == "median_inter_event_ms":
                return (
                    f"Median inter-event gap {top.observed:.0f}ms "
                    f"({top.ratio:.4f}x of {top.baseline:.0f}ms baseline)"
                )
            return f"Machine-speed timing: {top.name}={top.observed:.4f}"

        if mechanism_id == MECHANISM_ENUMERATION:
            if top.name == "distinct_destination_count":
                return (
                    f"{int(top.observed)} distinct hosts contacted "
                    f"({top.ratio:.1f}x baseline of {top.baseline:.0f})"
                )
            if top.name == "high_value_node_contacts":
                return (
                    f"{int(top.observed)} high-value node type(s) contacted "
                    "outside typical account scope"
                )
            return f"Broad enumeration detected: {top.name}={top.observed:.4f}"

        if mechanism_id == MECHANISM_PRIV_ESC:
            if top.name == "chain_depth":
                return (
                    f"Credential chain reached {int(top.observed)} privilege "
                    "level(s) above session start"
                )
            if top.name == "harvest_to_escalation_delta_s":
                return (
                    f"Privilege escalation {top.observed:.0f}s after "
                    "credential access indicator"
                )
            return f"Privilege escalation chain detected: {top.name}={top.observed}"

        return f"{mechanism_id}: {top.name}={top.observed:.4f}"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _compute_session_window(
        self,
        outputs_by_id: dict[str, MechanismOutput],
    ) -> TimeWindow:
        """Compute the union of all mechanism data windows."""
        starts = [o.data_window.start for o in outputs_by_id.values()
                  if o.data_window.start]
        ends   = [o.data_window.end for o in outputs_by_id.values()
                  if o.data_window.end]

        if not starts or not ends:
            now = _now_iso()
            return TimeWindow(start=now, end=now)

        return TimeWindow(
            start=min(starts),
            end=max(ends),
        )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return current UTC time as ISO 8601 with millisecond precision."""
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _default_session_ref_builder(session_id: str) -> str:
    """
    Default session reference builder — returns a placeholder.

    Replace with a platform-specific implementation in SIFT or Splunk
    specializations.
    """
    return f"session_ref:{session_id}"
