"""
MABE Detector — Splunk Notable Event Formatter
================================================

Formats CorrelationOutput as a Splunk Enterprise Security notable event
dict, ready for indexing via the Splunk SDK or MCP tool.

NOTABLE EVENT FORMAT
--------------------
Splunk ES notable events live in the `notable` index and follow a
well-defined field schema that ES correlation searches and the Incident
Review dashboard expect. Key fields:

    search_name     Name of the correlation search that generated this alert
    orig_time       Unix epoch of the session start (_time of first event)
    src             Source account / host of the anomalous session
    user            Account identifier
    severity        "critical" | "high" | "medium" | "low" | "informational"
    rule_name       Human-readable alert name
    rule_description One-sentence triage narrative (LLM-enhanced if available)
    drilldown_search SPL query to retrieve session events (Level 3 ref)
    drilldown_name  Label for the drilldown link in ES UI

MABE-SPECIFIC FIELDS
--------------------
Non-standard fields are prefixed with mabe_ to avoid collisions:

    mabe_session_id             Session UUID
    mabe_overall_confidence     Weighted confidence score
    mabe_alert_threshold        Threshold used
    mabe_mechanisms_fired       Pipe-delimited fired mechanism IDs
    mabe_mechanisms_absent      Pipe-delimited absent mechanism IDs
    mabe_velocity_confidence    Per-mechanism scores
    mabe_enumeration_confidence
    mabe_priv_escalation_confidence
    mabe_highest_layer_velocity     Layer depth per mechanism
    mabe_highest_layer_enumeration
    mabe_highest_layer_priv_escalation
    mabe_floor_applied          bool — high-confidence floor rule triggered
    mabe_session_start          ISO 8601 session start timestamp
    mabe_session_end            ISO 8601 session end timestamp
    mabe_evidence_velocity      JSON evidence summary for velocity
    mabe_evidence_enumeration   JSON evidence summary for enumeration
    mabe_evidence_priv_escalation JSON evidence summary for priv_esc

SEVERITY MAPPING
----------------
overall_confidence → Splunk ES severity:

    >= 0.85   critical
    >= 0.70   high
    >= 0.60   medium   (alert threshold floor)
    >= 0.40   low
    <  0.40   informational

INDEXING
--------
Notable events are written to Splunk via:

    index=notable source=mabe_detector sourcetype=stash

The `stash` sourcetype triggers Splunk ES's notable event processing
pipeline, which routes the event into the Incident Review dashboard.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from core.schema import (
    CorrelationOutput,
    EvidenceSummary,
    MECHANISM_VELOCITY,
    MECHANISM_ENUMERATION,
    MECHANISM_PRIV_ESC,
)
from splunk.output.spl_ref_builder import SplRefBuilder

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NOTABLE_SOURCE     = "mabe_detector"
NOTABLE_SOURCETYPE = "stash"
NOTABLE_INDEX      = "notable"
SEARCH_NAME        = "MABE - AI Attack Behavior Detector"

SEVERITY_THRESHOLDS = [
    (0.85, "critical"),
    (0.70, "high"),
    (0.60, "medium"),
    (0.40, "low"),
    (0.00, "informational"),
]


# ---------------------------------------------------------------------------
# NotableEventFormatter
# ---------------------------------------------------------------------------

class NotableEventFormatter:
    """
    Formats CorrelationOutput objects as Splunk ES notable event dicts.

    Parameters
    ----------
    spl_builder : SplRefBuilder
        Used to generate focused drilldown SPL when mechanisms are known.
    index : str
        Target index. Default: "notable".
    """

    def __init__(
        self,
        spl_builder: SplRefBuilder,
        index: str = NOTABLE_INDEX,
    ) -> None:
        self._spl_builder = spl_builder
        self._index = index

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def format(
        self,
        result: CorrelationOutput,
        narrative_override: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Format a CorrelationOutput as a Splunk ES notable event dict.

        Parameters
        ----------
        result : CorrelationOutput
            Detection result from the correlation agent.
        narrative_override : str | None
            If provided, replaces the triage card's plain_english field
            with an LLM-enhanced narrative from narrative.py.

        Returns
        -------
        dict[str, Any]
            Notable event ready for Splunk indexing.
        """
        tc = result.triage_card
        scores = tc.mechanism_scores

        narrative = narrative_override or tc.plain_english
        severity  = _map_severity(result.overall_confidence)

        # Session time bounds
        session_start = tc.time_window.start if tc.time_window else ""
        session_end   = tc.time_window.end   if tc.time_window else ""
        orig_time     = _iso_to_epoch(session_start)

        # Focused drilldown SPL
        drilldown_spl = self._spl_builder.build_focused(
            session_id=result.session_id,
            mechanisms_fired=result.mechanisms_fired,
        )

        # Per-mechanism highest layers
        layers = result.highest_layer_per_mechanism

        # Evidence summaries as JSON
        evidence_json = _format_evidence_summaries(result.evidence_summary)

        notable: dict[str, Any] = {
            # ── Splunk ES required fields ─────────────────────────────
            "search_name":       SEARCH_NAME,
            "source":            NOTABLE_SOURCE,
            "sourcetype":        NOTABLE_SOURCETYPE,
            "index":             self._index,
            "_time":             orig_time,
            "orig_time":         orig_time,

            # ── Identity ──────────────────────────────────────────────
            "src":               tc.account,
            "user":              tc.account,

            # ── Alert metadata ────────────────────────────────────────
            "severity":          severity,
            "rule_name":         _build_rule_name(result),
            "rule_description":  narrative,

            # ── Drilldown (Level 3) ───────────────────────────────────
            "drilldown_search":  drilldown_spl,
            "drilldown_name":    f"Investigate session {result.session_id}",

            # ── MABE detection fields ─────────────────────────────────
            "mabe_session_id":              result.session_id,
            "mabe_overall_confidence":      round(result.overall_confidence, 4),
            "mabe_alert_threshold":         result.alert_threshold,
            "mabe_mechanisms_fired":        "|".join(sorted(result.mechanisms_fired)),
            "mabe_mechanisms_absent":       "|".join(sorted(result.mechanisms_absent)),
            "mabe_floor_applied":           int(result.high_confidence_floor_applied),

            # Per-mechanism confidence scores
            "mabe_velocity_confidence":
                round(scores.get(MECHANISM_VELOCITY, 0.0), 4),
            "mabe_enumeration_confidence":
                round(scores.get(MECHANISM_ENUMERATION, 0.0), 4),
            "mabe_priv_escalation_confidence":
                round(scores.get(MECHANISM_PRIV_ESC, 0.0), 4),

            # Per-mechanism highest layers
            "mabe_highest_layer_velocity":
                layers.get(MECHANISM_VELOCITY, 0),
            "mabe_highest_layer_enumeration":
                layers.get(MECHANISM_ENUMERATION, 0),
            "mabe_highest_layer_priv_escalation":
                layers.get(MECHANISM_PRIV_ESC, 0),

            # Session time bounds
            "mabe_session_start": session_start,
            "mabe_session_end":   session_end,

            # Evidence summaries (Level 2) — JSON blobs for ES panels
            "mabe_evidence_velocity":
                evidence_json.get(MECHANISM_VELOCITY, "{}"),
            "mabe_evidence_enumeration":
                evidence_json.get(MECHANISM_ENUMERATION, "{}"),
            "mabe_evidence_priv_escalation":
                evidence_json.get(MECHANISM_PRIV_ESC, "{}"),
        }

        return notable

    def format_batch(
        self,
        results: list[CorrelationOutput],
        narratives: Optional[dict[str, str]] = None,
    ) -> list[dict[str, Any]]:
        """
        Format a list of CorrelationOutput objects.

        Only formats results where alert_triggered is True.
        Silently skips non-alert results.

        Parameters
        ----------
        results : list[CorrelationOutput]
        narratives : dict[str, str] | None
            Optional mapping of session_id → LLM narrative override.

        Returns
        -------
        list[dict[str, Any]]
            Notable event dicts for all triggered alerts.
        """
        notables: list[dict[str, Any]] = []
        narr = narratives or {}

        for result in results:
            if not result.alert_triggered:
                continue
            narrative_override = narr.get(result.session_id)
            notables.append(
                self.format(result, narrative_override=narrative_override)
            )

        logger.info(
            "Formatted %d notable event(s) from %d result(s).",
            len(notables), len(results)
        )
        return notables


# ---------------------------------------------------------------------------
# Notable event writer
# ---------------------------------------------------------------------------

class NotableEventWriter:
    """
    Writes notable events to Splunk via the SDK.

    Uses direct index submission rather than HTTP Event Collector,
    consistent with the rest of the Splunk SDK usage in this project.

    Parameters
    ----------
    service : splunklib.client.Service
        Connected and authenticated Splunk SDK service.
    index_name : str
        Target index. Default: "notable".
    """

    def __init__(
        self,
        service,                        # splunklib.client.Service
        index_name: str = NOTABLE_INDEX,
    ) -> None:
        self._service    = service
        self._index_name = index_name

    def write(self, notable_event: dict[str, Any]) -> bool:
        """
        Write a single notable event to Splunk.

        Parameters
        ----------
        notable_event : dict[str, Any]
            Formatted notable event from NotableEventFormatter.format().

        Returns
        -------
        bool
            True on success, False on failure.
        """
        try:
            index = self._service.indexes[self._index_name]
            index.submit(
                json.dumps(notable_event),
                sourcetype=NOTABLE_SOURCETYPE,
                source=NOTABLE_SOURCE,
            )
            logger.info(
                "Wrote notable event for session %s (severity=%s).",
                notable_event.get("mabe_session_id", "unknown"),
                notable_event.get("severity", "unknown"),
            )
            return True
        except Exception as exc:
            logger.error(
                "Failed to write notable event for session %s: %s",
                notable_event.get("mabe_session_id", "unknown"), exc
            )
            return False

    def write_batch(
        self, notable_events: list[dict[str, Any]]
    ) -> tuple[int, int]:
        """
        Write a batch of notable events to Splunk.

        Parameters
        ----------
        notable_events : list[dict]

        Returns
        -------
        tuple[int, int]
            (success_count, failure_count)
        """
        success = 0
        failure = 0
        for event in notable_events:
            if self.write(event):
                success += 1
            else:
                failure += 1
        logger.info(
            "Notable event batch write: %d success, %d failure.",
            success, failure
        )
        return success, failure


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _map_severity(confidence: float) -> str:
    """Map a confidence score to a Splunk ES severity string."""
    for threshold, label in SEVERITY_THRESHOLDS:
        if confidence >= threshold:
            return label
    return "informational"


def _iso_to_epoch(iso_ts: str) -> float:
    """
    Convert an ISO 8601 timestamp with Z suffix to a Unix epoch float.

    Returns 0.0 on parse failure.
    """
    if not iso_ts:
        return 0.0
    try:
        dt = datetime.strptime(iso_ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
        return dt.timestamp()
    except ValueError:
        try:
            dt = datetime.strptime(iso_ts, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
            return dt.timestamp()
        except ValueError:
            return 0.0


def _build_rule_name(result: CorrelationOutput) -> str:
    """
    Build a human-readable rule name for the notable event.

    Format: "MABE: <mechanisms> detected for <account>"
    """
    fired = result.mechanisms_fired
    if not fired:
        return f"MABE: Anomalous behavior — {result.triage_card.account}"

    mechanism_labels = {
        "velocity":        "Machine-speed timing",
        "enumeration":     "Network enumeration",
        "priv_escalation": "Privilege escalation",
    }
    labels = [mechanism_labels.get(m, m) for m in sorted(fired)]
    mechanisms_str = " + ".join(labels)
    return f"MABE: {mechanisms_str} — {result.triage_card.account}"


def _format_evidence_summaries(
    summaries: list[EvidenceSummary],
) -> dict[str, str]:
    """
    Serialize evidence summaries to JSON strings keyed by mechanism_id.

    Returns empty JSON object string for mechanisms with no summary.
    """
    result: dict[str, str] = {}

    for summary in summaries:
        evidence_dict = {
            "headline": summary.headline,
            "top_signals": [
                {
                    "name":        s.name,
                    "observed":    s.observed,
                    "baseline":    s.baseline,
                    "ratio":       s.ratio,
                    "contribution": s.contribution,
                }
                for s in (summary.top_signals or [])
            ],
            "top_events": [
                {
                    "event_id":    e.event_id,
                    "timestamp":   e.timestamp,
                    "event_type":  e.event_type,
                    "significance": e.significance,
                }
                for e in (summary.top_events or [])
            ],
        }
        result[summary.mechanism_id] = json.dumps(evidence_dict)

    return result
