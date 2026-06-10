"""
Tests for splunk/output/notable_event.py and splunk/output/spl_ref_builder.py

All tests are offline — no Splunk connection required.
Run with: python -m pytest tests/test_notable_event.py -v
"""

import json
import pytest
import sys
import os
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from splunk.output.spl_ref_builder import SplRefBuilder, make_session_ref_builder
from splunk.output.notable_event import (
    NotableEventFormatter,
    _map_severity,
    _iso_to_epoch,
    _build_rule_name,
    _format_evidence_summaries,
    SEARCH_NAME,
    NOTABLE_SOURCETYPE,
)

from core.schema import (
    CorrelationOutput,
    TriageCard,
    EvidenceSummary,
    TimeWindow,
    Signal,
    EvidenceRef,
    MECHANISM_VELOCITY,
    MECHANISM_ENUMERATION,
    MECHANISM_PRIV_ESC,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SESSION_ID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
ACCOUNT    = "j.harrison"


@pytest.fixture
def time_window():
    return TimeWindow(
        start="2025-11-14T09:00:00.000Z",
        end="2025-11-14T09:04:22.312Z",
    )


@pytest.fixture
def velocity_signal():
    return Signal(
        name="aggregate_rate_eps",
        observed=2.5,
        baseline=0.008,
        ratio=312.5,
        contribution=0.6,
    )


@pytest.fixture
def enum_signal():
    return Signal(
        name="distinct_destination_count",
        observed=23.0,
        baseline=4.0,
        ratio=5.75,
        contribution=1.0,
    )


@pytest.fixture
def evidence_ref():
    return EvidenceRef(
        event_id=f"{SESSION_ID}:2025-11-14T09:00:00.800Z",
        timestamp="2025-11-14T09:00:00.800Z",
        event_type="auth_attempt",
        significance="fastest inter-event gap: 800ms to next event",
        inline=None,
    )


@pytest.fixture
def velocity_summary(velocity_signal, evidence_ref):
    return EvidenceSummary(
        mechanism_id=MECHANISM_VELOCITY,
        headline="Event rate 312x above baseline (2.50 eps vs 0.01 baseline)",
        top_signals=[velocity_signal],
        top_events=[evidence_ref],
    )


@pytest.fixture
def enum_summary(enum_signal):
    return EvidenceSummary(
        mechanism_id=MECHANISM_ENUMERATION,
        headline="23 distinct hosts contacted (5.8x baseline of 4)",
        top_signals=[enum_signal],
        top_events=[],
    )


@pytest.fixture
def triage_card(time_window):
    return TriageCard(
        account=ACCOUNT,
        time_window=time_window,
        overall_confidence=0.7812,
        plain_english=(
            "Account j.harrison showed: event rate 312x above baseline; "
            "23 distinct hosts contacted including 3 high-value node type(s) "
            "between 2025-11-14T09:00:00.000Z and 2025-11-14T09:04:22.312Z."
        ),
        mechanism_scores={
            MECHANISM_VELOCITY:    0.91,
            MECHANISM_ENUMERATION: 0.73,
            MECHANISM_PRIV_ESC:    0.40,
        },
    )


@pytest.fixture
def alerted_result(triage_card, velocity_summary, enum_summary):
    return CorrelationOutput(
        session_id=SESSION_ID,
        overall_confidence=0.7812,
        alert_triggered=True,
        alert_threshold=0.60,
        weights_used={
            MECHANISM_VELOCITY: 0.25,
            MECHANISM_ENUMERATION: 0.35,
            MECHANISM_PRIV_ESC: 0.40,
        },
        mechanisms_fired=[MECHANISM_VELOCITY, MECHANISM_ENUMERATION],
        mechanisms_absent=[],
        highest_layer_per_mechanism={
            MECHANISM_VELOCITY:    3,
            MECHANISM_ENUMERATION: 2,
            MECHANISM_PRIV_ESC:    0,
        },
        high_confidence_floor_applied=False,
        triage_card=triage_card,
        evidence_summary=[velocity_summary, enum_summary],
        session_ref=f'index=mabe mabe_session_id="{SESSION_ID}" | sort _time',
    )


@pytest.fixture
def cleared_result(triage_card):
    return CorrelationOutput(
        session_id="cleared-session-id",
        overall_confidence=0.12,
        alert_triggered=False,
        alert_threshold=0.60,
        weights_used={
            MECHANISM_VELOCITY: 0.25,
            MECHANISM_ENUMERATION: 0.35,
            MECHANISM_PRIV_ESC: 0.40,
        },
        mechanisms_fired=[],
        mechanisms_absent=[MECHANISM_PRIV_ESC],
        highest_layer_per_mechanism={
            MECHANISM_VELOCITY:    0,
            MECHANISM_ENUMERATION: 0,
            MECHANISM_PRIV_ESC:    0,
        },
        high_confidence_floor_applied=False,
        triage_card=TriageCard(
            account="benign.user",
            time_window=TimeWindow(
                start="2025-11-14T10:00:00.000Z",
                end="2025-11-14T10:05:00.000Z",
            ),
            overall_confidence=0.12,
            plain_english="Account benign.user generated no significant anomaly signals.",
            mechanism_scores={
                MECHANISM_VELOCITY: 0.0,
                MECHANISM_ENUMERATION: 0.0,
                MECHANISM_PRIV_ESC: 0.0,
            },
        ),
        evidence_summary=[],
        session_ref='index=mabe mabe_session_id="cleared-session-id" | sort _time',
    )


@pytest.fixture
def spl_builder():
    return SplRefBuilder(index="mabe", sourcetype_filter="mabe:*")


@pytest.fixture
def formatter(spl_builder):
    return NotableEventFormatter(spl_builder=spl_builder)


# ---------------------------------------------------------------------------
# _map_severity
# ---------------------------------------------------------------------------

class TestMapSeverity:

    def test_critical_at_085(self):
        assert _map_severity(0.85) == "critical"

    def test_critical_above_085(self):
        assert _map_severity(0.99) == "critical"

    def test_high_at_070(self):
        assert _map_severity(0.70) == "high"

    def test_high_below_085(self):
        assert _map_severity(0.84) == "high"

    def test_medium_at_060(self):
        assert _map_severity(0.60) == "medium"

    def test_medium_below_070(self):
        assert _map_severity(0.69) == "medium"

    def test_low_at_040(self):
        assert _map_severity(0.40) == "low"

    def test_informational_below_040(self):
        assert _map_severity(0.39) == "informational"

    def test_informational_at_zero(self):
        assert _map_severity(0.0) == "informational"


# ---------------------------------------------------------------------------
# _iso_to_epoch
# ---------------------------------------------------------------------------

class TestIsoToEpoch:

    def test_known_timestamp(self):
        # 2025-11-14T09:00:02.312Z
        epoch = _iso_to_epoch("2025-11-14T09:00:02.312Z")
        assert abs(epoch - 1763110802.312) < 1.0

    def test_empty_string(self):
        assert _iso_to_epoch("") == 0.0

    def test_none_equivalent(self):
        assert _iso_to_epoch("") == 0.0

    def test_bad_format(self):
        assert _iso_to_epoch("not-a-timestamp") == 0.0

    def test_returns_float(self):
        epoch = _iso_to_epoch("2025-11-14T09:00:00.000Z")
        assert isinstance(epoch, float)


# ---------------------------------------------------------------------------
# _build_rule_name
# ---------------------------------------------------------------------------

class TestBuildRuleName:

    def test_velocity_and_enumeration(self, alerted_result):
        rule = _build_rule_name(alerted_result)
        assert "Machine-speed timing" in rule
        assert "Network enumeration" in rule
        assert ACCOUNT in rule

    def test_all_three_mechanisms(self, alerted_result):
        alerted_result.mechanisms_fired = [
            MECHANISM_VELOCITY,
            MECHANISM_ENUMERATION,
            MECHANISM_PRIV_ESC,
        ]
        rule = _build_rule_name(alerted_result)
        assert "Machine-speed timing" in rule
        assert "Network enumeration" in rule
        assert "Privilege escalation" in rule

    def test_no_mechanisms_fired(self, alerted_result):
        alerted_result.mechanisms_fired = []
        rule = _build_rule_name(alerted_result)
        assert "MABE" in rule
        assert ACCOUNT in rule

    def test_single_mechanism(self, alerted_result):
        alerted_result.mechanisms_fired = [MECHANISM_PRIV_ESC]
        rule = _build_rule_name(alerted_result)
        assert "Privilege escalation" in rule
        assert ACCOUNT in rule


# ---------------------------------------------------------------------------
# _format_evidence_summaries
# ---------------------------------------------------------------------------

class TestFormatEvidenceSummaries:

    def test_velocity_summary_serialized(self, velocity_summary):
        result = _format_evidence_summaries([velocity_summary])
        assert MECHANISM_VELOCITY in result
        parsed = json.loads(result[MECHANISM_VELOCITY])
        assert parsed["headline"] == velocity_summary.headline
        assert len(parsed["top_signals"]) == 1
        assert parsed["top_signals"][0]["name"] == "aggregate_rate_eps"
        assert parsed["top_signals"][0]["observed"] == 2.5

    def test_evidence_events_included(self, velocity_summary):
        result = _format_evidence_summaries([velocity_summary])
        parsed = json.loads(result[MECHANISM_VELOCITY])
        assert len(parsed["top_events"]) == 1
        assert parsed["top_events"][0]["event_type"] == "auth_attempt"

    def test_multiple_summaries(self, velocity_summary, enum_summary):
        result = _format_evidence_summaries([velocity_summary, enum_summary])
        assert MECHANISM_VELOCITY in result
        assert MECHANISM_ENUMERATION in result

    def test_empty_summaries(self):
        result = _format_evidence_summaries([])
        assert result == {}

    def test_empty_signals_and_events(self):
        summary = EvidenceSummary(
            mechanism_id=MECHANISM_PRIV_ESC,
            headline="Privilege escalation detected",
            top_signals=[],
            top_events=[],
        )
        result = _format_evidence_summaries([summary])
        parsed = json.loads(result[MECHANISM_PRIV_ESC])
        assert parsed["top_signals"] == []
        assert parsed["top_events"] == []


# ---------------------------------------------------------------------------
# SplRefBuilder
# ---------------------------------------------------------------------------

class TestSplRefBuilder:

    def test_base_spl_contains_session_id(self, spl_builder):
        spl = spl_builder.build(SESSION_ID)
        assert f'mabe_session_id="{SESSION_ID}"' in spl

    def test_base_spl_contains_sort(self, spl_builder):
        spl = spl_builder.build(SESSION_ID)
        assert "| sort _time" in spl

    def test_base_spl_contains_table(self, spl_builder):
        spl = spl_builder.build(SESSION_ID)
        assert "| table" in spl

    def test_base_spl_excludes_ground_truth_labels(self, spl_builder):
        spl = spl_builder.build(SESSION_ID)
        assert "mabe_is_attack" not in spl
        assert "mabe_agent_type" not in spl

    def test_quote_escaping(self, spl_builder):
        spl = spl_builder.build('abc"def')
        assert '\\"' in spl

    def test_focused_velocity_adds_gap_eval(self, spl_builder):
        spl = spl_builder.build_focused(SESSION_ID, [MECHANISM_VELOCITY])
        assert "gap_ms" in spl

    def test_focused_priv_esc_filters_event_types(self, spl_builder):
        spl = spl_builder.build_focused(SESSION_ID, [MECHANISM_PRIV_ESC])
        assert "auth_attempt" in spl
        assert "file_access" in spl
        assert "kerberos_tgt_request" in spl

    def test_focused_all_mechanisms(self, spl_builder):
        spl = spl_builder.build_focused(
            SESSION_ID,
            [MECHANISM_VELOCITY, MECHANISM_ENUMERATION, MECHANISM_PRIV_ESC]
        )
        assert "gap_ms" in spl
        assert "dest_port" in spl

    def test_make_session_ref_builder_factory(self):
        fn = make_session_ref_builder()
        spl = fn(SESSION_ID)
        assert f'mabe_session_id="{SESSION_ID}"' in spl


# ---------------------------------------------------------------------------
# NotableEventFormatter
# ---------------------------------------------------------------------------

class TestNotableEventFormatter:

    def test_format_returns_dict(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert isinstance(ne, dict)

    def test_search_name_present(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert ne["search_name"] == SEARCH_NAME

    def test_sourcetype_is_stash(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert ne["sourcetype"] == NOTABLE_SOURCETYPE

    def test_user_and_src_are_account(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert ne["user"] == ACCOUNT
        assert ne["src"] == ACCOUNT

    def test_severity_is_high_for_0_78(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert ne["severity"] == "high"

    def test_mabe_session_id_present(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert ne["mabe_session_id"] == SESSION_ID

    def test_overall_confidence_rounded(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert ne["mabe_overall_confidence"] == 0.7812

    def test_mechanism_scores_present(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert ne["mabe_velocity_confidence"] == 0.91
        assert ne["mabe_enumeration_confidence"] == 0.73
        assert ne["mabe_priv_escalation_confidence"] == 0.40

    def test_highest_layers_present(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert ne["mabe_highest_layer_velocity"] == 3
        assert ne["mabe_highest_layer_enumeration"] == 2
        assert ne["mabe_highest_layer_priv_escalation"] == 0

    def test_mechanisms_fired_pipe_delimited(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        fired = ne["mabe_mechanisms_fired"]
        parts = set(fired.split("|"))
        assert "velocity" in parts
        assert "enumeration" in parts

    def test_narrative_override_used(self, formatter, alerted_result):
        custom = "Enhanced LLM narrative for analyst."
        ne = formatter.format(alerted_result, narrative_override=custom)
        assert ne["rule_description"] == custom

    def test_plain_english_used_when_no_override(self, formatter, alerted_result):
        ne = formatter.format(alerted_result, narrative_override=None)
        assert ne["rule_description"] == alerted_result.triage_card.plain_english

    def test_drilldown_search_present(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert "drilldown_search" in ne
        assert SESSION_ID in ne["drilldown_search"]

    def test_session_time_bounds_present(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert ne["mabe_session_start"] == "2025-11-14T09:00:00.000Z"
        assert ne["mabe_session_end"]   == "2025-11-14T09:04:22.312Z"

    def test_evidence_json_for_velocity(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        vel_json = ne["mabe_evidence_velocity"]
        assert vel_json != "{}"
        parsed = json.loads(vel_json)
        assert "headline" in parsed
        assert "top_signals" in parsed

    def test_evidence_json_empty_for_absent_mechanism(
        self, formatter, alerted_result
    ):
        # priv_escalation didn't fire — no evidence summary for it
        ne = formatter.format(alerted_result)
        pe_json = ne["mabe_evidence_priv_escalation"]
        assert pe_json == "{}"

    def test_floor_applied_flag(self, formatter, alerted_result):
        ne = formatter.format(alerted_result)
        assert ne["mabe_floor_applied"] == 0   # False → int 0

        alerted_result.high_confidence_floor_applied = True
        ne2 = formatter.format(alerted_result)
        assert ne2["mabe_floor_applied"] == 1

    # ── format_batch ─────────────────────────────────────────────────

    def test_format_batch_skips_cleared(
        self, formatter, alerted_result, cleared_result
    ):
        notables = formatter.format_batch([alerted_result, cleared_result])
        assert len(notables) == 1
        assert notables[0]["mabe_session_id"] == SESSION_ID

    def test_format_batch_empty_results(self, formatter):
        assert formatter.format_batch([]) == []

    def test_format_batch_applies_narrative(
        self, formatter, alerted_result
    ):
        narratives = {SESSION_ID: "Custom narrative here."}
        notables = formatter.format_batch([alerted_result], narratives=narratives)
        assert notables[0]["rule_description"] == "Custom narrative here."

    def test_format_batch_no_narratives_uses_plain_english(
        self, formatter, alerted_result
    ):
        notables = formatter.format_batch([alerted_result])
        assert notables[0]["rule_description"] == alerted_result.triage_card.plain_english
