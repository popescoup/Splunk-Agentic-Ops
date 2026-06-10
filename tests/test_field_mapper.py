"""
Tests for splunk/ingestion/field_mapper.py

All tests are offline — no Splunk connection required.
Run with: python -m pytest tests/test_field_mapper.py -v
"""

import pytest
import sys
import os

# Allow running from detector-splunk/ root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from splunk.ingestion.field_mapper import (
    map_event,
    map_events,
    build_session_struct,
    normalise_timestamp,
    map_action_to_success,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def canonical_event():
    """A fully populated MABE Splunk CIM event."""
    return {
        "_time":           "2025-11-14T09:00:02.312Z",
        "dest":            "DB-02",
        "dest_port":       "1433",
        "src":             "WS-042",
        "user":            "j.harrison",
        "action":          "success",
        "app":             "mssql",
        "sourcetype":      "mabe:auth",
        "mabe_event_type": "auth_attempt",
        "mabe_session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
        # Ground truth labels — must be excluded from output
        "mabe_is_attack":   True,
        "mabe_agent_type":  "ai_attacker",
        "mabe_enum_phase":  "enumeration",
        "mabe_attack_step": "auth_test",
        "mabe_dwell_ms":    42,
        "mabe_fan_out_count": 7,
    }


@pytest.fixture
def minimal_event():
    """Minimal event with only timestamp and user."""
    return {
        "_time": "2025-11-14T09:00:02.312Z",
        "user":  "svc.deploy",
    }


# ---------------------------------------------------------------------------
# normalise_timestamp
# ---------------------------------------------------------------------------

class TestNormaliseTimestamp:

    def test_z_suffix_passthrough(self):
        ts = "2025-11-14T09:00:02.312Z"
        assert normalise_timestamp(ts) == ts

    def test_iso_offset_converted_to_z(self):
        ts = "2025-11-14T09:00:02.312+00:00"
        result = normalise_timestamp(ts)
        assert result.endswith("Z")
        assert "2025-11-14" in result

    def test_epoch_float_string(self):
        # 2025-11-14T09:00:02.312Z = 1763110802.312
        result = normalise_timestamp("1763110802.312")
        assert result is not None
        assert result.endswith("Z")
        assert "2025" in result

    def test_epoch_float(self):
        result = normalise_timestamp(1763110802.312)
        assert result is not None
        assert result.endswith("Z")

    def test_none_returns_none(self):
        assert normalise_timestamp(None) is None

    def test_empty_string_returns_none(self):
        assert normalise_timestamp("") is None


# ---------------------------------------------------------------------------
# map_action_to_success
# ---------------------------------------------------------------------------

class TestMapActionToSuccess:

    def test_success_string(self):
        assert map_action_to_success("success") is True

    def test_success_uppercase(self):
        assert map_action_to_success("SUCCESS") is True

    def test_failure_string(self):
        assert map_action_to_success("failure") is False

    def test_allowed_string(self):
        assert map_action_to_success("allowed") is False

    def test_none(self):
        assert map_action_to_success(None) is False

    def test_empty_string(self):
        assert map_action_to_success("") is False


# ---------------------------------------------------------------------------
# map_event — core field translations
# ---------------------------------------------------------------------------

class TestMapEvent:

    def test_timestamp_mapped(self, canonical_event):
        mapped = map_event(canonical_event)
        assert mapped["timestamp"] == "2025-11-14T09:00:02.312Z"

    def test_dst_host_mapped(self, canonical_event):
        mapped = map_event(canonical_event)
        assert mapped["dst_host"] == "DB-02"

    def test_dest_alias_preserved(self, canonical_event):
        """baseline.py reads e.get('dst_host') or e.get('dest') — both must be set."""
        mapped = map_event(canonical_event)
        assert mapped["dest"] == "DB-02"

    def test_dst_port_cast_to_int(self, canonical_event):
        mapped = map_event(canonical_event)
        assert mapped["dst_port"] == 1433
        assert isinstance(mapped["dst_port"], int)

    def test_dst_port_int_input(self, canonical_event):
        canonical_event["dest_port"] = 5432
        mapped = map_event(canonical_event)
        assert mapped["dst_port"] == 5432

    def test_src_host_mapped(self, canonical_event):
        mapped = map_event(canonical_event)
        assert mapped["src_host"] == "WS-042"

    def test_user_mapped(self, canonical_event):
        mapped = map_event(canonical_event)
        assert mapped["user"] == "j.harrison"

    def test_success_true_for_action_success(self, canonical_event):
        mapped = map_event(canonical_event)
        assert mapped["success"] is True

    def test_success_false_for_action_failure(self, canonical_event):
        canonical_event["action"] = "failure"
        mapped = map_event(canonical_event)
        assert mapped["success"] is False

    def test_protocol_from_app(self, canonical_event):
        mapped = map_event(canonical_event)
        assert mapped["protocol"] == "mssql"

    def test_event_type_from_mabe_event_type(self, canonical_event):
        mapped = map_event(canonical_event)
        assert mapped["event_type"] == "auth_attempt"

    def test_session_id_from_mabe_session_id(self, canonical_event):
        mapped = map_event(canonical_event)
        assert mapped["session_id"] == "f47ac10b-58cc-4372-a567-0e02b2c3d479"

    def test_sourcetype_passed_through(self, canonical_event):
        mapped = map_event(canonical_event)
        assert mapped["sourcetype"] == "mabe:auth"

    # ── Ground truth label exclusion ──────────────────────────────────

    def test_mabe_is_attack_excluded(self, canonical_event):
        mapped = map_event(canonical_event)
        assert "mabe_is_attack" not in mapped

    def test_mabe_agent_type_excluded(self, canonical_event):
        mapped = map_event(canonical_event)
        assert "mabe_agent_type" not in mapped

    def test_mabe_enum_phase_excluded(self, canonical_event):
        mapped = map_event(canonical_event)
        assert "mabe_enum_phase" not in mapped

    def test_mabe_attack_step_excluded(self, canonical_event):
        mapped = map_event(canonical_event)
        assert "mabe_attack_step" not in mapped

    def test_mabe_dwell_ms_excluded(self, canonical_event):
        mapped = map_event(canonical_event)
        assert "mabe_dwell_ms" not in mapped

    def test_mabe_fan_out_count_excluded(self, canonical_event):
        mapped = map_event(canonical_event)
        assert "mabe_fan_out_count" not in mapped

    # ── Missing fields ────────────────────────────────────────────────

    def test_missing_dest_omitted(self, minimal_event):
        mapped = map_event(minimal_event)
        assert "dst_host" not in mapped
        assert "dest" not in mapped

    def test_missing_port_omitted(self, minimal_event):
        mapped = map_event(minimal_event)
        assert "dst_port" not in mapped

    def test_missing_action_omits_success(self, minimal_event):
        mapped = map_event(minimal_event)
        assert "success" not in mapped

    def test_missing_app_omits_protocol(self, minimal_event):
        mapped = map_event(minimal_event)
        assert "protocol" not in mapped

    def test_empty_dict_returns_empty(self):
        mapped = map_event({})
        assert mapped == {}

    # ── Edge cases ────────────────────────────────────────────────────

    def test_kerberos_event_type(self, canonical_event):
        canonical_event["mabe_event_type"] = "kerberos_tgt_request"
        canonical_event["app"] = "kerberos"
        canonical_event["dest_port"] = "88"
        mapped = map_event(canonical_event)
        assert mapped["event_type"] == "kerberos_tgt_request"
        assert mapped["protocol"] == "kerberos"
        assert mapped["dst_port"] == 88

    def test_file_access_event(self, canonical_event):
        canonical_event["mabe_event_type"] = "file_access"
        canonical_event["app"] = "smb"
        canonical_event["dest_port"] = "445"
        mapped = map_event(canonical_event)
        assert mapped["event_type"] == "file_access"
        assert mapped["dst_port"] == 445


# ---------------------------------------------------------------------------
# map_events — batch
# ---------------------------------------------------------------------------

class TestMapEvents:

    def test_empty_list(self):
        assert map_events([]) == []

    def test_preserves_order(self, canonical_event):
        event_a = dict(canonical_event)
        event_a["user"] = "alice"
        event_b = dict(canonical_event)
        event_b["user"] = "bob"
        results = map_events([event_a, event_b])
        assert len(results) == 2
        assert results[0]["user"] == "alice"
        assert results[1]["user"] == "bob"

    def test_all_labels_excluded_in_batch(self, canonical_event):
        results = map_events([canonical_event, canonical_event])
        for r in results:
            assert "mabe_is_attack" not in r
            assert "mabe_agent_type" not in r


# ---------------------------------------------------------------------------
# build_session_struct
# ---------------------------------------------------------------------------

class TestBuildSessionStruct:

    def test_structure(self, canonical_event):
        mapped = [map_event(canonical_event)]
        struct = build_session_struct("sid-001", "j.harrison", mapped)
        assert struct["session_id"] == "sid-001"
        assert struct["user"] == "j.harrison"
        assert struct["events"] == mapped

    def test_events_list_reference(self, canonical_event):
        mapped = [map_event(canonical_event)]
        struct = build_session_struct("sid-001", "j.harrison", mapped)
        assert struct["events"] is mapped

    def test_empty_events(self):
        struct = build_session_struct("sid-002", "svc.deploy", [])
        assert struct["events"] == []
        assert struct["session_id"] == "sid-002"
