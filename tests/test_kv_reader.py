"""
Tests for splunk/baseline/kv_reader.py

All tests are offline — no Splunk connection required.
Tests focus on deserialization (the logic that has no live dependency).

Run with: python -m pytest tests/test_kv_reader.py -v
"""

import json
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from splunk.baseline.kv_reader import (
    _deserialize_pipe_set,
    _deserialize_json_dict,
    serialize_set_to_pipe,
    serialize_dict_to_json,
    PIPE_DELIMITER,
    POPULATION_KEY,
)

# KVBaselineReader._deserialize_row depends on AccountBaseline from core.
# Import it via the package path used in the deployed system.
from core.baseline import AccountBaseline


# ---------------------------------------------------------------------------
# _deserialize_pipe_set
# ---------------------------------------------------------------------------

class TestDeserializePipeSet:

    def test_standard_pipe_delimited(self):
        result = _deserialize_pipe_set("DC-01|WS-042|DB-02")
        assert result == {"DC-01", "WS-042", "DB-02"}

    def test_single_value(self):
        assert _deserialize_pipe_set("DC-01") == {"DC-01"}

    def test_empty_string(self):
        assert _deserialize_pipe_set("") == set()

    def test_none(self):
        assert _deserialize_pipe_set(None) == set()

    def test_whitespace_only(self):
        assert _deserialize_pipe_set("   ") == set()

    def test_strips_whitespace_around_values(self):
        result = _deserialize_pipe_set(" DC-01 | WS-042 ")
        assert result == {"DC-01", "WS-042"}

    def test_filters_empty_segments(self):
        result = _deserialize_pipe_set("DC-01||WS-042|")
        assert result == {"DC-01", "WS-042"}

    def test_json_array_format(self):
        result = _deserialize_pipe_set('["DC-01", "WS-042"]')
        assert result == {"DC-01", "WS-042"}

    def test_python_list_input(self):
        result = _deserialize_pipe_set(["DC-01", "WS-042", ""])
        assert result == {"DC-01", "WS-042"}

    def test_python_list_strips_whitespace(self):
        result = _deserialize_pipe_set(["  DC-01  ", "WS-042"])
        assert result == {"DC-01", "WS-042"}


# ---------------------------------------------------------------------------
# _deserialize_json_dict
# ---------------------------------------------------------------------------

class TestDeserializeJsonDict:

    def test_valid_json_dict(self):
        raw = '{"domain_controller": 0.15, "workstation": 0.60, "file_server": 0.25}'
        result = _deserialize_json_dict(raw)
        assert abs(result["domain_controller"] - 0.15) < 1e-9
        assert abs(result["workstation"] - 0.60) < 1e-9
        assert abs(result["file_server"] - 0.25) < 1e-9

    def test_empty_json_object(self):
        assert _deserialize_json_dict("{}") == {}

    def test_none(self):
        assert _deserialize_json_dict(None) == {}

    def test_null_string(self):
        assert _deserialize_json_dict("null") == {}

    def test_empty_string(self):
        assert _deserialize_json_dict("") == {}

    def test_malformed_json(self):
        assert _deserialize_json_dict("not-valid-json") == {}

    def test_values_cast_to_float(self):
        # Integer values in JSON should become floats
        result = _deserialize_json_dict('{"workstation": 1, "database": 0}')
        assert isinstance(result["workstation"], float)
        assert result["workstation"] == 1.0

    def test_keys_cast_to_str(self):
        result = _deserialize_json_dict('{"workstation": 0.75}')
        assert "workstation" in result
        assert isinstance(list(result.keys())[0], str)


# ---------------------------------------------------------------------------
# Round-trip serialization
# ---------------------------------------------------------------------------

class TestRoundTrip:

    def test_set_round_trip(self):
        original = {"DC-01", "WS-042", "DB-02", "FS-01", "WS-015"}
        serialized = serialize_set_to_pipe(original)
        recovered = _deserialize_pipe_set(serialized)
        assert recovered == original

    def test_dict_round_trip(self):
        original = {
            "domain_controller": 0.05,
            "workstation":       0.60,
            "file_server":       0.35,
        }
        serialized = serialize_dict_to_json(original)
        recovered = _deserialize_json_dict(serialized)
        for k, v in original.items():
            assert abs(recovered[k] - v) < 1e-9

    def test_empty_set_round_trip(self):
        serialized = serialize_set_to_pipe(set())
        recovered = _deserialize_pipe_set(serialized)
        assert recovered == set()

    def test_empty_dict_round_trip(self):
        serialized = serialize_dict_to_json({})
        recovered = _deserialize_json_dict(serialized)
        assert recovered == {}

    def test_set_sort_order_is_deterministic(self):
        s1 = {"Z", "A", "M", "B"}
        s2 = {"Z", "A", "M", "B"}
        assert serialize_set_to_pipe(s1) == serialize_set_to_pipe(s2)


# ---------------------------------------------------------------------------
# AccountBaseline deserialization (simulating _deserialize_row logic)
# ---------------------------------------------------------------------------

class TestDeserializeRow:
    """
    Tests the full deserialization path from a raw KV Store row dict
    to an AccountBaseline object.

    Replicates the logic in KVBaselineReader._deserialize_row without
    needing a live Splunk connection.
    """

    def _deserialize_row(self, row: dict):
        """Replicate KVBaselineReader._deserialize_row inline."""
        account = row.get("account", "").strip()
        if not account:
            return None
        return AccountBaseline(
            account=account,
            session_count=int(float(row.get("session_count", 0))),
            mean_destination_count=float(row.get("mean_destination_count", 0.0)),
            std_destination_count=float(row.get("std_destination_count", 0.0)),
            baseline_mode=str(row.get("baseline_mode", "individual")),
            typical_destinations=_deserialize_pipe_set(
                row.get("typical_destinations", "")
            ),
            typical_segments=_deserialize_pipe_set(
                row.get("typical_segments", "")
            ),
            node_type_distribution=_deserialize_json_dict(
                row.get("node_type_distribution", "{}")
            ),
        )

    @pytest.fixture
    def individual_row(self):
        return {
            "account":                  "j.harrison",
            "session_count":            "12",
            "typical_destinations":     "DC-01|FS-01|FS-02|WS-042",
            "node_type_distribution":
                '{"domain_controller": 0.05, "file_server": 0.35, "workstation": 0.60}',
            "mean_destination_count":   "3.8333",
            "std_destination_count":    "1.2041",
            "typical_segments":         "corporate|infrastructure",
            "baseline_mode":            "individual",
            "last_updated":             "2025-11-14T02:00:00.000Z",
        }

    @pytest.fixture
    def population_row(self):
        return {
            "account":                  "__population__",
            "session_count":            "205",
            "typical_destinations":     "WS-001|WS-002|FS-01",
            "node_type_distribution":   '{"workstation": 0.75, "file_server": 0.25}',
            "mean_destination_count":   "4.1",
            "std_destination_count":    "2.3",
            "typical_segments":         "corporate",
            "baseline_mode":            "population",
            "last_updated":             "2025-11-14T02:00:00.000Z",
        }

    def test_account_field(self, individual_row):
        bl = self._deserialize_row(individual_row)
        assert bl.account == "j.harrison"

    def test_session_count(self, individual_row):
        bl = self._deserialize_row(individual_row)
        assert bl.session_count == 12

    def test_mean_destination_count(self, individual_row):
        bl = self._deserialize_row(individual_row)
        assert abs(bl.mean_destination_count - 3.8333) < 1e-4

    def test_std_destination_count(self, individual_row):
        bl = self._deserialize_row(individual_row)
        assert abs(bl.std_destination_count - 1.2041) < 1e-4

    def test_typical_destinations_set(self, individual_row):
        bl = self._deserialize_row(individual_row)
        assert isinstance(bl.typical_destinations, set)
        assert "DC-01" in bl.typical_destinations
        assert "WS-042" in bl.typical_destinations
        assert len(bl.typical_destinations) == 4

    def test_node_type_distribution_dict(self, individual_row):
        bl = self._deserialize_row(individual_row)
        assert isinstance(bl.node_type_distribution, dict)
        assert abs(bl.node_type_distribution["workstation"] - 0.60) < 1e-9
        assert abs(bl.node_type_distribution["file_server"] - 0.35) < 1e-9

    def test_typical_segments_set(self, individual_row):
        bl = self._deserialize_row(individual_row)
        assert "corporate" in bl.typical_segments
        assert "infrastructure" in bl.typical_segments

    def test_baseline_mode_individual(self, individual_row):
        bl = self._deserialize_row(individual_row)
        assert bl.baseline_mode == "individual"

    def test_population_key(self, population_row):
        bl = self._deserialize_row(population_row)
        assert bl.account == POPULATION_KEY
        assert bl.baseline_mode == "population"
        assert bl.session_count == 205

    def test_missing_account_returns_none(self):
        assert self._deserialize_row({}) is None
        assert self._deserialize_row({"account": "  "}) is None

    def test_numeric_session_count_string(self):
        """session_count may arrive as "12.0" from Splunk stats."""
        row = {
            "account": "svc.deploy",
            "session_count": "8.0",
            "mean_destination_count": "5.0",
            "std_destination_count": "1.5",
            "baseline_mode": "individual",
        }
        bl = self._deserialize_row(row)
        assert bl.session_count == 8
        assert isinstance(bl.session_count, int)

    def test_empty_optional_fields_give_empty_collections(self):
        row = {
            "account": "new.user",
            "session_count": "1",
            "mean_destination_count": "3.0",
            "std_destination_count": "0.0",
            "baseline_mode": "individual",
            # typical_destinations, node_type_distribution, typical_segments absent
        }
        bl = self._deserialize_row(row)
        assert bl.typical_destinations == set()
        assert bl.node_type_distribution == {}
        assert bl.typical_segments == set()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:

    def test_pipe_delimiter(self):
        assert PIPE_DELIMITER == "|"

    def test_population_key(self):
        assert POPULATION_KEY == "__population__"
