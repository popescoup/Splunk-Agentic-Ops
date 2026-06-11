"""
MABE Detector — Splunk Field Mapper
=====================================

Translates Splunk CIM event records into the field schema expected by the
core detection mechanisms.

WHY THIS EXISTS
---------------
MABE's Splunk CIM formatter outputs events using standard CIM field names:
    _time, dest, dest_port, action, app, src, user, sourcetype, ...

The core mechanisms were written against the canonical MABE event schema:
    timestamp, dst_host, dst_port, success, protocol, src_host, user, ...

This module is the single translation layer between the two. All Splunk
ingestion code calls map_event() or map_events() before passing event
records to any core mechanism.

FIELD MAPPING TABLE
-------------------
Splunk CIM field     → Core field         Notes
--------------------   -----------------   --------------------------------
_time                → timestamp          ISO 8601 — Splunk may return epoch
                                           or string; normalised here
dest                 → dst_host           destination host identifier
dest_port            → dst_port           int; cast from string if needed
src                  → src_host           source host identifier
user                 → user               no change
action               → success            "success" → True, else False
app                  → protocol           e.g. "kerberos", "mssql"
sourcetype           → sourcetype         passed through unchanged
mabe_event_type      → event_type         detection uses this for priv_esc L1/L2
mabe_session_id      → session_id         used for evidence EvidenceRef.event_id

FIELDS NOT MAPPED (detection-input fields only — never used by mechanisms)
--------------------------------------------------------------------------
mabe_is_attack, mabe_enum_phase, mabe_attack_step, mabe_ttp,
mabe_agent_type, mabe_dwell_ms, mabe_fan_out_count

These ground-truth label fields are intentionally excluded from the mapped
output so that no detection mechanism can accidentally consume them.

UNKNOWN / MISSING FIELDS
------------------------
If a field is absent from the Splunk event, the mapped output omits it
rather than inserting a None sentinel. Core mechanisms already handle absent
fields gracefully (e.g. e.get("dst_port") returns None safely).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Timestamp normalisation
# ---------------------------------------------------------------------------

# Splunk can return _time as:
#   "2025-11-14T09:00:02.312+00:00"  (ISO 8601 with offset)
#   "2025-11-14T09:00:02.312Z"       (ISO 8601 with Z — MABE default)
#   "1731574802.312"                 (Unix epoch float string)
#   1731574802.312                   (Unix epoch float)
#
# The core mechanisms expect: "2025-11-14T09:00:02.312Z"

_ISO_Z_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$"
)
_ISO_OFFSET_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?[+-]\d{2}:\d{2}$"
)


def normalise_timestamp(raw: Any) -> str | None:
    """
    Normalise a Splunk _time value to ISO 8601 with Z suffix.

    Parameters
    ----------
    raw : Any
        Raw _time value from Splunk — string, int, or float.

    Returns
    -------
    str | None
        Normalised timestamp string, or None if parsing fails.
    """
    if raw is None:
        return None

    # Already in the right format
    if isinstance(raw, str) and _ISO_Z_RE.match(raw):
        return raw

    # ISO 8601 with timezone offset
    if isinstance(raw, str) and _ISO_OFFSET_RE.match(raw):
        try:
            # Replace offset with Z
            dt = datetime.fromisoformat(raw)
            dt_utc = dt.astimezone(timezone.utc)
            ms = dt_utc.microsecond // 1000
            return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"
        except Exception:
            pass

    # Unix epoch (float or numeric string)
    try:
        epoch = float(raw)
        dt_utc = datetime.fromtimestamp(epoch, tz=timezone.utc)
        ms = dt_utc.microsecond // 1000
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"
    except (ValueError, TypeError, OSError):
        pass

    # Fallback: return as-is if it's a non-empty string
    if isinstance(raw, str) and raw.strip():
        return raw.strip()

    return None


# ---------------------------------------------------------------------------
# Action → success mapping
# ---------------------------------------------------------------------------

def map_action_to_success(action: Any) -> bool:
    """
    Map Splunk CIM 'action' field to a boolean success flag.

    Parameters
    ----------
    action : Any
        Value of the CIM 'action' field.

    Returns
    -------
    bool
        True if action == "success" (case-insensitive), False otherwise.
    """
    if isinstance(action, str):
        return action.strip().lower() == "success"
    return bool(action)


# ---------------------------------------------------------------------------
# Single event mapper
# ---------------------------------------------------------------------------

def map_event(splunk_event: dict) -> dict:
    """
    Translate one Splunk CIM event record into core mechanism field names.

    Parameters
    ----------
    splunk_event : dict
        Raw event dict returned by splunk_run_query.

    Returns
    -------
    dict
        Mapped event with core field names. Ground-truth label fields
        (mabe_is_attack, mabe_agent_type, etc.) are excluded.

    Notes
    -----
    - Fields absent in the source event are omitted from the output (not None).
    - dst_host is set from 'dest'; the core also accepts 'dest' directly,
      but we normalise to 'dst_host' for consistency with SIFT mode.
    - dst_port is cast to int; if casting fails the field is omitted.
    - event_type is taken from mabe_event_type (the canonical MABE field);
      falls back to sourcetype-based inference if absent.
    """
    mapped: dict[str, Any] = {}

    # ── Temporal ──────────────────────────────────────────────────────────
    raw_time = splunk_event.get("_time")
    ts = normalise_timestamp(raw_time)
    if ts:
        mapped["timestamp"] = ts

    # ── Network addressing ────────────────────────────────────────────────
    dest = splunk_event.get("dest")
    if dest:
        mapped["dst_host"] = dest[0] if isinstance(dest, list) else str(dest)
        mapped["dest"] = dest[0] if isinstance(dest, list) else str(dest)

    raw_port = splunk_event.get("dest_port")
    if raw_port is not None:
        try:
            mapped["dst_port"] = int(raw_port)
        except (ValueError, TypeError):
            pass

    src = splunk_event.get("src")
    if src:
        mapped["src_host"] = src[0] if isinstance(src, list) else str(src)

    # ── Identity ──────────────────────────────────────────────────────────
    user = splunk_event.get("user")
    if user:
        mapped["user"] = user[0] if isinstance(user, list) else str(user)

    # ── Outcome ───────────────────────────────────────────────────────────
    action = splunk_event.get("action")
    if action is not None:
        mapped["success"] = map_action_to_success(action)

    # ── Protocol ─────────────────────────────────────────────────────────
    # 'app' in Splunk CIM carries the application/protocol identifier.
    # NodeClassifier.classify_event() reads e.get("protocol").
    app = splunk_event.get("app")
    if app:
        mapped["protocol"] = app[0] if isinstance(app, list) else str(app)

    # ── Event classification ──────────────────────────────────────────────
    # mabe_event_type carries the canonical event type used by priv_esc
    # mechanism for event_type == "auth_attempt", "file_access", etc.
    event_type = splunk_event.get("mabe_event_type")
    if event_type:
        mapped["event_type"] = event_type[0] if isinstance(event_type, list) else str(event_type)

    # ── Session identity ─────────────────────────────────────────────────
    session_id = splunk_event.get("mabe_session_id")
    if session_id:
        mapped["session_id"] = session_id[0] if isinstance(session_id, list) else str(session_id)

    # ── Splunk metadata (passed through for EvidenceRef.event_id) ─────────
    sourcetype = splunk_event.get("sourcetype")
    if sourcetype:
        mapped["sourcetype"] = sourcetype[0] if isinstance(sourcetype, list) else str(sourcetype)

    return mapped


# ---------------------------------------------------------------------------
# Batch mapper
# ---------------------------------------------------------------------------

def map_events(splunk_events: list[dict]) -> list[dict]:
    """
    Map a list of Splunk CIM event records to core field names.

    Parameters
    ----------
    splunk_events : list[dict]
        Raw events from splunk_run_query.

    Returns
    -------
    list[dict]
        Mapped events, in the same order. Events that produce an empty
        mapping (e.g. completely empty source dicts) are included as
        empty dicts — callers should filter if needed.
    """
    return [map_event(e) for e in splunk_events]


# ---------------------------------------------------------------------------
# Session struct builder
# ---------------------------------------------------------------------------

def build_session_struct(
    session_id: str,
    user: str,
    mapped_events: list[dict],
) -> dict:
    """
    Build the session dict structure expected by BaselineBuilder.build()
    and the dataset stats functions.

    Parameters
    ----------
    session_id : str
    user : str
    mapped_events : list[dict]
        Already-mapped events (output of map_events()).

    Returns
    -------
    dict
        {"session_id": str, "user": str, "events": list[dict]}
    """
    return {
        "session_id": session_id,
        "user": user,
        "events": mapped_events,
    }
