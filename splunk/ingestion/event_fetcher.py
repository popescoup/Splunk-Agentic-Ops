"""
MABE Detector — Event Fetcher
================================

Fetches all events for a single session from Splunk and translates them
into the field schema expected by the core detection mechanisms.

DESIGN
------
Two concerns live here:

1. PAGINATION — Splunk's splunk_run_query has a 1,000-event response cap.
   Real MABE attack sessions can have 200–500 events; benign sessions
   typically 10–50. We stay safely under the cap for individual sessions,
   but the pagination logic is implemented defensively for production use
   where sessions can be larger.

   Strategy: request events in pages of PAGE_SIZE=900 (leaving headroom),
   using 'offset' to advance through the result set. Stop when a page
   returns fewer rows than PAGE_SIZE or the hard cap MAX_EVENTS is reached.

2. FIELD MAPPING — raw Splunk CIM events are passed through field_mapper
   before being returned. The caller receives core-schema dicts, not
   Splunk CIM dicts.

SPL QUERY
---------
Per-session event retrieval:

    index=<index> sourcetype=mabe:* mabe_session_id="<sid>"
    | table _time dest dest_port src user action app sourcetype
            mabe_event_type mabe_session_id
    | sort _time

The explicit 'table' command selects only the fields the mapper needs,
keeping result payloads small. Ground-truth label fields (mabe_is_attack,
mabe_agent_type, etc.) are excluded at the SPL level as a second line of
defence — field_mapper excludes them too, but belt-and-suspenders here
prevents label leakage even if the mapper is bypassed.

SPLUNK MCP NOTE
---------------
The SPL strings produced here are the same queries issued via the
splunk_run_query MCP tool in the agentic demo layer.
"""

from __future__ import annotations

import logging
from typing import Optional

import splunklib.client as splunk_client
import splunklib.results as splunk_results

from splunk.ingestion.field_mapper import map_events, build_session_struct

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_INDEX = "mabe"
DEFAULT_SOURCETYPE_FILTER = "mabe:*"

# Page size for paginated event retrieval.
# Set below 1000 to stay clear of the MCP cap.
PAGE_SIZE = 900

# Hard cap on total events retrieved per session.
# MABE sessions are bounded; this is a safety net for production use.
MAX_EVENTS = 10_000


# ---------------------------------------------------------------------------
# EventFetcher
# ---------------------------------------------------------------------------

class EventFetcher:
    """
    Fetches and maps events for a single session from Splunk.

    Parameters
    ----------
    service : splunklib.client.Service
        Connected and authenticated Splunk SDK service instance.
    index : str
        Splunk index name. Default: "mabe".
    sourcetype_filter : str
        Sourcetype wildcard filter. Default: "mabe:*".
    page_size : int
        Events per page for paginated retrieval. Default: 900.
    max_events : int
        Hard cap on events retrieved per session. Default: 10,000.
    """

    def __init__(
        self,
        service: splunk_client.Service,
        index: str = DEFAULT_INDEX,
        sourcetype_filter: str = DEFAULT_SOURCETYPE_FILTER,
        page_size: int = PAGE_SIZE,
        max_events: int = MAX_EVENTS,
    ) -> None:
        self._service = service
        self._index = index
        self._sourcetype_filter = sourcetype_filter
        self._page_size = page_size
        self._max_events = max_events

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def fetch_session_events(
        self,
        session_id: str,
    ) -> list[dict]:
        """
        Fetch all events for a session and return mapped core-schema dicts.

        Parameters
        ----------
        session_id : str
            The mabe_session_id to retrieve.

        Returns
        -------
        list[dict]
            Mapped events in ascending timestamp order.
            Empty list if the session has no events or the query fails.
        """
        spl = self._build_event_spl(session_id)
        logger.debug("Event fetch SPL for %s: %s", session_id, spl)

        raw_events = self._run_paginated_query(spl, session_id)
        if not raw_events:
            logger.warning("No events returned for session %s", session_id)
            return []

        mapped = map_events(raw_events)
        logger.debug(
            "Session %s: fetched %d events, mapped %d",
            session_id, len(raw_events), len(mapped)
        )
        return mapped

    def fetch_session_struct(
        self,
        session_id: str,
        user: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Fetch events and return a session struct for BaselineBuilder / stats.

        Parameters
        ----------
        session_id : str
        user : str | None
            Account identifier. If None, inferred from the first event
            with a 'user' field in the mapped results.

        Returns
        -------
        dict | None
            {"session_id": str, "user": str, "events": list[dict]}
            None if no events are returned for this session.
        """
        mapped_events = self.fetch_session_events(session_id)
        if not mapped_events:
            return None

        resolved_user = user or self._infer_user(mapped_events)
        if not resolved_user:
            logger.warning(
                "Could not determine user for session %s", session_id
            )
            resolved_user = "__unknown__"

        return build_session_struct(session_id, resolved_user, mapped_events)

    # ------------------------------------------------------------------
    # SPL construction
    # ------------------------------------------------------------------

    def _build_event_spl(self, session_id: str) -> str:
        """
        Build the per-session event retrieval SPL.

        Uses an explicit 'table' command to select only the fields needed
        by field_mapper. Ground-truth label fields are excluded at the
        SPL level as a defence-in-depth measure.

        Parameters
        ----------
        session_id : str
            The session to retrieve. Value is quoted in SPL to handle
            UUID hyphens safely.

        Returns
        -------
        str
            SPL query string.
        """
        # Escape double quotes in session_id (UUIDs won't have them, but
        # be defensive for production use with arbitrary session identifiers)
        safe_sid = session_id.replace('"', '\\"')

        spl = (
            f'search index={self._index}'
            f' sourcetype={self._sourcetype_filter}'
            f' mabe_session_id="{safe_sid}"'
            f' | table'
            f'   _time dest dest_port src user action app'
            f'   sourcetype mabe_event_type mabe_session_id'
            f' | sort _time'
        )
        return spl

    # ------------------------------------------------------------------
    # Paginated query execution
    # ------------------------------------------------------------------

    def _run_paginated_query(
        self,
        spl: str,
        session_id: str,
    ) -> list[dict]:
        """
        Execute a Splunk search with pagination and collect all results.

        Creates one blocking search job, then iterates through result
        pages using offset until exhausted or MAX_EVENTS is reached.

        Parameters
        ----------
        spl : str
            SPL query to execute.
        session_id : str
            Used only for log messages.

        Returns
        -------
        list[dict]
            All raw Splunk event dicts collected across all pages.
        """
        # Create a single blocking job — results are paged after completion
        try:
            job = self._service.jobs.create(
                spl,
                exec_mode="blocking",
                output_mode="json",
                count=0,    # job-level count=0 means no cap on total results
            )
        except Exception as exc:
            logger.error(
                "Failed to create search job for session %s: %s",
                session_id, exc
            )
            return []

        all_events: list[dict] = []
        offset = 0

        try:
            while True:
                remaining_budget = self._max_events - len(all_events)
                if remaining_budget <= 0:
                    logger.warning(
                        "Session %s hit MAX_EVENTS cap (%d)",
                        session_id, self._max_events
                    )
                    break

                page_size = min(self._page_size, remaining_budget)

                try:
                    results_stream = job.results(
                        output_mode="json",
                        count=page_size,
                        offset=offset,
                    )
                    reader = splunk_results.JSONResultsReader(results_stream)
                    page_events: list[dict] = []

                    for item in reader:
                        if isinstance(item, dict):
                            page_events.append(item)

                except Exception as exc:
                    logger.error(
                        "Failed to read results page (offset=%d) for "
                        "session %s: %s",
                        offset, session_id, exc
                    )
                    break

                all_events.extend(page_events)

                if len(page_events) < page_size:
                    # Last page — no more results
                    break

                offset += len(page_events)

        finally:
            try:
                job.cancel()
            except Exception:
                pass

        logger.debug(
            "Session %s: retrieved %d raw events in %d page(s)",
            session_id, len(all_events),
            max(1, (offset // self._page_size) + 1)
        )
        return all_events

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_user(mapped_events: list[dict]) -> Optional[str]:
        """
        Infer the account username from the first event that has one.

        Parameters
        ----------
        mapped_events : list[dict]
            Already-mapped event dicts.

        Returns
        -------
        str | None
        """
        for event in mapped_events:
            user = event.get("user")
            if user and isinstance(user, str) and user.strip():
                return user.strip()
        return None

    # ------------------------------------------------------------------
    # SPL accessor (for MCP demo layer)
    # ------------------------------------------------------------------

    def get_event_spl(self, session_id: str) -> str:
        """
        Return the event retrieval SPL string without executing it.

        Used by the MCP demo layer in main.py to issue the same query
        via splunk_run_query rather than the SDK directly.

        Parameters
        ----------
        session_id : str

        Returns
        -------
        str
            SPL query string.
        """
        return self._build_event_spl(session_id)
