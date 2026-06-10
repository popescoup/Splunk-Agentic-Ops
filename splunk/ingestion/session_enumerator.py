"""
MABE Detector — Session Enumerator
=====================================

Queries Splunk for all distinct mabe_session_id values present in the
configured index. This is the first step in the detection loop — it
produces the list of session IDs that the runner will process one by one.

DESIGN
------
Two query modes are supported:

1. ALL sessions — returns every session ID in the index.
   Used for a full batch detection run over a MABE dataset.

2. RECENT sessions — returns session IDs from events in the last N minutes.
   Used for near-real-time polling mode (e.g. run every 5 minutes, process
   sessions that have accumulated new events since last run).

SPL QUERY
---------
Both modes use a stats-based enumeration query:

    index=<index> [earliest=<t>]
    | stats count by mabe_session_id
    | fields mabe_session_id

This is O(index_size) but returns only one row per session, so it never
hits the 1000-event response cap regardless of dataset size.

SPLUNK MCP NOTE
---------------
The SPL strings produced here are the same queries issued via the
splunk_run_query MCP tool in the agentic demo layer. In standalone
Python execution, the Splunk SDK client is used directly.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

import splunklib.client as splunk_client
import splunklib.results as splunk_results

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_INDEX = "mabe"
DEFAULT_SOURCETYPE_FILTER = "mabe:*"


# ---------------------------------------------------------------------------
# SessionEnumerator
# ---------------------------------------------------------------------------

class SessionEnumerator:
    """
    Enumerates distinct session IDs from a Splunk index.

    Parameters
    ----------
    service : splunklib.client.Service
        Connected and authenticated Splunk SDK service instance.
    index : str
        Splunk index name to query. Default: "mabe".
    sourcetype_filter : str
        Sourcetype filter to scope queries. Default: "mabe:*".
    """

    def __init__(
        self,
        service: splunk_client.Service,
        index: str = DEFAULT_INDEX,
        sourcetype_filter: str = DEFAULT_SOURCETYPE_FILTER,
    ) -> None:
        self._service = service
        self._index = index
        self._sourcetype_filter = sourcetype_filter

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get_all_session_ids(self) -> list[str]:
        """
        Return all distinct mabe_session_id values in the index.

        Returns
        -------
        list[str]
            Sorted list of session ID strings.
            Empty list if the index contains no MABE sessions.
        """
        spl = self._build_enumeration_spl(earliest=None)
        logger.debug("Session enumeration SPL (all): %s", spl)
        return self._run_enumeration_query(spl)

    def get_recent_session_ids(self, lookback_minutes: int = 5) -> list[str]:
        """
        Return distinct session IDs that have seen activity in the last
        N minutes. Used for near-real-time polling mode.

        Parameters
        ----------
        lookback_minutes : int
            How far back to look for recent events. Default: 5 minutes.

        Returns
        -------
        list[str]
            Sorted list of recently active session ID strings.
        """
        earliest = f"-{lookback_minutes}m"
        spl = self._build_enumeration_spl(earliest=earliest)
        logger.debug(
            "Session enumeration SPL (recent %dm): %s",
            lookback_minutes, spl
        )
        return self._run_enumeration_query(spl)

    def get_session_ids_in_window(
        self,
        earliest: str,
        latest: str = "now",
    ) -> list[str]:
        """
        Return distinct session IDs within an explicit time window.

        Parameters
        ----------
        earliest : str
            Splunk time modifier, e.g. "-24h", "-7d", or an ISO timestamp.
        latest : str
            Splunk time modifier. Default: "now".

        Returns
        -------
        list[str]
            Sorted list of session ID strings in the window.
        """
        spl = self._build_enumeration_spl(
            earliest=earliest, latest=latest
        )
        logger.debug(
            "Session enumeration SPL (window %s→%s): %s",
            earliest, latest, spl
        )
        return self._run_enumeration_query(spl)

    # ------------------------------------------------------------------
    # SPL construction
    # ------------------------------------------------------------------

    def _build_enumeration_spl(
        self,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
    ) -> str:
        """
        Build the session enumeration SPL query.

        The query uses stats to count events per session_id. The count
        itself is discarded — only the session_id column is used. The
        stats approach ensures the result set is O(n_sessions) not
        O(n_events), so it never hits the 1000-event response cap.

        Returns
        -------
        str
            SPL query string ready for splunk_run_query.
        """
        time_clause = ""
        if earliest:
            time_clause = f" earliest={earliest}"
            if latest:
                time_clause += f" latest={latest}"

        spl = (
            f"search index={self._index}"
            f" sourcetype={self._sourcetype_filter}"
            f"{time_clause}"
            f" | stats count by mabe_session_id"
            f" | fields mabe_session_id"
            f" | sort mabe_session_id"
        )
        return spl

    # ------------------------------------------------------------------
    # Query execution
    # ------------------------------------------------------------------

    def _run_enumeration_query(self, spl: str) -> list[str]:
        """
        Execute an enumeration SPL query and extract session ID strings.

        Parameters
        ----------
        spl : str
            SPL query string.

        Returns
        -------
        list[str]
            Session ID strings. Empty list on error or no results.
        """
        try:
            job = self._service.jobs.create(
                spl,
                exec_mode="blocking",   # wait for completion
                output_mode="json",
                count=0,                # 0 = no cap on result rows
            )
        except Exception as exc:
            logger.error("Failed to create Splunk search job: %s", exc)
            return []

        try:
            reader = splunk_results.JSONResultsReader(
                job.results(output_mode="json", count=0)
            )
            session_ids: list[str] = []
            for item in reader:
                if isinstance(item, dict):
                    sid = item.get("mabe_session_id")
                    if sid and isinstance(sid, str) and sid.strip():
                        session_ids.append(sid.strip())
            return sorted(session_ids)
        except Exception as exc:
            logger.error("Failed to read enumeration results: %s", exc)
            return []
        finally:
            try:
                job.cancel()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # SPL accessor (for MCP demo layer)
    # ------------------------------------------------------------------

    def get_enumeration_spl(
        self,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
    ) -> str:
        """
        Return the enumeration SPL string without executing it.

        Used by the MCP demo layer in main.py to issue the same query
        via splunk_run_query rather than the SDK directly.

        Parameters
        ----------
        earliest : str | None
            Optional time bound, e.g. "-24h".
        latest : str | None
            Optional upper time bound. Ignored if earliest is None.

        Returns
        -------
        str
            SPL query string.
        """
        return self._build_enumeration_spl(earliest=earliest, latest=latest)


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def connect_to_splunk(
    host: Optional[str] = None,
    port: Optional[int] = None,
    token: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> splunk_client.Service:
    """
    Create and return an authenticated Splunk SDK service.

    Authentication priority:
      1. Token (preferred — token-based auth as specified in design)
      2. Username + password (fallback for dev environments)

    All parameters fall back to environment variables if not supplied:
      SPLUNK_HOST     (default: "localhost")
      SPLUNK_PORT     (default: 8089)
      SPLUNK_TOKEN    (token auth)
      SPLUNK_USERNAME (basic auth fallback)
      SPLUNK_PASSWORD (basic auth fallback)

    Parameters
    ----------
    host : str | None
    port : int | None
    token : str | None
        Splunk authentication token.
    username : str | None
    password : str | None

    Returns
    -------
    splunklib.client.Service
        Connected and authenticated service.

    Raises
    ------
    ValueError
        If no authentication credentials are available.
    splunklib.binding.AuthenticationError
        If authentication fails.
    """
    resolved_host = host or os.environ.get("SPLUNK_HOST", "localhost")
    resolved_port = port or int(os.environ.get("SPLUNK_PORT", "8089"))
    resolved_token = token or os.environ.get("SPLUNK_TOKEN")
    resolved_username = username or os.environ.get("SPLUNK_USERNAME")
    resolved_password = password or os.environ.get("SPLUNK_PASSWORD")

    if resolved_token:
        service = splunk_client.connect(
            host=resolved_host,
            port=resolved_port,
            splunkToken=resolved_token,
        )
    elif resolved_username and resolved_password:
        service = splunk_client.connect(
            host=resolved_host,
            port=resolved_port,
            username=resolved_username,
            password=resolved_password,
        )
    else:
        raise ValueError(
            "No Splunk credentials available. Set SPLUNK_TOKEN or "
            "SPLUNK_USERNAME + SPLUNK_PASSWORD environment variables."
        )

    logger.info(
        "Connected to Splunk at %s:%s", resolved_host, resolved_port
    )
    return service
