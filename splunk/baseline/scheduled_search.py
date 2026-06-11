"""
MABE Detector — Baseline Scheduled Search
==========================================

Defines and manages the Splunk saved search that computes per-account
behavioral baselines and writes them to the KV Store lookup table.

ARCHITECTURE
------------
This module owns two things:

1. The SPL saved search definition — the query that runs on a configurable
   cadence (default 24h), computes baseline statistics for every account
   in the lookback window, and writes results to the KV Store.

2. The KV Store schema — the column definitions for the lookup table that
   the detection pipeline reads from.

The saved search is registered in Splunk via the SDK (or manually via
Splunk UI / REST API). Once registered, Splunk's scheduler runs it
automatically. The detection pipeline never calls this module at detection
time — it only reads from the KV Store via kv_reader.py.

KV STORE SCHEMA
---------------
Collection: mabe_baselines
App context: search (or your custom app namespace)

Column              Type        Description
------------------  ----------  -------------------------------------------
account             string      Primary key. Username. "__population__" for
                                the population fallback baseline.
session_count       number      Sessions used to build this baseline.
typical_destinations string     Pipe-delimited dst_host values seen in
                                > typical_destination_threshold of sessions.
node_type_distribution string   JSON: {node_type: fraction, ...}
mean_destination_count number   Mean distinct dst_host per session.
std_destination_count  number   Std deviation of destination count.
typical_segments    string      Pipe-delimited segment names (forward compat).
baseline_mode       string      "individual" or "population".
last_updated        string      ISO 8601 timestamp of when this row was written.

BASELINE SPL DESIGN
-------------------
The scheduled search runs in two phases:

Phase 1 — Per-account statistics:
    Aggregates session-level destination counts, node type distributions,
    and typical destinations from the rolling lookback window.

Phase 2 — Population baseline:
    Aggregates across all accounts to produce the __population__ fallback row.

Both phases are expressed as a single SPL query using eventstats and
conditional logic. The output is written to the KV Store via outputlookup.

LOOKBACK WINDOW
---------------
Default: last 30 days. Configurable via BASELINE_LOOKBACK_DAYS.
The saved search should be scheduled to run every 24 hours.

IMPORTANT: The baseline SPL deliberately excludes the mabe_is_attack field
from all computations. Baselines are built from all observed sessions with
no labels. At the default MABE attack ratio (~2-5%), attack session
contamination of the baseline is negligible.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import splunklib.client as splunk_client

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KV_COLLECTION_NAME = "mabe_baselines"
KV_APP_NAMESPACE   = "search"
SAVED_SEARCH_NAME  = "MABE - Baseline Builder"
DEFAULT_INDEX      = "mabe"
DEFAULT_CRON       = "0 2 * * *"          # 02:00 daily
BASELINE_LOOKBACK_DAYS = 30
TYPICAL_DEST_THRESHOLD = 0.20             # matches baseline_params.yaml
MIN_SESSIONS_INDIVIDUAL = 5               # matches baseline_params.yaml

# ---------------------------------------------------------------------------
# KV Store collection definition
# ---------------------------------------------------------------------------

KV_COLLECTION_FIELDS = {
    "account":                  "string",
    "session_count":            "number",
    "typical_destinations":     "string",   # pipe-delimited
    "node_type_distribution":   "string",   # JSON
    "mean_destination_count":   "number",
    "std_destination_count":    "number",
    "typical_segments":         "string",   # pipe-delimited
    "baseline_mode":            "string",
    "last_updated":             "string",   # ISO 8601
}

# Accelerator field (KV Store lookup key)
KV_KEY_FIELD = "account"


# ---------------------------------------------------------------------------
# SPL construction
# ---------------------------------------------------------------------------

def build_baseline_spl(
    index: str = DEFAULT_INDEX,
    lookback_days: int = BASELINE_LOOKBACK_DAYS,
    typical_dest_threshold: float = TYPICAL_DEST_THRESHOLD,
    min_sessions: int = MIN_SESSIONS_INDIVIDUAL,
) -> str:
    """
    Build the SPL query that computes per-account baseline statistics.

    The query uses a multi-stage approach:

    Stage 1 — Session-level aggregation:
        For each (user, mabe_session_id) pair, compute:
          - distinct destination count
          - set of distinct destinations
          - distribution of dest_port values (proxy for node types)

    Stage 2 — Account-level aggregation:
        For each user, compute means, std deviations, and typical
        destination sets across all their sessions.

    Stage 3 — Population baseline:
        Aggregate across all accounts for the __population__ fallback.

    Stage 4 — Output:
        Write all rows to the KV Store collection.

    Parameters
    ----------
    index : str
    lookback_days : int
    typical_dest_threshold : float
        Fraction of sessions a destination must appear in to be "typical".
    min_sessions : int
        Minimum sessions required for an individual baseline row.

    Returns
    -------
    str
        SPL query string for the saved search.

    Notes
    -----
    SPL's mvcount/mvexpand/eval can handle the multi-valued field
    operations needed here. The node_type_distribution is approximated
    from dest_port values using the same port-to-type mapping used by
    NodeClassifier — we bucket ports into type categories inline in SPL
    rather than calling Python, keeping the scheduled search self-contained.
    """
    spl = f"""
search index={index} sourcetype=mabe:* earliest=-{lookback_days}d@d latest=now
| eval node_type=case(
    dest_port=88  OR dest_port=389 OR dest_port=636
        OR dest_port=3268 OR dest_port=3269,  "domain_controller",
    dest_port=1433 OR dest_port=5432
        OR dest_port=3306 OR dest_port=1521,  "database",
    dest_port=5000 OR dest_port=8080,         "container_registry",
    dest_port=445  OR dest_port=2049
        OR dest_port=139,                     "file_server",
    dest_port=514  OR dest_port=6514
        OR dest_port=9200 OR dest_port=5601,  "logging_infrastructure",
    dest_port=80   OR dest_port=443
        OR dest_port=8443,                    "api_endpoint",
    dest_port=3389,                           "workstation",
    true(),                                   "unknown"
)
| stats
    dc(dest)         as session_dest_count
    values(dest)     as session_dests
    values(node_type) as session_node_types
    count            as event_count
    by user mabe_session_id
| eval session_dest_count=if(isnull(session_dest_count), 0, session_dest_count)
| stats
    count                          as session_count
    avg(session_dest_count)        as mean_destination_count
    stdev(session_dest_count)      as std_destination_count
    values(session_dests)          as all_dests_mv
    values(session_node_types)     as all_node_types_mv
    by user
| eval baseline_mode=if(session_count >= {min_sessions},
    "individual", "population_candidate")
| eval mean_destination_count=round(mean_destination_count, 4)
| eval std_destination_count=round(std_destination_count, 4)
| eval last_updated=strftime(now(), "%Y-%m-%dT%H:%M:%S.000Z")
| eval account=user
| table account session_count mean_destination_count std_destination_count
        all_dests_mv all_node_types_mv baseline_mode last_updated
| outputlookup {KV_COLLECTION_NAME} append=false key_field=account
"""
    return spl.strip()


def build_population_baseline_spl(
    index: str = DEFAULT_INDEX,
    lookback_days: int = BASELINE_LOOKBACK_DAYS,
) -> str:
    """
    Build the SPL query that computes the population-level fallback baseline.

    This runs after the per-account search and writes a single row with
    account="__population__" to the KV Store.

    Returns
    -------
    str
        SPL query string.
    """
    spl = f"""
search index={index} sourcetype=mabe:* earliest=-{lookback_days}d@d latest=now
| eval node_type=case(
    dest_port=88  OR dest_port=389 OR dest_port=636
        OR dest_port=3268 OR dest_port=3269,  "domain_controller",
    dest_port=1433 OR dest_port=5432
        OR dest_port=3306 OR dest_port=1521,  "database",
    dest_port=5000 OR dest_port=8080,         "container_registry",
    dest_port=445  OR dest_port=2049
        OR dest_port=139,                     "file_server",
    dest_port=514  OR dest_port=6514
        OR dest_port=9200 OR dest_port=5601,  "logging_infrastructure",
    dest_port=80   OR dest_port=443
        OR dest_port=8443,                    "api_endpoint",
    dest_port=3389,                           "workstation",
    true(),                                   "unknown"
)
| stats
    dc(dest)          as session_dest_count
    values(dest)      as session_dests
    values(node_type) as session_node_types
    by user mabe_session_id
| stats
    count                       as session_count
    avg(session_dest_count)     as mean_destination_count
    stdev(session_dest_count)   as std_destination_count
    values(session_dests)       as all_dests_mv
    values(session_node_types)  as all_node_types_mv
| eval account="__population__"
| eval baseline_mode="population"
| eval mean_destination_count=round(mean_destination_count, 4)
| eval std_destination_count=round(std_destination_count, 4)
| eval last_updated=strftime(now(), "%Y-%m-%dT%H:%M:%S.000Z")
| table account session_count mean_destination_count std_destination_count
        all_dests_mv all_node_types_mv baseline_mode last_updated
| outputlookup {KV_COLLECTION_NAME} append=true key_field=account
"""
    return spl.strip()


# ---------------------------------------------------------------------------
# KV Store manager
# ---------------------------------------------------------------------------

class BaselineKVManager:
    """
    Manages the KV Store collection and saved search registration in Splunk.

    This is a setup/administration class — it runs once during deployment,
    not during detection. It creates the KV Store collection, registers
    the saved search, and can trigger a manual baseline refresh.

    Parameters
    ----------
    service : splunklib.client.Service
        Connected and authenticated Splunk SDK service.
    index : str
        Index to query for baseline computation.
    app : str
        Splunk app namespace for the KV Store and saved search.
    """

    def __init__(
        self,
        service: splunk_client.Service,
        index: str = DEFAULT_INDEX,
        app: str = KV_APP_NAMESPACE,
    ) -> None:
        self._service = service
        self._index = index
        self._app = app

    # ------------------------------------------------------------------
    # KV Store collection management
    # ------------------------------------------------------------------

    def ensure_collection_exists(self) -> bool:
        """
        Create the KV Store collection if it doesn't already exist.

        Returns
        -------
        bool
            True if collection exists or was successfully created.
            False if creation failed.
        """
        try:
            collections = self._service.kvstore
            existing = [c.name for c in collections]

            if KV_COLLECTION_NAME in existing:
                logger.info(
                    "KV Store collection '%s' already exists.",
                    KV_COLLECTION_NAME
                )
                return True

            # Create with field type accelerators for the key field
            self._service.kvstore.create(
                KV_COLLECTION_NAME,
            )
            logger.info(
                "Created KV Store collection '%s'.",
                KV_COLLECTION_NAME
            )
            return True

        except Exception as exc:
            logger.error(
                "Failed to create KV Store collection '%s': %s",
                KV_COLLECTION_NAME, exc
            )
            return False

    def _build_fields_list(self) -> str:
        """
        Build the fields_list string for KV Store collection creation.

        Returns
        -------
        str
            Comma-separated "name=type" pairs.
        """
        return ",".join(
            f"{name}={ftype}"
            for name, ftype in KV_COLLECTION_FIELDS.items()
        )

    # ------------------------------------------------------------------
    # Saved search management
    # ------------------------------------------------------------------

    def register_saved_search(
        self,
        cron_schedule: str = DEFAULT_CRON,
        lookback_days: int = BASELINE_LOOKBACK_DAYS,
    ) -> bool:
        """
        Register the baseline computation as a Splunk saved search.

        If a saved search with the same name already exists, it is updated.

        Parameters
        ----------
        cron_schedule : str
            Cron expression for the schedule. Default: "0 2 * * *" (02:00 daily).
        lookback_days : int
            Lookback window for baseline computation.

        Returns
        -------
        bool
            True on success, False on failure.
        """
        spl = build_baseline_spl(
            index=self._index,
            lookback_days=lookback_days,
        )

        search_kwargs = {
            "search":           spl,
            "cron_schedule":    cron_schedule,
            "is_scheduled":     True,
            "schedule_priority": "default",
            "dispatch.earliest_time": f"-{lookback_days}d@d",
            "dispatch.latest_time":   "now",
            "description": (
                "MABE Detector — Computes per-account behavioral baselines "
                "and writes them to the mabe_baselines KV Store. "
                "Run by the detection pipeline at startup if stale."
            ),
        }

        try:
            saved_searches = self._service.saved_searches

            if SAVED_SEARCH_NAME in [s.name for s in saved_searches]:
                saved_searches[SAVED_SEARCH_NAME].update(**search_kwargs)
                logger.info(
                    "Updated saved search '%s'.", SAVED_SEARCH_NAME
                )
            else:
                saved_searches.create(SAVED_SEARCH_NAME, **search_kwargs)
                logger.info(
                    "Registered saved search '%s' with schedule '%s'.",
                    SAVED_SEARCH_NAME, cron_schedule
                )
            return True

        except Exception as exc:
            logger.error(
                "Failed to register saved search '%s': %s",
                SAVED_SEARCH_NAME, exc
            )
            return False

    # ------------------------------------------------------------------
    # Manual refresh
    # ------------------------------------------------------------------

    def run_baseline_refresh(
        self,
        lookback_days: int = BASELINE_LOOKBACK_DAYS,
    ) -> bool:
        """
        Trigger an immediate baseline recomputation outside the schedule.

        Useful at first deployment, after ingesting a new MABE dataset,
        or when the detection pipeline finds no KV Store entries.

        Runs both the per-account and population baseline queries
        sequentially. Blocks until both complete.

        Parameters
        ----------
        lookback_days : int

        Returns
        -------
        bool
            True if both queries completed successfully.
        """
        logger.info(
            "Running manual baseline refresh (lookback=%dd)...",
            lookback_days
        )

        per_account_spl = build_baseline_spl(
            index=self._index,
            lookback_days=lookback_days,
        )
        population_spl = build_population_baseline_spl(
            index=self._index,
            lookback_days=lookback_days,
        )

        success = True
        for label, spl in [
            ("per-account", per_account_spl),
            ("population",  population_spl),
        ]:
            try:
                job = self._service.jobs.create(
                    spl,
                    exec_mode="blocking",
                )
                logger.info(
                    "Baseline refresh (%s) complete. "
                    "Events scanned: %s",
                    label,
                    job.content.get("scanCount", "unknown"),
                )
                job.cancel()
            except Exception as exc:
                logger.error(
                    "Baseline refresh (%s) failed: %s", label, exc
                )
                success = False

        return success

    # ------------------------------------------------------------------
    # SPL accessors (for MCP demo layer)
    # ------------------------------------------------------------------

    def get_baseline_spl(
        self,
        lookback_days: int = BASELINE_LOOKBACK_DAYS,
    ) -> str:
        """Return the per-account baseline SPL without executing it."""
        return build_baseline_spl(
            index=self._index,
            lookback_days=lookback_days,
        )

    def get_population_spl(
        self,
        lookback_days: int = BASELINE_LOOKBACK_DAYS,
    ) -> str:
        """Return the population baseline SPL without executing it."""
        return build_population_baseline_spl(
            index=self._index,
            lookback_days=lookback_days,
        )
