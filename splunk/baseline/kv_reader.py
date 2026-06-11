"""
MABE Detector — KV Store Baseline Reader
==========================================

Reads per-account behavioral baselines from the Splunk KV Store and
deserializes them into AccountBaseline objects for use by the detection
mechanisms.

ROLE IN THE PIPELINE
--------------------
This is the read side of the baseline infrastructure. The write side
(scheduled_search.py) computes baselines on a schedule and writes rows
to the mabe_baselines KV Store collection.

At detection time, the runner calls get_baseline(account) for each
session being evaluated. If the account has an individual baseline row
it's returned directly. If not, the population fallback row is returned.
If neither exists (KV Store empty / baseline not yet computed), a warning
is logged and None is returned — the calling mechanism handles this
gracefully by skipping Layer 3.

DESERIALIZATION
---------------
KV Store stores all values as strings or numbers. The following
transformations are applied on read:

    typical_destinations    pipe-delimited string → set[str]
    node_type_distribution  JSON string           → dict[str, float]
    typical_segments        pipe-delimited string → set[str]
    session_count           number                → int
    mean_destination_count  number                → float
    std_destination_count   number                → float
    baseline_mode           string                → str (no transform)

SPLUNK MCP NOTE
---------------
The KV Store lookup is performed via a SPL query using inputlookup,
keeping all data access consistent through the Splunk query interface.
The same SPL string is used whether executing via SDK or MCP tool.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

import splunklib.client as splunk_client
import splunklib.results as splunk_results

# AccountBaseline lives in core — import it directly
# In the deployed package this resolves from detector-splunk/core/baseline.py
from core.baseline import AccountBaseline

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — must match scheduled_search.py exactly
# ---------------------------------------------------------------------------

KV_COLLECTION_NAME = "mabe_baselines"
POPULATION_KEY     = "__population__"
PIPE_DELIMITER     = "|"


# ---------------------------------------------------------------------------
# KVBaselineReader
# ---------------------------------------------------------------------------

class KVBaselineReader:
    """
    Reads AccountBaseline objects from the Splunk KV Store.

    Parameters
    ----------
    service : splunklib.client.Service
        Connected and authenticated Splunk SDK service.
    collection : str
        KV Store collection name. Default: "mabe_baselines".
    """

    def __init__(
        self,
        service: splunk_client.Service,
        collection: str = KV_COLLECTION_NAME,
    ) -> None:
        self._service = service
        self._collection = collection
        self._population_cache: Optional[AccountBaseline] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get_baseline(self, account: str) -> Optional[AccountBaseline]:
        """
        Return the AccountBaseline for an account.

        Lookup order:
          1. Individual baseline row for this account.
          2. Population fallback baseline (__population__ row).
          3. None — if KV Store is empty or query fails.

        Parameters
        ----------
        account : str
            Username / account identifier.

        Returns
        -------
        AccountBaseline | None
            Deserialized baseline, or None if unavailable.
        """
        # Try individual first
        individual = self._fetch_row(account)
        if individual is not None:
            return individual

        # Fall back to population baseline
        population = self.get_population_baseline()
        if population is not None:
            logger.debug(
                "Account '%s' has no individual baseline — "
                "using population fallback.",
                account
            )
            # Return a copy stamped with the correct account name
            return AccountBaseline(
                account=account,
                session_count=population.session_count,
                typical_destinations=population.typical_destinations,
                node_type_distribution=population.node_type_distribution,
                mean_destination_count=population.mean_destination_count,
                std_destination_count=population.std_destination_count,
                typical_segments=population.typical_segments,
                baseline_mode="population",
            )

        logger.warning(
            "No baseline available for account '%s' and no population "
            "fallback found. KV Store may be empty — run a baseline "
            "refresh before detection.",
            account
        )
        return None

    def get_population_baseline(self) -> Optional[AccountBaseline]:
        """
        Return the population-level fallback baseline.

        Result is cached in memory for the lifetime of this reader
        instance — the population baseline is the same for all accounts
        and queried frequently during a detection run.

        Returns
        -------
        AccountBaseline | None
        """
        if self._population_cache is not None:
            return self._population_cache

        row = self._fetch_row(POPULATION_KEY)
        if row is not None:
            self._population_cache = row
        return row

    def get_all_baselines(self) -> dict[str, AccountBaseline]:
        """
        Load all baseline rows from the KV Store into a dict.

        Used by dataset_stats.py at startup to pre-load the full baseline
        map rather than hitting the KV Store once per session.

        Returns
        -------
        dict[str, AccountBaseline]
            account → AccountBaseline. Empty dict if the store is empty
            or the query fails.
        """
        spl = self._build_lookup_all_spl()
        logger.debug("Loading all baselines: %s", spl)

        try:
            job = self._service.jobs.create(
                spl,
                exec_mode="blocking",
                count=0,
            )
        except Exception as exc:
            logger.error("Failed to load all baselines: %s", exc)
            return {}

        results: dict[str, AccountBaseline] = {}
        try:
            reader = splunk_results.JSONResultsReader(
                job.results(output_mode="json", count=0)
            )
            for item in reader:
                if isinstance(item, dict):
                    baseline = self._deserialize_row(item)
                    if baseline is not None:
                        results[baseline.account] = baseline

            logger.info(
                "Loaded %d baseline rows from KV Store.", len(results)
            )
            return results

        except Exception as exc:
            logger.error("Failed to read baseline results: %s", exc)
            return {}
        finally:
            try:
                job.cancel()
            except Exception:
                pass

    def is_stale(self, max_age_hours: float = 25.0) -> bool:
        """
        Check whether the KV Store baselines are stale.

        Reads the most recent last_updated timestamp across all rows.
        Returns True if no rows exist or the newest row is older than
        max_age_hours. Used by main.py to decide whether to trigger
        a manual baseline refresh before the detection run.

        Parameters
        ----------
        max_age_hours : float
            Age threshold in hours. Default 25h (just over one daily cycle).

        Returns
        -------
        bool
            True if refresh is needed, False if baselines are fresh.
        """
        spl = (
            "| inputlookup mabe_baselines.csv"
            " | stats max(last_updated) as newest_update"
        )

        try:
            job = self._service.jobs.create(
                spl,
                exec_mode="blocking",
                count=0,
            )
            reader = splunk_results.JSONResultsReader(
                job.results(output_mode="json", count=1)
            )
            for item in reader:
                if isinstance(item, dict):
                    newest = item.get("newest_update", "")
                    if not newest:
                        return True
                    from datetime import datetime, timezone
                    try:
                        updated_at = datetime.strptime(
                            newest, "%Y-%m-%dT%H:%M:%S.%fZ"
                        ).replace(tzinfo=timezone.utc)
                        now = datetime.now(tz=timezone.utc)
                        age_hours = (
                            (now - updated_at).total_seconds() / 3600
                        )
                        stale = age_hours > max_age_hours
                        if stale:
                            logger.warning(
                                "Baselines are %.1fh old (threshold: %.1fh).",
                                age_hours, max_age_hours
                            )
                        return stale
                    except ValueError:
                        return True
            return True   # no rows → stale

        except Exception as exc:
            logger.warning("Could not check baseline staleness: %s", exc)
            return True   # assume stale on error
        finally:
            try:
                job.cancel()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # SPL construction
    # ------------------------------------------------------------------

    def _build_lookup_spl(self, account: str) -> str:
        """SPL to fetch a single account row from the KV Store."""
        safe_account = account.replace('"', '\\"')
        return (f'| inputlookup mabe_baselines.csv'
        f' | where account="{safe_account}"')

    def _build_lookup_all_spl(self) -> str:
        """SPL to fetch all rows from the KV Store."""
        return "| inputlookup mabe_baselines.csv"

    def get_lookup_spl(self, account: str) -> str:
        """
        Return the single-account lookup SPL without executing it.

        Used by the MCP demo layer in main.py.
        """
        return self._build_lookup_spl(account)

    # ------------------------------------------------------------------
    # Row fetch
    # ------------------------------------------------------------------

    def _fetch_row(self, account: str) -> Optional[AccountBaseline]:
        """
        Fetch a single row from the KV Store and deserialize it.

        Parameters
        ----------
        account : str
            Account key to look up.

        Returns
        -------
        AccountBaseline | None
        """
        spl = self._build_lookup_spl(account)

        try:
            job = self._service.jobs.create(
                spl,
                exec_mode="blocking",
                count=0,
            )
        except Exception as exc:
            logger.error(
                "KV lookup failed for account '%s': %s", account, exc
            )
            return None

        try:
            reader = splunk_results.JSONResultsReader(
                job.results(output_mode="json", count=1)
            )
            for item in reader:
                if isinstance(item, dict):
                    return self._deserialize_row(item)
            return None

        except Exception as exc:
            logger.error(
                "Failed to read KV row for account '%s': %s", account, exc
            )
            return None
        finally:
            try:
                job.cancel()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Deserialization
    # ------------------------------------------------------------------

    def _deserialize_row(self, row: dict) -> Optional[AccountBaseline]:
        """
        Deserialize a raw KV Store row dict into an AccountBaseline.

        Parameters
        ----------
        row : dict
            Raw row from Splunk results reader.

        Returns
        -------
        AccountBaseline | None
            None if the row is missing required fields or parsing fails.
        """
        account = row.get("account", "").strip()
        if not account:
            logger.warning("KV row missing 'account' field: %s", row)
            return None

        try:
            session_count = int(float(row.get("session_count", 0)))
            mean_dest     = float(row.get("mean_destination_count", 0.0))
            std_dest      = float(row.get("std_destination_count", 0.0))
            baseline_mode = str(row.get("baseline_mode", "individual"))

            typical_destinations = _deserialize_pipe_set(
                row.get("typical_destinations", "")
            )
            typical_segments = _deserialize_pipe_set(
                row.get("typical_segments", "")
            )
            node_type_distribution = _deserialize_json_dict(
                row.get("node_type_distribution", "{}")
            )

            return AccountBaseline(
                account=account,
                session_count=session_count,
                typical_destinations=typical_destinations,
                node_type_distribution=node_type_distribution,
                mean_destination_count=mean_dest,
                std_destination_count=std_dest,
                typical_segments=typical_segments,
                baseline_mode=baseline_mode,
            )

        except (ValueError, TypeError, KeyError) as exc:
            logger.error(
                "Failed to deserialize KV row for account '%s': %s",
                account, exc
            )
            return None


# ---------------------------------------------------------------------------
# Deserialization helpers
# ---------------------------------------------------------------------------

def _deserialize_pipe_set(raw: object) -> set:
    """
    Deserialize a pipe-delimited string to a set of non-empty strings.

    Parameters
    ----------
    raw : object
        Raw KV Store value — string, list, or None.

    Returns
    -------
    set[str]

    Notes
    -----
    Splunk's outputlookup can store multi-valued fields as either a
    pipe-delimited string or a JSON array depending on the context.
    Both formats are handled here.
    """
    if raw is None:
        return set()

    # Splunk may return a list for multi-valued fields
    if isinstance(raw, list):
        return {str(v).strip() for v in raw if str(v).strip()}

    raw_str = str(raw).strip()
    if not raw_str:
        return set()

    # Try JSON array first (defensive — Splunk sometimes returns this)
    if raw_str.startswith("["):
        try:
            parsed = json.loads(raw_str)
            if isinstance(parsed, list):
                return {str(v).strip() for v in parsed if str(v).strip()}
        except (json.JSONDecodeError, ValueError):
            pass

    # Standard pipe-delimited
    return {v.strip() for v in raw_str.split(PIPE_DELIMITER) if v.strip()}


def _deserialize_json_dict(raw: object) -> dict:
    """
    Deserialize a JSON string to a dict[str, float].

    Parameters
    ----------
    raw : object
        Raw KV Store value.

    Returns
    -------
    dict[str, float]
        Empty dict on parse failure.
    """
    if raw is None:
        return {}

    raw_str = str(raw).strip()
    if not raw_str or raw_str in ("{}", "null", ""):
        return {}

    try:
        parsed = json.loads(raw_str)
        if isinstance(parsed, dict):
            return {str(k): float(v) for k, v in parsed.items()}
        return {}
    except (json.JSONDecodeError, ValueError, TypeError):
        logger.warning(
            "Failed to parse node_type_distribution JSON: %r", raw_str
        )
        return {}


# ---------------------------------------------------------------------------
# Serialization helpers (used by manual baseline writer in tests/dev)
# ---------------------------------------------------------------------------

def serialize_set_to_pipe(values: set) -> str:
    """Serialize a set to a pipe-delimited string for KV Store write."""
    return PIPE_DELIMITER.join(sorted(str(v) for v in values))


def serialize_dict_to_json(d: dict) -> str:
    """Serialize a dict to a JSON string for KV Store write."""
    return json.dumps({str(k): float(v) for k, v in d.items()})
