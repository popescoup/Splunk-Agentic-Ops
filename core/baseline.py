"""
MABE Detector — Behavioral Baseline Construction
==================================================

Builds per-account behavioral baselines from observed session history
without relying on ground truth labels. Used by Mechanism 2 (Layer 3)
and Mechanism 3 (Layer 3).

DESIGN PRINCIPLES
-----------------
1. Fully unsupervised — no labels required. Built from the statistical
   center of the observed distribution on the assumption that benign
   sessions dominate (attack sessions typically < 5% of dataset).

2. Two-mode fallback:
   - Individual baseline: used when account has >= minimum_sessions history
   - Population baseline: fallback when history is sparse

3. Preprocessing step — baseline construction runs once over the full
   dataset before the detection loop begins, not per-session.

4. Lookback window — configurable. None = use all available sessions.
   Integer = use last N sessions. In real deployment, a time-based
   rolling window (e.g. 30 days) would replace this.

BASELINE CONTAMINATION NOTE
----------------------------
If attack sessions are incorporated into the baseline (they will be,
since we have no labels), the baseline is slightly contaminated.
At the default MABE ratio (~2-5% attack sessions), contamination is
negligible. At higher attack ratios, baseline accuracy degrades.
This is documented as a known limitation.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from core.config_loader import load_baseline_params
from core.node_classifier import NodeClassifier


# ---------------------------------------------------------------------------
# AccountBaseline dataclass
# ---------------------------------------------------------------------------

@dataclass
class AccountBaseline:
    """
    Behavioral baseline for a single account.

    Built from the account's observed session history without labels.

    Fields
    ------
    account : str
        Username this baseline belongs to.
    session_count : int
        Number of sessions used to build this baseline.
    typical_destinations : set[str]
        dst_host values seen in > typical_destination_threshold fraction
        of this account's sessions.
    node_type_distribution : dict[str, float]
        node_type → mean fraction of events directed at that type,
        computed across all baseline sessions.
    mean_destination_count : float
        Mean number of distinct dst_host values per session.
    std_destination_count : float
        Standard deviation of destination count per session.
    typical_segments : set[str]
        Segment identifiers (inferred from node types) seen in >
        typical_destination_threshold fraction of sessions.
    baseline_mode : str
        "individual" or "population" — which mode was used.
    """
    account:                  str
    session_count:            int
    typical_destinations:     set = field(default_factory=set)
    node_type_distribution:   dict = field(default_factory=dict)
    mean_destination_count:   float = 0.0
    std_destination_count:    float = 0.0
    typical_segments:         set = field(default_factory=set)
    baseline_mode:            str = "individual"


# ---------------------------------------------------------------------------
# BaselineBuilder
# ---------------------------------------------------------------------------

class BaselineBuilder:
    """
    Builds per-account behavioral baselines from a session corpus.

    Parameters
    ----------
    params : dict | None
        Baseline parameters from baseline_params.yaml. If None, loads
        from config file.
    classifier : NodeClassifier | None
        Node type classifier. If None, instantiates default.
    """

    def __init__(
        self,
        params: dict | None = None,
        classifier: NodeClassifier | None = None,
    ) -> None:
        cfg = params or load_baseline_params()
        self._min_sessions: int = int(cfg.get("minimum_sessions", 5))
        self._typical_threshold: float = float(
            cfg.get("typical_destination_threshold", 0.20)
        )
        self._lookback: Optional[int] = cfg.get("lookback_window")
        self._population_fallback: bool = bool(
            cfg.get("population_fallback_enabled", True)
        )
        self._classifier = classifier or NodeClassifier()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def build(
        self,
        sessions: list[dict],
        exclude_session_id: str | None = None,
    ) -> dict[str, AccountBaseline]:
        """
        Build baselines for all accounts in the session corpus.

        Parameters
        ----------
        sessions : list[dict]
            List of session records. Each session must have:
                - "session_id": str
                - "user": str (account identifier)
                - "events": list[dict] (event records for the session)
            This structure matches what the ingestion adapters produce.
        exclude_session_id : str | None
            If provided, this session is excluded from baseline
            construction. Used in MABE evaluation to prevent the
            session under test from contaminating its own baseline.

        Returns
        -------
        dict[str, AccountBaseline]
            account → AccountBaseline
        """
        # Filter to lookback window if configured
        corpus = self._apply_lookback(sessions)

        # Exclude the session under test
        if exclude_session_id:
            corpus = [
                s for s in corpus
                if s.get("session_id") != exclude_session_id
            ]

        # Group by account
        by_account: dict[str, list[dict]] = defaultdict(list)
        for session in corpus:
            user = session.get("user", "")
            if user:
                by_account[user].append(session)

        # Build individual baselines for accounts with sufficient history
        baselines: dict[str, AccountBaseline] = {}
        for account, account_sessions in by_account.items():
            if len(account_sessions) >= self._min_sessions:
                baselines[account] = self._build_individual(
                    account, account_sessions
                )

        # Build population baseline for fallback
        population_baseline = self._build_population(corpus) \
            if self._population_fallback else None

        # For accounts with insufficient history, use population baseline
        all_accounts = set(by_account.keys())
        sparse_accounts = all_accounts - set(baselines.keys())
        if population_baseline is not None:
            for account in sparse_accounts:
                pop = AccountBaseline(
                    account=account,
                    session_count=population_baseline.session_count,
                    typical_destinations=population_baseline.typical_destinations,
                    node_type_distribution=population_baseline.node_type_distribution,
                    mean_destination_count=population_baseline.mean_destination_count,
                    std_destination_count=population_baseline.std_destination_count,
                    typical_segments=population_baseline.typical_segments,
                    baseline_mode="population",
                )
                baselines[account] = pop

        return baselines

    # ------------------------------------------------------------------
    # Individual baseline construction
    # ------------------------------------------------------------------

    def _build_individual(
        self,
        account: str,
        sessions: list[dict],
    ) -> AccountBaseline:
        """Build a baseline from one account's session history."""
        # Per-session destination sets and node type distributions
        session_destinations: list[set] = []
        all_node_type_fractions: list[dict] = []

        for session in sessions:
            events = session.get("events", [])
            if not events:
                continue

            # Distinct destinations in this session
            dests = {
                e.get("dst_host") or e.get("dest")
                for e in events
                if e.get("dst_host") or e.get("dest")
            }
            session_destinations.append(dests)

            # Node type distribution for this session
            nt_dist = self._classifier.get_node_type_distribution(events)
            all_node_type_fractions.append(nt_dist)

        if not session_destinations:
            return self._empty_baseline(account)

        # Typical destinations: appear in > threshold fraction of sessions
        n_sessions = len(session_destinations)
        dest_counts: dict[str, int] = defaultdict(int)
        for dests in session_destinations:
            for d in dests:
                dest_counts[d] += 1

        typical_destinations = {
            d for d, count in dest_counts.items()
            if count / n_sessions > self._typical_threshold
        }

        # Mean node type distribution across sessions
        mean_nt_dist = self._mean_node_type_distribution(
            all_node_type_fractions
        )

        # Typical segments (approximated from high-value node type presence)
        typical_segments = self._infer_typical_segments(
            all_node_type_fractions, n_sessions
        )

        # Destination count statistics
        dest_counts_per_session = [len(d) for d in session_destinations]
        mean_dest = _mean(dest_counts_per_session)
        std_dest = _std(dest_counts_per_session, mean_dest)

        return AccountBaseline(
            account=account,
            session_count=n_sessions,
            typical_destinations=typical_destinations,
            node_type_distribution=mean_nt_dist,
            mean_destination_count=mean_dest,
            std_destination_count=std_dest,
            typical_segments=typical_segments,
            baseline_mode="individual",
        )

    # ------------------------------------------------------------------
    # Population baseline construction
    # ------------------------------------------------------------------

    def _build_population(self, sessions: list[dict]) -> AccountBaseline:
        """
        Build a population-level baseline from all sessions.

        Used as fallback for accounts with insufficient individual history.
        Represents the typical behavior of all accounts in the corpus.
        """
        all_dests: list[set] = []
        all_node_type_fractions: list[dict] = []

        for session in sessions:
            events = session.get("events", [])
            if not events:
                continue
            dests = {
                e.get("dst_host") or e.get("dest")
                for e in events
                if e.get("dst_host") or e.get("dest")
            }
            all_dests.append(dests)
            nt_dist = self._classifier.get_node_type_distribution(events)
            all_node_type_fractions.append(nt_dist)

        if not all_dests:
            return self._empty_baseline("__population__")

        n_sessions = len(all_dests)
        dest_counts: dict[str, int] = defaultdict(int)
        for dests in all_dests:
            for d in dests:
                dest_counts[d] += 1

        typical_destinations = {
            d for d, count in dest_counts.items()
            if count / n_sessions > self._typical_threshold
        }

        mean_nt_dist = self._mean_node_type_distribution(
            all_node_type_fractions
        )
        typical_segments = self._infer_typical_segments(
            all_node_type_fractions, n_sessions
        )
        dest_counts_per_session = [len(d) for d in all_dests]
        mean_dest = _mean(dest_counts_per_session)
        std_dest = _std(dest_counts_per_session, mean_dest)

        return AccountBaseline(
            account="__population__",
            session_count=n_sessions,
            typical_destinations=typical_destinations,
            node_type_distribution=mean_nt_dist,
            mean_destination_count=mean_dest,
            std_destination_count=std_dest,
            typical_segments=typical_segments,
            baseline_mode="population",
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _apply_lookback(self, sessions: list[dict]) -> list[dict]:
        """Apply lookback window if configured."""
        if self._lookback is None:
            return sessions
        # Integer lookback: use last N sessions by list order
        # In real deployment: filter by timestamp
        return sessions[-self._lookback:]

    def _mean_node_type_distribution(
        self,
        fractions_list: list[dict],
    ) -> dict[str, float]:
        """Compute mean node type distribution across sessions."""
        if not fractions_list:
            return {}
        all_types: set[str] = set()
        for d in fractions_list:
            all_types.update(d.keys())

        mean_dist: dict[str, float] = {}
        n = len(fractions_list)
        for nt in all_types:
            mean_dist[nt] = sum(d.get(nt, 0.0) for d in fractions_list) / n
        return mean_dist

    def _infer_typical_segments(
        self,
        fractions_list: list[dict],
        n_sessions: int,
    ) -> set[str]:
        """
        Infer which segment types are typical for this account.

        Uses node type as a proxy for segment — infrastructure node types
        map to the infrastructure segment, etc.
        """
        segment_counts: dict[str, int] = defaultdict(int)
        for fractions in fractions_list:
            for nt in fractions:
                segment = _node_type_to_segment(nt)
                if segment and fractions[nt] > 0:
                    segment_counts[segment] += 1

        return {
            seg for seg, count in segment_counts.items()
            if count / n_sessions > self._typical_threshold
        }

    def _empty_baseline(self, account: str) -> AccountBaseline:
        """Return an empty baseline for accounts with no usable sessions."""
        return AccountBaseline(
            account=account,
            session_count=0,
            typical_destinations=set(),
            node_type_distribution={},
            mean_destination_count=0.0,
            std_destination_count=0.0,
            typical_segments=set(),
            baseline_mode="individual",
        )


# ---------------------------------------------------------------------------
# Deviation computation
# ---------------------------------------------------------------------------

def compute_baseline_deviation(
    session_events: list[dict],
    baseline: AccountBaseline,
    classifier: NodeClassifier | None = None,
) -> dict[str, float]:
    """
    Compute deviation metrics between a session and its baseline.

    Returns
    -------
    dict with keys:
        new_host_ratio : float
            Fraction of dst_host values never seen in baseline sessions.
            0.0 = all familiar; 1.0 = all new.
        node_type_distribution_shift : float
            L1 distance between session node type distribution and
            baseline distribution. 0.0 = identical; 2.0 = completely
            different (theoretical max).
        session_breadth_zscore : float
            How many standard deviations above the baseline mean the
            session's destination count falls. Negative = below average.
    """
    clf = classifier or NodeClassifier()

    # Distinct destinations in the session
    session_dests = {
        e.get("dst_host") or e.get("dest")
        for e in session_events
        if e.get("dst_host") or e.get("dest")
    }
    session_dest_count = len(session_dests)

    # New host ratio
    if not session_dests:
        new_host_ratio = 0.0
    elif not baseline.typical_destinations:
        # No baseline history — treat all as new
        new_host_ratio = 1.0
    else:
        new_hosts = session_dests - baseline.typical_destinations
        new_host_ratio = len(new_hosts) / len(session_dests)

    # Node type distribution shift (L1 distance)
    session_nt_dist = clf.get_node_type_distribution(session_events)
    baseline_nt_dist = baseline.node_type_distribution

    all_types = set(session_nt_dist.keys()) | set(baseline_nt_dist.keys())
    nt_shift = sum(
        abs(session_nt_dist.get(nt, 0.0) - baseline_nt_dist.get(nt, 0.0))
        for nt in all_types
    )

    # Session breadth z-score
    if baseline.std_destination_count > 0:
        breadth_zscore = (
            (session_dest_count - baseline.mean_destination_count)
            / baseline.std_destination_count
        )
    elif session_dest_count > baseline.mean_destination_count:
        breadth_zscore = float("inf")
    else:
        breadth_zscore = 0.0

    return {
        "new_host_ratio":                new_host_ratio,
        "node_type_distribution_shift":  nt_shift,
        "session_breadth_zscore":        breadth_zscore,
    }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _std(values: list[float], mean: float) -> float:
    if len(values) < 2:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def _node_type_to_segment(node_type: str) -> str | None:
    """Approximate segment from node type."""
    mapping = {
        "domain_controller":      "infrastructure",
        "container_registry":     "infrastructure",
        "logging_infrastructure": "infrastructure",
        "database":               "data_tier",
        "api_endpoint":           "corporate",
        "file_server":            "corporate",
        "workstation":            "corporate",
    }
    return mapping.get(node_type)
