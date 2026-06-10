"""
MABE Detector — Node Type Classifier
======================================

Infers node type categories from observable event characteristics,
primarily destination port numbers. This is the topology-agnostic
alternative to graph-based node classification.

DESIGN
------
Node types are inferred from the port-to-node-type mapping table in
config/node_type_mapping.yaml. The table ships with standard port
defaults and is the intended customization point for non-standard
environments.

KNOWN LIMITATION
----------------
Non-standard port assignments produce misclassification. Operators
should update node_type_mapping.yaml for their environment.
When a port is not in the mapping, the node type is "unknown".

HIGH-VALUE NODE TYPES
---------------------
Nodes requiring elevated privilege that are anomalous targets for
standard user accounts:
    domain_controller, database, container_registry, logging_infrastructure

This set is configurable but defaults are grounded in MABE topology
and GTG-1002's documented high-value target categories.
"""

from __future__ import annotations

from functools import lru_cache

from core.config_loader import load_port_to_node_type

# ---------------------------------------------------------------------------
# High-value node types (configurable at module level for now)
# ---------------------------------------------------------------------------

HIGH_VALUE_NODE_TYPES = frozenset({
    "domain_controller",
    "database",
    "container_registry",
    "logging_infrastructure",
})

# Node types that indicate infrastructure/sensitive segments
INFRASTRUCTURE_NODE_TYPES = frozenset({
    "domain_controller",
    "container_registry",
    "logging_infrastructure",
})

# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class NodeClassifier:
    """
    Classifies destination hosts by node type based on observable
    event characteristics.

    Parameters
    ----------
    port_map : dict[int, str] | None
        Override the default port-to-node-type mapping. If None,
        loads from config/node_type_mapping.yaml.
    """

    def __init__(self, port_map: dict[int, str] | None = None) -> None:
        self._port_map: dict[int, str] = (
            port_map if port_map is not None
            else load_port_to_node_type()
        )

    def classify_port(self, port: int) -> str:
        """
        Infer node type from destination port.

        Parameters
        ----------
        port : int
            Destination port number.

        Returns
        -------
        str
            Node type string, e.g. "domain_controller", "database".
            Returns "unknown" if port is not in the mapping.
        """
        return self._port_map.get(port, "unknown")

    def classify_event(self, event: dict) -> str:
        """
        Infer node type from an event record.

        Uses dst_port as the primary signal, with protocol as a
        secondary hint when available.

        Parameters
        ----------
        event : dict
            Event record with at minimum a "dst_port" field.

        Returns
        -------
        str
            Inferred node type string.
        """
        dst_port = event.get("dst_port") or event.get("dest_port")
        if dst_port is not None:
            node_type = self.classify_port(int(dst_port))
            if node_type != "unknown":
                return node_type

        # Secondary: protocol hint
        protocol = (event.get("protocol") or "").lower()
        protocol_hints = {
            "kerberos": "domain_controller",
            "ldap":     "domain_controller",
            "mssql":    "database",
            "postgresql": "database",
            "smb":      "file_server",
            "nfs":      "file_server",
            "rdp":      "workstation",
        }
        return protocol_hints.get(protocol, "unknown")

    def is_high_value(self, node_type: str) -> bool:
        """Return True if node_type is in the high-value set."""
        return node_type in HIGH_VALUE_NODE_TYPES

    def is_infrastructure(self, node_type: str) -> bool:
        """Return True if node_type is an infrastructure segment type."""
        return node_type in INFRASTRUCTURE_NODE_TYPES

    def classify_events(self, events: list[dict]) -> list[str]:
        """
        Classify a list of events, returning a node type per event.

        Parameters
        ----------
        events : list[dict]

        Returns
        -------
        list[str]
            Node type for each event, in the same order.
        """
        return [self.classify_event(e) for e in events]

    def get_node_type_distribution(
        self,
        events: list[dict],
    ) -> dict[str, float]:
        """
        Compute the fraction of events directed at each node type.

        Parameters
        ----------
        events : list[dict]
            Events to analyze.

        Returns
        -------
        dict[str, float]
            node_type → fraction of total events (sums to 1.0).
            "unknown" is included if present.
        """
        if not events:
            return {}

        counts: dict[str, int] = {}
        for event in events:
            node_type = self.classify_event(event)
            counts[node_type] = counts.get(node_type, 0) + 1

        total = len(events)
        return {nt: count / total for nt, count in counts.items()}
