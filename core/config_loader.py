"""
MABE Detector — Configuration Loader
======================================

Loads and validates all configuration from config/ YAML files.
No thresholds or weights are hardcoded in mechanism implementations.
All parameters flow through this module.

CONFIG FILES
------------
config/thresholds.yaml      — weights, thresholds, alert parameters
config/baseline_params.yaml — baseline construction parameters
config/node_type_mapping.yaml — port-to-node-type classification table
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

_CONFIG_DIR = Path(__file__).parent.parent / "config"


def _load_yaml(filename: str) -> dict:
    """Load a YAML config file from the config directory."""
    path = _CONFIG_DIR / filename
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            "Ensure config/ directory is present relative to detector/."
        )
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ---------------------------------------------------------------------------
# Config accessors
# ---------------------------------------------------------------------------

def load_thresholds() -> dict:
    """Load threshold and weight configuration."""
    return _load_yaml("thresholds.yaml")


def load_baseline_params() -> dict:
    """Load baseline construction parameters."""
    return _load_yaml("baseline_params.yaml")


def load_node_type_mapping() -> dict[str, list[int]]:
    """
    Load port-to-node-type mapping table.

    Returns
    -------
    dict
        Mapping from node_type string to list of port integers.
        e.g. {"domain_controller": [88, 389, 636], ...}
    """
    raw = _load_yaml("node_type_mapping.yaml")
    # Validate all values are lists of integers
    result: dict[str, list[int]] = {}
    for node_type, ports in raw.items():
        if not isinstance(ports, list):
            raise ValueError(
                f"node_type_mapping.yaml: ports for '{node_type}' "
                f"must be a list; got {type(ports)}"
            )
        result[node_type] = [int(p) for p in ports]
    return result


def load_port_to_node_type() -> dict[int, str]:
    """
    Invert the node type mapping to a port → node_type lookup.

    When a port appears in multiple node type lists (e.g. 445 in both
    file_server and workstation), the first match in yaml order wins.
    Standard practice: list more specific types before more general ones
    in node_type_mapping.yaml.

    Returns
    -------
    dict
        Mapping from port integer to node_type string.
    """
    mapping = load_node_type_mapping()
    port_to_type: dict[int, str] = {}
    for node_type, ports in mapping.items():
        for port in ports:
            if port not in port_to_type:
                port_to_type[port] = node_type
    return port_to_type


# ---------------------------------------------------------------------------
# Typed accessors for commonly used config values
# ---------------------------------------------------------------------------

def get_layer_weights(thresholds: dict | None = None) -> dict[str, float]:
    """
    Return layer weights for confidence computation.

    Returns
    -------
    dict
        {"L1": float, "L2": float, "L3": float}
    """
    cfg = thresholds or load_thresholds()
    lw = cfg.get("layer_weights", {})
    return {
        "L1": float(lw.get("L1", 0.20)),
        "L2": float(lw.get("L2", 0.35)),
        "L3": float(lw.get("L3", 0.45)),
    }


def get_mechanism_weights(thresholds: dict | None = None) -> dict[str, float]:
    """
    Return cross-mechanism weights for the correlation agent.

    Returns
    -------
    dict
        {"velocity": float, "enumeration": float, "priv_escalation": float}
    """
    cfg = thresholds or load_thresholds()
    w = cfg.get("weights", {})
    return {
        "velocity":        float(w.get("velocity", 0.25)),
        "enumeration":     float(w.get("enumeration", 0.35)),
        "priv_escalation": float(w.get("priv_escalation", 0.40)),
    }


def get_alert_threshold(thresholds: dict | None = None) -> float:
    """Return the configured alert threshold."""
    cfg = thresholds or load_thresholds()
    return float(cfg.get("alert_threshold", 0.50))


def get_high_confidence_floor_params(
    thresholds: dict | None = None,
) -> tuple[float, float]:
    """
    Return (trigger_threshold, floor_value) for the high-confidence floor rule.

    If any mechanism confidence exceeds trigger_threshold, overall_confidence
    is set to max(overall_confidence, floor_value).
    """
    cfg = thresholds or load_thresholds()
    hcf = cfg.get("high_confidence_floor", {})
    return (
        float(hcf.get("trigger_threshold", 0.90)),
        float(hcf.get("floor_value", 0.75)),
    )
