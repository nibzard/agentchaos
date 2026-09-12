"""Deterministic risk classification (spec 9.1, G6).

The classification is a pure function of the resolved manifest. The
same inputs always produce the same class, so an operator can predict
the result before submitting the manifest.
"""

from __future__ import annotations

from dataclasses import dataclass

RISK_ORDER = {"low": 0, "moderate": 1, "high": 2}

# Modes that require the hardened backend (spec 8.2).
HARDENED_ONLY_MODES = frozenset({"production_synthetic", "customer_canary"})

# Modes that must write only to synthetic sinks in beta (spec 13.1).
SYNTHETIC_SINK_MODES = frozenset({"observe", "replay", "isolated_reexecution"})

# Event kinds every manifest must require (spec 9.4, AC-004).
MANDATORY_EVENT_KINDS = frozenset({"injection_receipt"})


@dataclass(frozen=True)
class RiskPolicy:
    """What the deployment accepts. Unacceptable classes are rejected
    before execution (spec G6)."""

    max_risk: str = "moderate"
    hardened_only_modes: frozenset = HARDENED_ONLY_MODES
    synthetic_sink_modes: frozenset = SYNTHETIC_SINK_MODES
    mandatory_event_kinds: frozenset = MANDATORY_EVENT_KINDS


def _bump(current: str, amount: int) -> str:
    rank = min(RISK_ORDER[current] + amount, 2)
    for name, value in RISK_ORDER.items():
        if value == rank:
            return name
    return current  # Unreachable; keeps the function total.


def classify_risk(
    mode: str,
    profile_action_classes: list[list[str]],
    identity_kind: str,
    sink_kinds: list[str],
) -> str:
    """Return low, moderate, or high for a resolved manifest.

    - customer_canary starts high: real customers opt in and residual
      risk is documented per experiment (spec 13.4).
    - production_synthetic starts moderate: production-path services
      are involved (spec 13.4).
    - Any arm allowing A2, real identities, or enrolled services
      raises the class one step.
    """
    level = "low"
    if mode == "customer_canary":
        level = "high"
    elif mode == "production_synthetic":
        level = "moderate"

    bumps = 0
    if any("A2" in classes for classes in profile_action_classes):
        bumps += 1
    if identity_kind == "enrolled_opt_in":
        bumps += 1
    if any(kind == "enrolled_service" for kind in sink_kinds):
        bumps += 1
    return _bump(level, bumps)
