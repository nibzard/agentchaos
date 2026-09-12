"""Strict contract validation for Gauntlet resources.

Loads the JSON Schema contracts from shared/schemas and validates
resource instances fail-closed: unknown fields, unknown contract
versions, and malformed values are rejected, never ignored.
"""

from acx_schemas.errors import ContractViolation, UnknownResourceKind
from acx_schemas.loader import ContractRegistry, default_registry
from acx_schemas.strictness import StrictnessError, assert_schema_strict

__all__ = [
    "ContractRegistry",
    "ContractViolation",
    "StrictnessError",
    "UnknownResourceKind",
    "assert_schema_strict",
    "default_registry",
    "validate",
]

_DEFAULT_REGISTRY: ContractRegistry | None = None


def validate(instance: dict, kind: str) -> None:
    """Validate one resource instance against its contract.

    Raises ContractViolation with structured errors when the instance
    does not conform. Raises UnknownResourceKind for an unregistered
    kind. Never mutates the instance.
    """
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = default_registry()
    _DEFAULT_REGISTRY.validate(instance, kind)
