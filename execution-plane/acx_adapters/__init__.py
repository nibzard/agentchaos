"""Fault adapters and the conformance suite (spec 8.2, 9.3, AC-028)."""

from acx_adapters.adapter import (
    AdapterRefusal,
    FaultAdapter,
    ReferenceFileAdapter,
    fresh_workspace,
    receipt_id,
    reference_manifest,
    workspace_tree,
)
from acx_adapters.conformance import failed_checks, run_conformance
from acx_adapters.contract import ContractError, validate_manifest

__all__ = [
    "AdapterRefusal",
    "ContractError",
    "FaultAdapter",
    "ReferenceFileAdapter",
    "failed_checks",
    "fresh_workspace",
    "receipt_id",
    "reference_manifest",
    "run_conformance",
    "validate_manifest",
    "workspace_tree",
]
