"""Fault adapters and the conformance suite (spec 8.2, 9.3, AC-028)."""

from gauntlet_adapters.adapter import (
    AdapterRefusal,
    FaultAdapter,
    ReferenceFileAdapter,
    fresh_workspace,
    receipt_id,
    reference_manifest,
    workspace_tree,
)
from gauntlet_adapters.conformance import failed_checks, run_conformance
from gauntlet_adapters.contract import ContractError, validate_manifest
from gauntlet_adapters.mcp import (
    MCP_EXTRA_CHECKS,
    MCPServer,
    MCPToolAdapter,
    default_tools,
    encode_credential,
    fixture_mcp_adapter,
    issue_credential,
    mcp_manifest,
    parse_credential,
    run_mcp_conformance,
)

__all__ = [
    "AdapterRefusal",
    "ContractError",
    "FaultAdapter",
    "MCP_EXTRA_CHECKS",
    "MCPServer",
    "MCPToolAdapter",
    "ReferenceFileAdapter",
    "default_tools",
    "encode_credential",
    "failed_checks",
    "fixture_mcp_adapter",
    "fresh_workspace",
    "issue_credential",
    "mcp_manifest",
    "parse_credential",
    "receipt_id",
    "reference_manifest",
    "run_conformance",
    "run_mcp_conformance",
    "validate_manifest",
    "workspace_tree",
]
