"""The MCP adapter (T048, spec 18.3, S18, AC-032).

Two halves, like the conformance suite: the adapter passes everything,
and a broken adapter that violates one MCP rule fails exactly the
check that rule belongs to. An auth check that cannot reject is
decoration.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gauntlet_adapters import (
    AdapterRefusal,
    MCPServer,
    MCPToolAdapter,
    default_tools,
    encode_credential,
    failed_checks,
    fixture_mcp_adapter,
    issue_credential,
    run_conformance,
    run_mcp_conformance,
)
from gauntlet_adapters.adapter import fresh_workspace
from gauntlet_adapters.conformance import SCENARIO_ID


def workspace_under(tmp_path: Path) -> Path:
    return fresh_workspace(tmp_path, baseline={"task.md": "work\n"})


def worker_token(adapter: MCPToolAdapter) -> str:
    return issue_credential(adapter.server.server_id, "worker:test")


# --- the adapter passes the whole suite --------------------------------


def test_the_mcp_adapter_passes_the_canonical_conformance():
    report = run_conformance(fixture_mcp_adapter())
    assert report["passed"] is True
    assert report["adapter_id"] == "adp_mcpserver01"
    assert len(report["checks"]) == 9
    assert failed_checks(report) == []


def test_the_mcp_report_adds_the_auth_checks():
    report = run_mcp_conformance(fixture_mcp_adapter())
    ids = [record["id"] for record in report["checks"]]
    assert ids == [
        "manifest-shape",
        "advertised-capabilities",
        "unsupported-paths",
        "interception-location",
        "side-effect-semantics",
        "logging",
        "teardown",
        "cleanup-guarantee",
        "isolation-coverage",
        "mcp-audience-binding",
        "mcp-no-passthrough",
        "mcp-record-redaction",
        "mcp-fault-in-flight",
    ]
    assert report["passed"] is True
    assert failed_checks(report) == []


# --- audience-bound authorization --------------------------------------


def test_a_bound_credential_dispatches(tmp_path):
    adapter = fixture_mcp_adapter()
    result = adapter.call_tool(
        workspace_under(tmp_path), "fetch_document",
        {"path": "task.md"}, worker_token(adapter),
    )
    assert result == {"payload": "contents of task.md"}
    assert len(adapter.server.calls) == 1


def test_a_wrong_audience_credential_refuses_before_dispatch(tmp_path):
    adapter = fixture_mcp_adapter()
    wrong = issue_credential("srv_somebodyelse00", "worker:test")
    with pytest.raises(AdapterRefusal, match="does not bind"):
        adapter.call_tool(
            workspace_under(tmp_path), "fetch_document", {}, wrong,
        )
    assert adapter.server.calls == []


def test_a_missing_credential_refuses(tmp_path):
    adapter = fixture_mcp_adapter()
    with pytest.raises(AdapterRefusal, match="worker credential"):
        adapter.call_tool(
            workspace_under(tmp_path), "fetch_document", {}, None,
        )
    assert adapter.server.calls == []


def test_a_malformed_credential_refuses(tmp_path):
    adapter = fixture_mcp_adapter()
    with pytest.raises(AdapterRefusal, match="unusable"):
        adapter.call_tool(
            workspace_under(tmp_path), "fetch_document",
            {}, "not-a-credential",
        )
    assert adapter.server.calls == []


def test_an_audience_less_credential_refuses(tmp_path):
    adapter = fixture_mcp_adapter()
    token = encode_credential({"sub": "worker:test"})
    with pytest.raises(AdapterRefusal):
        adapter.call_tool(
            workspace_under(tmp_path), "fetch_document", {}, token,
        )
    assert adapter.server.calls == []


def test_the_server_enforces_its_own_audience():
    """The downstream server refuses credentials for another audience."""
    server = MCPServer("srv_mcpfixture001", default_tools())
    intruder = issue_credential("srv_somebodyelse00", "intruder")
    with pytest.raises(ValueError, match="not bound to this server"):
        server.dispatch("status_lookup", {}, intruder)
    assert server.calls == []


# --- no downstream token passthrough -----------------------------------


def test_the_worker_token_never_reaches_the_server(tmp_path):
    adapter = fixture_mcp_adapter()
    token = worker_token(adapter)
    adapter.call_tool(
        workspace_under(tmp_path), "fetch_document", {}, token,
    )
    server = adapter.server
    assert server.last_presented != token
    assert token not in json.dumps(server.calls)
    assert token not in json.dumps(adapter.dispatch_log)
    record = server.calls[0]
    assert record["authenticated_subject"] == "adapter:adp_mcpserver01"
    assert record["authenticated_subject"] != "worker:test"


def test_the_dispatch_log_states_the_boundary(tmp_path):
    adapter = fixture_mcp_adapter()
    adapter.call_tool(
        workspace_under(tmp_path), "status_lookup", {}, worker_token(adapter),
    )
    entry = adapter.dispatch_log[0]
    assert entry["forwarded_worker_credential"] is False
    assert entry["audience_check"] == "passed"
    assert entry["worker_credential_fingerprint"].startswith("hk_")


def test_records_carry_no_raw_credential_material(tmp_path):
    adapter = fixture_mcp_adapter()
    token = worker_token(adapter)
    adapter.call_tool(
        workspace_under(tmp_path), "status_lookup", {}, token,
    )
    everything = (
        json.dumps(adapter.server.calls)
        + json.dumps(adapter.dispatch_log)
    )
    assert token not in everything
    assert adapter.server.last_presented not in everything


# --- the tool_result fault ----------------------------------------------


def test_the_fault_changes_the_result_in_flight(tmp_path):
    adapter = fixture_mcp_adapter()
    workspace = workspace_under(tmp_path)
    token = worker_token(adapter)
    clean = adapter.call_tool(workspace, "fetch_document", {}, token)
    receipt = adapter.apply(
        adapter.probe_fault("tool_result", SCENARIO_ID), workspace,
    )
    faulted = adapter.call_tool(workspace, "fetch_document", {}, token)
    assert faulted != clean
    assert faulted["payload"].startswith("corrupted:")
    assert receipt["tool"] == "fetch_document"
    assert receipt["mutation"] == "corrupt_payload"
    assert receipt["emitted_by"] == "adapter_outside_worker"


def test_the_fault_leaves_other_tools_untouched(tmp_path):
    adapter = fixture_mcp_adapter()
    workspace = workspace_under(tmp_path)
    token = worker_token(adapter)
    before = adapter.call_tool(workspace, "status_lookup", {}, token)
    adapter.apply(
        adapter.probe_fault("tool_result", SCENARIO_ID), workspace,
    )
    after = adapter.call_tool(workspace, "status_lookup", {}, token)
    assert after == before


def test_teardown_restores_the_clean_result(tmp_path):
    adapter = fixture_mcp_adapter()
    workspace = workspace_under(tmp_path)
    token = worker_token(adapter)
    clean = adapter.call_tool(workspace, "fetch_document", {}, token)
    adapter.apply(
        adapter.probe_fault("tool_result", SCENARIO_ID), workspace,
    )
    adapter.teardown(workspace)
    assert adapter.call_tool(workspace, "fetch_document", {}, token) == clean
    assert not (workspace / ".gauntlet" / "mcp-fault.json").exists()


def test_a_swap_error_fault_replaces_the_result(tmp_path):
    adapter = fixture_mcp_adapter()
    workspace = workspace_under(tmp_path)
    fault = {
        "kind": "tool_result",
        "scenario_version_id": SCENARIO_ID,
        "parameters": {"tool": "status_lookup", "mutation": "swap_error"},
    }
    adapter.apply(fault, workspace)
    result = adapter.call_tool(
        workspace, "status_lookup", {}, worker_token(adapter),
    )
    assert result == {
        "error": {"code": "mcp_tool_failed",
                  "message": "the tool call failed"}
    }


# --- fail-closed behavior ----------------------------------------------


def test_a_fault_outside_tool_result_refuses(tmp_path):
    adapter = fixture_mcp_adapter()
    fault = {
        "kind": "file",
        "scenario_version_id": SCENARIO_ID,
        "parameters": {"files": {"x": "y"}},
    }
    with pytest.raises(AdapterRefusal, match="outside the advertised"):
        adapter.apply(fault, workspace_under(tmp_path))


def test_a_fault_for_an_unknown_tool_refuses(tmp_path):
    adapter = fixture_mcp_adapter()
    fault = {
        "kind": "tool_result",
        "scenario_version_id": SCENARIO_ID,
        "parameters": {"tool": "not_exposed", "mutation": "swap_error"},
    }
    with pytest.raises(AdapterRefusal, match="does not expose"):
        adapter.apply(fault, workspace_under(tmp_path))


def test_an_unknown_mutation_refuses(tmp_path):
    adapter = fixture_mcp_adapter()
    fault = {
        "kind": "tool_result",
        "scenario_version_id": SCENARIO_ID,
        "parameters": {"tool": "status_lookup", "mutation": "drop_all"},
    }
    with pytest.raises(AdapterRefusal, match="mutation"):
        adapter.apply(fault, workspace_under(tmp_path))


def test_a_call_for_an_unknown_tool_refuses_before_dispatch(tmp_path):
    adapter = fixture_mcp_adapter()
    with pytest.raises(AdapterRefusal, match="does not expose"):
        adapter.call_tool(
            workspace_under(tmp_path), "not_exposed", {},
            worker_token(adapter),
        )
    assert adapter.server.calls == []


def test_the_same_fault_yields_the_same_receipt_id(tmp_path):
    receipts = []
    for directory in ("one", "two"):
        adapter = fixture_mcp_adapter()
        workspace = workspace_under(tmp_path / directory)
        receipts.append(
            adapter.apply(
                adapter.probe_fault("tool_result", SCENARIO_ID), workspace,
            )
        )
    assert receipts[0]["receipt_event_id"] == receipts[1]["receipt_event_id"]


def test_the_server_requires_well_formed_ids_and_tools():
    with pytest.raises(ValueError):
        MCPServer("not-a-valid-id", default_tools())
    with pytest.raises(ValueError):
        MCPServer("srv_mcpfixture001", {})


# --- one broken rule per adapter ---------------------------------------


class AudienceBlind(MCPToolAdapter):
    """Launders any worker token into a bound one and dispatches it,
    instead of checking the presented credential's audience."""

    def call_tool(self, workspace, tool, arguments, worker_credential):
        if worker_credential is None:
            return super().call_tool(workspace, tool, arguments, None)
        return super().call_tool(
            workspace, tool, arguments,
            issue_credential(self.server.server_id, "worker:test"),
        )


class Passthrough(MCPToolAdapter):
    """Forwards the worker token to the server instead of consuming
    it at the boundary."""

    def call_tool(self, workspace, tool, arguments, worker_credential):
        if isinstance(worker_credential, str):
            try:
                return self.server.dispatch(
                    tool, dict(arguments or {}), worker_credential,
                )
            except (ValueError, KeyError):
                pass
        return super().call_tool(
            workspace, tool, arguments, worker_credential,
        )


class LeakyLogger(MCPToolAdapter):
    """Writes the raw worker token into the dispatch record."""

    def call_tool(self, workspace, tool, arguments, worker_credential):
        result = super().call_tool(
            workspace, tool, arguments, worker_credential,
        )
        self.dispatch_log[-1]["raw_worker_token"] = worker_credential
        return result


class Ineffective(MCPToolAdapter):
    """Arms the fault but never applies it."""

    def _armed_fault(self, workspace):
        return None


def test_an_audience_blind_adapter_fails_the_auth_check():
    report = run_mcp_conformance(AudienceBlind(
        MCPServer("srv_mcpfixture001", default_tools())
    ))
    assert "mcp-audience-binding" in failed_checks(report)
    assert "mcp-no-passthrough" not in failed_checks(report)


def test_a_passthrough_adapter_fails_the_boundary_check():
    report = run_mcp_conformance(Passthrough(
        MCPServer("srv_mcpfixture001", default_tools())
    ))
    assert "mcp-no-passthrough" in failed_checks(report)
    assert "mcp-audience-binding" not in failed_checks(report)


def test_a_leaky_logger_fails_the_redaction_check():
    report = run_mcp_conformance(LeakyLogger(
        MCPServer("srv_mcpfixture001", default_tools())
    ))
    assert "mcp-record-redaction" in failed_checks(report)


def test_an_ineffective_fault_fails_the_visibility_check():
    report = run_mcp_conformance(Ineffective(
        MCPServer("srv_mcpfixture001", default_tools())
    ))
    assert "mcp-fault-in-flight" in failed_checks(report)
