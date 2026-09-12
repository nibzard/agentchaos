"""The Model Context Protocol adapter (T048, spec 18.3, S18, AC-032).

The specification names one protocol-level rule for an MCP
integration: it "must preserve audience-bound authorization rather
than pass downstream tokens through indiscriminately" (spec 18.3,
source S18). This adapter implements that rule at the network edge
between the worker's MCP client and the MCP server:

- Every tool call presents a worker credential whose `aud` claim must
  bind the target server. A missing, malformed, or wrong-audience
  credential refuses before anything dispatches.
- The worker credential is consumed at the adapter boundary. The
  server downstream authenticates the adapter's own audience-bound
  credential, never the worker's token.
- Every record carries keyed fingerprints of credentials, never raw
  credential material.

The fault capability is `tool_result`: apply arms a mutation that
changes one tool's result while it passes through the adapter. The
server is a simulated in-process MCP server, and the credentials are
an unsigned fixture encoding. The audience check is the point here,
not cryptography; a real deployment signs both tokens and speaks the
real transport. Those upgrades do not change the checks.

`run_mcp_conformance` runs the nine canonical checks plus four
MCP-specific ones (auth, passthrough, redaction, fault visibility),
because AC-032 demands auth conformance and the canonical suite does
not test it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import tempfile
from pathlib import Path

from gauntlet_adapters.adapter import (
    AdapterRefusal,
    FaultAdapter,
    fresh_workspace,
    receipt_id,
)
from gauntlet_adapters.conformance import (
    SCENARIO_ID,
    check_record,
    run_conformance,
)

ADAPTER_ID = "adp_mcpserver01"
SERVER_ID = re.compile(r"^srv_[a-z0-9]{4,64}$")

# What a fault may change about a tool result while it is in flight.
MUTATIONS = ("corrupt_payload", "swap_error")

# Where apply installs the fault configuration inside the workspace.
CONFIG_RELATIVE = ".gauntlet/mcp-fault.json"

CREDENTIAL_PREFIX = "mcp1_"


# --- fixture credentials ---------------------------------------------


def encode_credential(payload: dict) -> str:
    """Encode one credential payload as an opaque fixture token.

    This is an encoding, not a signature. A real deployment replaces
    it with a signed short-lived token; the audience check below does
    not depend on the encoding.
    """
    raw = json.dumps(payload, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    return CREDENTIAL_PREFIX + base64.urlsafe_b64encode(
        raw
    ).decode("ascii").rstrip("=")


def issue_credential(server_id: str, subject: str,
                     scopes: tuple[str, ...] = ("tools:call",)) -> str:
    """Issue a fixture credential bound to one server audience."""
    return encode_credential({
        "aud": server_id,
        "sub": subject,
        "scopes": list(scopes),
    })


def parse_credential(token: str) -> dict:
    """Decode a fixture credential; raise ValueError when unusable."""
    if not isinstance(token, str) or not token.startswith(CREDENTIAL_PREFIX):
        raise ValueError("not an mcp1 credential")
    body = token[len(CREDENTIAL_PREFIX):]
    padding = "=" * (-len(body) % 4)
    try:
        raw = base64.urlsafe_b64decode(body + padding)
        payload = json.loads(raw)
    except (ValueError, TypeError) as error:
        raise ValueError("malformed credential") from error
    if not isinstance(payload, dict):
        raise ValueError("credential payload is not an object")
    return payload


def _fingerprint(key: bytes, token: str) -> str:
    """A keyed pseudonym for one credential (spec 19).

    Keyed, so the digest is not searchable across independent records
    the way a bare hash would be.
    """
    digest = hmac.new(key, token.encode("utf-8"),
                      hashlib.sha256).hexdigest()
    return "hk_" + digest[:16]


def _corrupt(value) -> str:  # noqa: ANN001 - any JSON value
    """Deterministically garble one payload value."""
    return "corrupted:" + json.dumps(value, sort_keys=True)[::-1]


def _mutate(result: dict, mutation: str) -> dict:
    if mutation == "corrupt_payload":
        mutated = dict(result)
        mutated["payload"] = _corrupt(mutated.get("payload"))
        return mutated
    if mutation == "swap_error":
        return {
            "error": {
                "code": "mcp_tool_failed",
                "message": "the tool call failed",
            }
        }
    raise AdapterRefusal(f"unknown mutation {mutation!r}")


def default_tools() -> dict:
    """The fixture tool set for the simulated server.

    Two tools, so conformance can show a fault affects one tool and
    not its neighbor.
    """

    def fetch_document(arguments: dict) -> dict:
        path = arguments.get("path", "")
        return {"payload": f"contents of {path}"}

    def status_lookup(arguments: dict) -> dict:  # noqa: ARG001
        return {"status": "ok"}

    return {"fetch_document": fetch_document, "status_lookup": status_lookup}


# --- the simulated downstream server ---------------------------------


class MCPServer:
    """An in-process stand-in for one MCP server: the audience.

    The server authenticates the credential presented to it and
    records every dispatch. Records carry the authenticated subject
    and a keyed fingerprint, never the credential itself. The raw
    credential the server authenticated is kept in `last_presented`
    so tests can prove which token traveled downstream; it is test
    state, not a record, and never leaves the process.
    """

    def __init__(self, server_id: str, tools: dict) -> None:
        if not SERVER_ID.match(server_id):
            raise ValueError(
                "server id must be srv_ plus 4-64 [a-z0-9]"
            )
        if not tools:
            raise ValueError("a server must expose at least one tool")
        self.server_id = server_id
        self._tools = dict(tools)
        self._redaction_key = hashlib.sha256(
            server_id.encode("utf-8")
        ).digest()
        self.calls: list[dict] = []
        self.last_presented: str | None = None

    def fingerprint(self, token: str) -> str:
        return _fingerprint(self._redaction_key, token)

    def tool_names(self) -> list[str]:
        return sorted(self._tools)

    def exposes(self, tool: str) -> bool:
        return tool in self._tools

    def dispatch(self, tool: str, arguments: dict,
                 presented_credential: str) -> dict:
        """Run one tool call; record what the server received."""
        payload = parse_credential(presented_credential)
        if payload.get("aud") != self.server_id:
            raise ValueError(
                "the presented credential is not bound to this server"
            )
        if "tools:call" not in payload.get("scopes", []):
            raise ValueError("the presented credential cannot call tools")
        if tool not in self._tools:
            raise KeyError(tool)
        self.last_presented = presented_credential
        self.calls.append({
            "server_id": self.server_id,
            "tool": tool,
            "arguments": dict(arguments or {}),
            "authenticated_subject": payload.get("sub"),
            "presented_credential_fingerprint":
                self.fingerprint(presented_credential),
        })
        return self._tools[tool](dict(arguments or {}))


# --- the adapter ------------------------------------------------------


def mcp_manifest() -> dict:
    """The MCP adapter's advertisement (spec 8.2)."""

    def rejected(family: str, reason: str) -> dict:
        return {"family": family, "reason": reason}

    return {
        "kind": "AdapterManifest",
        "api_version": "v1",
        "adapter_id": ADAPTER_ID,
        "version": "1.0.0",
        "capabilities": ["tool_result"],
        "unsupported_paths": [
            rejected("model_response",
                     "the adapter sits below the model client"),
            rejected("file",
                     "filesystem faults belong to the file adapter"),
            rejected("memory_snapshot",
                     "the adapter carries no snapshot primitives"),
            rejected("peer_channel",
                     "peer channels do not cross this edge"),
            rejected("permission",
                     "permission changes need the hardened backend"),
            rejected("dependency",
                     "dependency faults are not wired here"),
            rejected("budget",
                     "budget faults live in the broker"),
            rejected("monitor_component",
                     "monitor components run outside this adapter"),
        ],
        "interception_location": {
            "site": "network_edge",
            "outside_worker": True,
            "description": (
                "Sits between the worker's MCP client and the MCP "
                "server. Tool calls and results pass through the "
                "adapter in both directions."
            ),
        },
        "side_effect_semantics": {
            "declared_effects": ["workspace_write"],
            "reversible": True,
        },
        "logging": {
            "emits_injection_receipt": True,
            "receipt_fields": [
                "scenario_version_id",
                "trigger_state",
                "receipt_event_id",
                "tool",
                "mutation",
                "emitted_by",
            ],
        },
        "cleanup": {
            "operation": (
                "remove exactly the client config this adapter added "
                "and disarm the in-flight fault"
            ),
            "guarantee": "workspace_restore",
            "verified_by": "independent_cleanup_verifier",
        },
    }


class MCPToolAdapter(FaultAdapter):
    """The MCP tool-result fault adapter.

    `apply` installs the fault configuration into the workspace and
    arms an in-flight mutation for one tool. `call_tool` is the edge
    the worker's MCP client talks to: it checks the worker
    credential's audience, consumes the credential at the boundary,
    dispatches with the adapter's own credential, applies the armed
    mutation to the result, and returns it. `teardown` removes the
    config and disarms.
    """

    def __init__(self, server: MCPServer) -> None:
        self.server = server
        # The adapter's own credential for this audience. The worker
        # token is never presented downstream; this one is.
        self._adapter_subject = f"adapter:{ADAPTER_ID}"
        self._adapter_credential = issue_credential(
            server.server_id, self._adapter_subject,
        )
        # workspace path -> armed fault config
        self._armed: dict[str, dict] = {}
        # workspace path -> files this adapter added
        self._added: dict[str, list[str]] = {}
        # what the adapter did with every call, fingerprinted
        self.dispatch_log: list[dict] = []

    def manifest(self) -> dict:
        return mcp_manifest()

    def probe_fault(self, family: str, scenario_version_id: str) -> dict:
        if family != "tool_result":
            raise AdapterRefusal(
                f"the MCP adapter does not support {family!r}"
            )
        return {
            "kind": "tool_result",
            "scenario_version_id": scenario_version_id,
            "parameters": {
                "tool": self.server.tool_names()[0],
                "mutation": "corrupt_payload",
            },
        }

    def _armed_fault(self, workspace: Path) -> dict | None:
        """The fault armed for this workspace; a seam for test doubles."""
        return self._armed.get(str(workspace))

    def apply(self, fault: dict, workspace: Path) -> dict:
        family = fault.get("kind")
        if family not in self.manifest()["capabilities"]:
            raise AdapterRefusal(
                f"fault family {family!r} is outside the advertised "
                "capabilities"
            )
        scenario_version_id = fault.get("scenario_version_id", "")
        if not isinstance(scenario_version_id, str) or not (
            scenario_version_id
        ):
            raise AdapterRefusal("a fault needs its scenario version id")
        parameters = fault.get("parameters")
        if not isinstance(parameters, dict):
            raise AdapterRefusal("a tool_result fault needs parameters")
        tool = parameters.get("tool")
        if not isinstance(tool, str) or not tool:
            raise AdapterRefusal("a tool_result fault needs a tool name")
        mutation = parameters.get("mutation")
        if mutation not in MUTATIONS:
            raise AdapterRefusal(
                f"mutation {mutation!r} is not one of {list(MUTATIONS)}"
            )
        if not self.server.exposes(tool):
            raise AdapterRefusal(
                f"the server does not expose tool {tool!r}; a fault "
                "against it can never fire"
            )

        config = {
            "adapter_id": ADAPTER_ID,
            "scenario_version_id": scenario_version_id,
            "tool": tool,
            "mutation": mutation,
        }
        target = workspace / CONFIG_RELATIVE
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(config, indent=2, sort_keys=True)
                          + "\n", encoding="utf-8")
        key = str(workspace)
        self._added.setdefault(key, [])
        if CONFIG_RELATIVE not in self._added[key]:
            self._added[key].append(CONFIG_RELATIVE)
        self._armed[key] = {"tool": tool, "mutation": mutation}

        return {
            "scenario_version_id": scenario_version_id,
            "trigger_state": "triggered",
            "receipt_event_id": receipt_id(
                ADAPTER_ID, scenario_version_id, family, tool, mutation,
            ),
            "tool": tool,
            "mutation": mutation,
            "emitted_by": "adapter_outside_worker",
        }

    def teardown(self, workspace: Path) -> dict:
        key = str(workspace)
        removed: list[str] = []
        for relative in sorted(self._added.get(key, [])):
            target = workspace / relative
            if target.exists():
                target.unlink()
            removed.append(relative)
        # Leave no empty config directory behind.
        config_dir = workspace / Path(CONFIG_RELATIVE).parent
        if config_dir.is_dir() and not any(config_dir.iterdir()):
            config_dir.rmdir()
        self._added.pop(key, None)
        self._armed.pop(key, None)
        return {
            "operation": (
                "remove exactly the client config this adapter added "
                "and disarm the in-flight fault"
            ),
            "removed": removed,
            "failed": [],
        }

    def call_tool(self, workspace: Path, tool: str, arguments: dict,
                  worker_credential: str | None) -> dict:
        """The network edge the worker's MCP client calls through.

        The audience check runs first and nothing dispatches without
        it. The worker credential is then consumed here: fingerprinted
        for the record, never forwarded.
        """
        if worker_credential is None:
            raise AdapterRefusal(
                "a tool call needs a worker credential"
            )
        try:
            payload = parse_credential(worker_credential)
        except ValueError as error:
            raise AdapterRefusal(
                f"the worker credential is unusable: {error}"
            ) from None
        audience = payload.get("aud")
        if audience != self.server.server_id:
            raise AdapterRefusal(
                f"credential audience {audience!r} does not bind "
                f"server {self.server.server_id!r}"
            )
        if not isinstance(arguments, dict):
            arguments = {}
        if not self.server.exposes(tool):
            raise AdapterRefusal(
                f"the server does not expose tool {tool!r}"
            )

        # The boundary: the worker credential stops here. The server
        # authenticates the adapter's own audience-bound credential.
        try:
            result = self.server.dispatch(
                tool, arguments, self._adapter_credential,
            )
        except ValueError as error:
            raise AdapterRefusal(
                f"the server refused the dispatch: {error}"
            ) from None

        fault_applied = False
        armed = self._armed_fault(workspace)
        if armed is not None and armed["tool"] == tool:
            result = _mutate(result, armed["mutation"])
            fault_applied = True

        self.dispatch_log.append({
            "workspace": str(workspace),
            "tool": tool,
            "audience_check": "passed",
            "worker_credential_fingerprint":
                self.server.fingerprint(worker_credential),
            "forwarded_worker_credential": False,
            "presented_credential_subject": self._adapter_subject,
            "fault_applied": fault_applied,
        })
        return result


def fixture_mcp_adapter() -> MCPToolAdapter:
    """A wired adapter over the fixture server, for tests and demos."""
    return MCPToolAdapter(MCPServer("srv_mcpfixture001", default_tools()))


# --- the MCP-specific conformance checks ------------------------------


def _worker_credential(adapter: MCPToolAdapter) -> str:
    return issue_credential(adapter.server.server_id, "worker:test")


def _check_audience_binding(adapter: MCPToolAdapter) -> dict:
    requirement = (
        "every tool call presents a credential whose audience binds "
        "this MCP server; a missing, malformed, wrong-audience, or "
        "audience-less credential refuses before anything dispatches"
    )
    server = adapter.server
    good = _worker_credential(adapter)
    wrong = issue_credential("srv_somebodyelse00", "worker:test")
    audience_less = encode_credential(
        {"sub": "worker:test", "scopes": ["tools:call"]}
    )
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as root:
        workspace = fresh_workspace(Path(root))
        tool = server.tool_names()[0]
        before = len(server.calls)
        adapter.call_tool(workspace, tool, {}, good)
        if len(server.calls) != before + 1:
            problems.append("a bound credential did not dispatch")
        for label, credential in (
            ("a missing", None),
            ("a wrong-audience", wrong),
            ("a malformed", "not-a-credential"),
            ("an audience-less", audience_less),
        ):
            count = len(server.calls)
            try:
                adapter.call_tool(workspace, tool, {}, credential)
            except AdapterRefusal:
                if len(server.calls) != count:
                    problems.append(
                        f"{label} credential refused but still dispatched"
                    )
            except Exception as error:  # noqa: BLE001
                problems.append(
                    f"{label} credential raised "
                    f"{type(error).__name__}, not a refusal"
                )
            else:
                problems.append(f"{label} credential was accepted")
    if problems:
        return check_record(
            "mcp-audience-binding", requirement, False, "; ".join(problems)
        )
    return check_record(
        "mcp-audience-binding", requirement, True,
        "bound credentials dispatch; every other credential refuses "
        "with nothing sent downstream",
    )


def _check_no_passthrough(adapter: MCPToolAdapter) -> dict:
    requirement = (
        "the worker credential is consumed at the adapter boundary: "
        "the server downstream authenticates the adapter's own "
        "audience-bound credential and the worker token never travels"
    )
    server = adapter.server
    worker = _worker_credential(adapter)
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as root:
        workspace = fresh_workspace(Path(root))
        adapter.call_tool(
            workspace, server.tool_names()[0], {}, worker,
        )
        record = server.calls[-1]
    if server.last_presented == worker:
        problems.append("the server authenticated the worker's token")
    if worker in json.dumps(server.calls):
        problems.append("the worker token appears in a server record")
    if record.get("authenticated_subject") == "worker:test":
        problems.append("the server saw the worker's subject downstream")
    if record.get("authenticated_subject") != f"adapter:{ADAPTER_ID}":
        problems.append(
            "the server did not authenticate the adapter's credential "
            f"(subject {record.get('authenticated_subject')!r})"
        )
    if problems:
        return check_record(
            "mcp-no-passthrough", requirement, False, "; ".join(problems)
        )
    return check_record(
        "mcp-no-passthrough", requirement, True,
        "the server authenticated the adapter credential; the worker "
        "token stayed at the boundary",
    )


def _check_record_redaction(adapter: MCPToolAdapter) -> dict:
    requirement = (
        "every record and receipt carries keyed fingerprints, never "
        "raw credential material"
    )
    server = adapter.server
    worker = _worker_credential(adapter)
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as root:
        workspace = fresh_workspace(Path(root))
        adapter.call_tool(workspace, server.tool_names()[0], {}, worker)
        receipt = adapter.apply(
            adapter.probe_fault("tool_result", SCENARIO_ID), workspace,
        )
        documents = (
            json.dumps(server.calls[-1:])
            + json.dumps(adapter.dispatch_log[-1:])
            + json.dumps(receipt)
        )
        entry = adapter.dispatch_log[-1]
    for name, token in (
        ("worker", worker),
        ("adapter", server.last_presented),
    ):
        if token is not None and token in documents:
            problems.append(f"the raw {name} credential appears in a "
                            "record or receipt")
    fingerprint = entry.get("worker_credential_fingerprint", "")
    if not isinstance(fingerprint, str) or not fingerprint.startswith("hk_"):
        problems.append(
            f"dispatch log fingerprint {fingerprint!r} is not a keyed "
            "pseudonym"
        )
    if problems:
        return check_record(
            "mcp-record-redaction", requirement, False, "; ".join(problems)
        )
    return check_record(
        "mcp-record-redaction", requirement, True,
        "records and receipts carry hk_ fingerprints only",
    )


def _check_fault_in_flight(adapter: MCPToolAdapter) -> dict:
    requirement = (
        "the armed fault changes the tool result the worker receives, "
        "leaves other tools untouched, and teardown restores the "
        "clean result"
    )
    server = adapter.server
    worker = _worker_credential(adapter)
    fault = adapter.probe_fault("tool_result", SCENARIO_ID)
    tool = fault["parameters"]["tool"]
    others = [name for name in server.tool_names() if name != tool]
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as root:
        workspace = fresh_workspace(Path(root))
        clean = adapter.call_tool(workspace, tool, {}, worker)
        clean_other = (
            adapter.call_tool(workspace, others[0], {}, worker)
            if others else None
        )
        receipt = adapter.apply(fault, workspace)
        faulted = adapter.call_tool(workspace, tool, {}, worker)
        faulted_other = (
            adapter.call_tool(workspace, others[0], {}, worker)
            if others else None
        )
        adapter.teardown(workspace)
        restored = adapter.call_tool(workspace, tool, {}, worker)
    if faulted == clean:
        problems.append("the armed fault left the result unchanged")
    if receipt.get("tool") != tool:
        problems.append("the receipt does not name the faulted tool")
    if others and faulted_other != clean_other:
        problems.append(
            f"the fault also changed tool {others[0]!r}"
        )
    if restored != clean:
        problems.append("teardown did not restore the clean result")
    if problems:
        return check_record(
            "mcp-fault-in-flight", requirement, False, "; ".join(problems)
        )
    detail = f"tool {tool!r} faulted in flight"
    detail += f"; tool {others[0]!r} untouched" if others else ""
    return check_record("mcp-fault-in-flight", requirement, True, detail)


MCP_EXTRA_CHECKS = (
    ("mcp-audience-binding", _check_audience_binding),
    ("mcp-no-passthrough", _check_no_passthrough),
    ("mcp-record-redaction", _check_record_redaction),
    ("mcp-fault-in-flight", _check_fault_in_flight),
)


def run_mcp_conformance(adapter: FaultAdapter) -> dict:
    """The canonical nine checks plus the four MCP-specific ones.

    AC-032 demands auth conformance; the canonical suite does not test
    it, so this report appends the audience, passthrough, and
    redaction checks to the standard report.
    """
    report = run_conformance(adapter)
    for check_id, check in MCP_EXTRA_CHECKS:
        try:
            record = check(adapter)
        except Exception as error:  # noqa: BLE001 - the suite survives
            record = check_record(
                check_id, "", False,
                f"the check itself saw {type(error).__name__}: {error}",
            )
        report["checks"].append(record)
    report["passed"] = all(record["passed"] for record in report["checks"])
    return report
