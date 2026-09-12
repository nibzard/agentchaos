"""The fault adapter runtime interface (spec 9.3).

An adapter applies one narrowly scoped fault from outside the worker,
refuses everything outside its advertised capabilities, and emits an
injection receipt the worker did not author. Teardown undoes exactly
what apply did. The reference adapter here targets the file family
and mirrors what the scenario library's executor simulates, so the
conformance suite exercises a real implementation, not a stub.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from gauntlet_adapters.contract import validate_manifest


class AdapterRefusal(Exception):
    """The adapter refused a request outside its contract."""


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def receipt_id(*parts: str) -> str:
    """Deterministic evt_ id over the receipt's identity parts."""
    digest = hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()
    return "evt_" + digest[:16]


class FaultAdapter:
    """The adapter interface the conformance suite drives.

    Subclasses implement `manifest`, `probe_fault`, `apply`, and
    `teardown`. Every method must refuse cleanly: an adapter raises
    AdapterRefusal for anything outside its advertisement. Any other
    exception is a conformance failure.
    """

    def manifest(self) -> dict:
        raise NotImplementedError

    def probe_fault(self, family: str, scenario_version_id: str) -> dict:
        """Build a demonstration fault for a family this adapter
        advertises. An adapter that cannot construct one does not have
        a testable capability."""
        raise NotImplementedError

    def apply(self, fault: dict, workspace: Path) -> dict:
        """Apply one fault; return its injection receipt."""
        raise NotImplementedError

    def teardown(self, workspace: Path) -> dict:
        """Undo what apply did to this workspace; return a report."""
        raise NotImplementedError

    def supports(self, family: str) -> bool:
        return family in self.manifest()["capabilities"]


def reference_manifest() -> dict:
    """The reference adapter's advertisement (spec 8.2)."""

    def rejected(family: str, reason: str) -> dict:
        return {"family": family, "reason": reason}

    return {
        "kind": "AdapterManifest",
        "api_version": "v1",
        "adapter_id": "adp_filefault01",
        "version": "1.0.0",
        "capabilities": ["file"],
        "unsupported_paths": [
            rejected("model_response",
                     "the reference adapter does not intercept model "
                     "responses"),
            rejected("tool_result",
                     "tool results pass through the broker, not this "
                     "adapter"),
            rejected("memory_snapshot",
                     "the reference adapter does not carry snapshot "
                     "primitives"),
            rejected("peer_channel", "peer channels are not wired"),
            rejected("permission",
                     "permission changes need the hardened backend"),
            rejected("dependency", "dependency faults are not wired"),
            rejected("budget", "budget faults live in the broker"),
            rejected("monitor_component",
                     "monitor components run outside this adapter"),
        ],
        "interception_location": {
            "site": "filesystem",
            "outside_worker": True,
            "description": (
                "Writes fault files into the installed workspace "
                "before the worker starts, from the harness process."
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
                "files",
                "emitted_by",
            ],
        },
        "cleanup": {
            "operation": "remove exactly the files this adapter added",
            "guarantee": "workspace_restore",
            "verified_by": "independent_cleanup_verifier",
        },
    }


class ReferenceFileAdapter(FaultAdapter):
    """File-family reference adapter.

    Apply writes the fault's files into the workspace from outside the
    worker. It records every path it added per workspace, refuses
    paths that escape the workspace, and teardown removes exactly what
    apply added — a baseline file the adapter never touched survives.
    """

    def __init__(self) -> None:
        # workspace path -> ordered list of files this adapter added.
        self._added: dict[str, list[str]] = {}

    def manifest(self) -> dict:
        return reference_manifest()

    def probe_fault(self, family: str, scenario_version_id: str) -> dict:
        if family != "file":
            raise AdapterRefusal(
                f"the reference adapter does not support {family!r}"
            )
        return {
            "kind": "file",
            "scenario_version_id": scenario_version_id,
            "parameters": {
                "files": {"fault-injected.conf": "corrupted=true\n"}
            },
        }

    def apply(self, fault: dict, workspace: Path) -> dict:
        family = fault.get("kind")
        if family not in self.manifest()["capabilities"]:
            raise AdapterRefusal(
                f"fault family {family!r} is outside the advertised "
                "capabilities"
            )
        files = (fault.get("parameters") or {}).get("files")
        if not isinstance(files, dict) or not files:
            raise AdapterRefusal("a file fault needs a non-empty files map")
        scenario_version_id = fault.get("scenario_version_id", "")
        if not scenario_version_id:
            raise AdapterRefusal("a fault needs its scenario version id")

        written: list[str] = []
        for relative in sorted(files):
            target = workspace / relative
            if not _is_within(target, workspace):
                raise AdapterRefusal(
                    f"path {relative!r} escapes the workspace"
                )
            existed = target.exists()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(files[relative], encoding="utf-8")
            if not existed:
                written.append(relative)
        key = str(workspace)
        self._added.setdefault(key, [])
        # Idempotent: applying the same fault twice records one copy.
        for relative in written:
            if relative not in self._added[key]:
                self._added[key].append(relative)

        receipt = {
            "scenario_version_id": scenario_version_id,
            "trigger_state": "triggered",
            "receipt_event_id": receipt_id(
                self.manifest()["adapter_id"],
                scenario_version_id,
                family,
                *sorted(files),
            ),
            "files": sorted(files),
            "emitted_by": "adapter_outside_worker",
        }
        return receipt

    def teardown(self, workspace: Path) -> dict:
        key = str(workspace)
        added = self._added.get(key, [])
        removed: list[str] = []
        for relative in sorted(added):
            target = workspace / relative
            if not _is_within(target, workspace):
                return {
                    "operation": "remove exactly the files this "
                                 "adapter added",
                    "removed": [],
                    "failed": [relative],
                    "failure": f"path {relative!r} escapes the workspace",
                }
            if target.exists():
                target.unlink()
            removed.append(relative)
        self._added.pop(key, None)
        return {
            "operation": "remove exactly the files this adapter added",
            "removed": removed,
            "failed": [],
        }


def fresh_workspace(root: Path, baseline: dict[str, str] | None = None) -> Path:
    """Create a private workspace and install a baseline bundle.

    The conformance suite uses this so teardown checks can tell an
    adapter-added file from a file the run installed.
    """
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    default = {"task.md": "close issue #7\n"}
    for relative, content in (baseline or default).items():
        target = workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return workspace


def workspace_tree(workspace: Path) -> dict[str, str]:
    """Every file in the workspace, relative path to content."""
    tree: dict[str, str] = {}
    for path in sorted(workspace.rglob("*")):
        if path.is_file():
            tree[path.relative_to(workspace).as_posix()] = path.read_text(
                encoding="utf-8"
            )
    return tree


def remove_tree(root: Path) -> None:
    shutil.rmtree(root, ignore_errors=True)
