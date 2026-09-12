"""The adapter conformance suite (spec 8.2, AC-028).

An adapter passes this suite before the product calls it contained.
Each check takes one promise from the adapter's manifest and tests the
adapter's behavior against it: advertised capabilities must be
exercisable, unsupported paths must refuse, the interception location
must sit outside the worker, side effects must match the declaration,
receipts must be complete and deterministic, teardown must restore the
installed state, and no operation may touch anything outside the
workspace.

The suite treats the adapter as untrusted. Any exception other than
AdapterRefusal fails the check that saw it; nothing an adapter does
may crash the suite.
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

from acx_adapters.adapter import (
    AdapterRefusal,
    FaultAdapter,
    fresh_workspace,
    workspace_tree,
)
from acx_adapters.contract import REQUIRED_RECEIPT_FIELDS, validate_manifest

EVIDENCE_EVENT_ID = re.compile(r"^evt_[a-z0-9]{8,64}$")

SCENARIO_ID = "scn_conformance01"

CANARY_CONTENT = "untouched\n"
ESCAPING_RELATIVE = "../escape.txt"


def check_record(check_id: str, requirement: str, passed: bool,
                 detail: str) -> dict:
    return {
        "id": check_id,
        "requirement": requirement,
        "passed": passed,
        "detail": detail,
    }


def _receipt_problems(receipt: dict) -> list[str]:
    """Structural problems with one injection receipt."""
    problems: list[str] = []
    if not isinstance(receipt, dict):
        return [f"receipt is {type(receipt).__name__}, not an object"]
    if receipt.get("emitted_by") != "adapter_outside_worker":
        problems.append(
            f"emitted_by is {receipt.get('emitted_by')!r}, not "
            "'adapter_outside_worker'"
        )
    if receipt.get("trigger_state") != "triggered":
        problems.append(
            f"probe trigger_state is {receipt.get('trigger_state')!r}"
        )
    event_id = receipt.get("receipt_event_id", "")
    if not isinstance(event_id, str) or not EVIDENCE_EVENT_ID.match(event_id):
        problems.append(f"receipt_event_id {event_id!r} is not an evt_ id")
    if receipt.get("scenario_version_id") != SCENARIO_ID:
        problems.append("receipt lost the scenario version id")
    missing = sorted(
        REQUIRED_RECEIPT_FIELDS - frozenset(receipt)
    )
    if missing:
        problems.append(f"receipt is missing {missing}")
    return problems


def _check_manifest_shape(adapter: FaultAdapter) -> dict:
    requirement = (
        "the manifest advertises capabilities, unsupported paths, "
        "interception location, side-effect semantics, logging, and "
        "cleanup guarantees under a strict closed contract"
    )
    manifest = adapter.manifest()
    errors = validate_manifest(manifest)
    if errors:
        return check_record("manifest-shape", requirement, False,
                            "; ".join(errors))
    return check_record("manifest-shape", requirement, True,
                        f"manifest for {manifest['adapter_id']} is valid")


def _check_advertised_capabilities(adapter: FaultAdapter) -> dict:
    requirement = (
        "every advertised fault family is exercisable: the adapter "
        "builds a probe fault for it and applies it successfully"
    )
    manifest = adapter.manifest()
    for family in manifest["capabilities"]:
        try:
            fault = adapter.probe_fault(family, SCENARIO_ID)
        except AdapterRefusal as refusal:
            return check_record(
                "advertised-capabilities", requirement, False,
                f"probe for {family!r} was refused: {refusal}",
            )
        except Exception as error:  # noqa: BLE001 - the suite survives
            return check_record(
                "advertised-capabilities", requirement, False,
                f"probe for {family!r} raised {type(error).__name__}: "
                f"{error}",
            )
        if not isinstance(fault, dict) or fault.get("kind") != family:
            return check_record(
                "advertised-capabilities", requirement, False,
                f"probe for {family!r} returned a fault of kind "
                f"{fault.get('kind') if isinstance(fault, dict) else fault!r}",
            )
        with tempfile.TemporaryDirectory() as root:
            workspace = fresh_workspace(Path(root))
            try:
                receipt = adapter.apply(fault, workspace)
            except Exception as error:  # noqa: BLE001
                return check_record(
                    "advertised-capabilities", requirement, False,
                    f"apply of the {family!r} probe raised "
                    f"{type(error).__name__}: {error}",
                )
            problems = _receipt_problems(receipt)
            if problems:
                return check_record(
                    "advertised-capabilities", requirement, False,
                    f"{family!r} probe receipt: {'; '.join(problems)}",
                )
    return check_record(
        "advertised-capabilities", requirement, True,
        f"probes exercised {sorted(manifest['capabilities'])}",
    )


def _check_unsupported_paths(adapter: FaultAdapter) -> dict:
    requirement = (
        "every unsupported path is declared with a reason, and "
        "applying a fault of an unsupported family refuses explicitly"
    )
    manifest = adapter.manifest()
    unsupported = [
        entry["family"] for entry in manifest["unsupported_paths"]
    ]
    if not unsupported:
        return check_record(
            "unsupported-paths", requirement, False,
            "the adapter claims every fault family; nothing to refuse",
        )
    family = unsupported[0]
    fault = {"kind": family, "scenario_version_id": SCENARIO_ID,
             "parameters": {}}
    with tempfile.TemporaryDirectory() as root:
        workspace = fresh_workspace(Path(root))
        try:
            receipt = adapter.apply(fault, workspace)
        except AdapterRefusal:
            return check_record(
                "unsupported-paths", requirement, True,
                f"{family!r} refused with an explicit adapter refusal",
            )
        except Exception as error:  # noqa: BLE001
            return check_record(
                "unsupported-paths", requirement, False,
                f"{family!r} raised {type(error).__name__} instead of "
                f"refusing: {error}",
            )
        return check_record(
            "unsupported-paths", requirement, False,
            f"{family!r} was silently applied (receipt "
            f"{receipt.get('receipt_event_id') if isinstance(receipt, dict) else receipt!r})",
        )


def _check_interception_location(adapter: FaultAdapter) -> dict:
    requirement = (
        "the interception location is a known site outside the worker, "
        "and receipts carry emitted_by=adapter_outside_worker with no "
        "worker involved"
    )
    manifest = adapter.manifest()
    family = manifest["capabilities"][0]
    fault = adapter.probe_fault(family, SCENARIO_ID)
    with tempfile.TemporaryDirectory() as root:
        # No worker runs here at all. A receipt still arriving proves
        # the emission does not depend on worker cooperation.
        workspace = fresh_workspace(Path(root))
        receipt = adapter.apply(fault, workspace)
        problems = _receipt_problems(receipt)
        location = manifest["interception_location"]
        if location.get("outside_worker") is not True:
            problems.append("the manifest declares an inside-worker site")
    if problems:
        return check_record("interception-location", requirement, False,
                            "; ".join(problems))
    return check_record(
        "interception-location", requirement, True,
        f"receipt emitted at site {location['site']} with no worker "
        "running",
    )


def _check_side_effect_semantics(adapter: FaultAdapter) -> dict:
    requirement = (
        "observed writes match the declared effect classes exactly"
    )
    manifest = adapter.manifest()
    declared = set(manifest["side_effect_semantics"]["declared_effects"])
    family = manifest["capabilities"][0]
    fault = adapter.probe_fault(family, SCENARIO_ID)
    with tempfile.TemporaryDirectory() as root:
        root_path = Path(root)
        workspace = fresh_workspace(root_path)
        before = workspace_tree(workspace)
        adapter.apply(fault, workspace)
        after = workspace_tree(workspace)
    added = sorted(set(after) - set(before))
    changed = sorted(
        name for name in set(after) & set(before)
        if after[name] != before[name]
    )
    writes = bool(added or changed)
    if declared == {"none"} and writes:
        return check_record(
            "side-effect-semantics", requirement, False,
            f"declared no effects but wrote {added + changed}",
        )
    if writes and not (
        declared & {"workspace_write", "external_write"}
    ):
        return check_record(
            "side-effect-semantics", requirement, False,
            f"wrote {added + changed} but declared only "
            f"{sorted(declared)}",
        )
    if "external_write" in declared and not writes:
        return check_record(
            "side-effect-semantics", requirement, False,
            "declared external_write but the probe wrote nothing; the "
            "declaration and the behavior disagree",
        )
    return check_record(
        "side-effect-semantics", requirement, True,
        f"probe wrote {added + changed or 'nothing'} under "
        f"{sorted(declared)}",
    )


def _check_logging(adapter: FaultAdapter) -> dict:
    requirement = (
        "every apply emits one complete receipt, and the same fault "
        "applied twice yields the same receipt event id"
    )
    manifest = adapter.manifest()
    family = manifest["capabilities"][0]
    fault = adapter.probe_fault(family, SCENARIO_ID)
    ids: list[str] = []
    for _ in range(2):
        with tempfile.TemporaryDirectory() as root:
            workspace = fresh_workspace(Path(root))
            receipt = adapter.apply(fault, workspace)
        problems = _receipt_problems(receipt)
        if problems:
            return check_record(
                "logging", requirement, False, "; ".join(problems)
            )
        assert isinstance(receipt, dict)
        ids.append(receipt["receipt_event_id"])
    if ids[0] != ids[1]:
        return check_record(
            "logging", requirement, False,
            f"the same fault produced two ids: {ids}",
        )
    return check_record(
        "logging", requirement, True,
        f"stable receipt id {ids[0]}",
    )


def _check_teardown(adapter: FaultAdapter) -> dict:
    requirement = (
        "teardown returns the workspace to its installed state: "
        "adapter-added files are gone, baseline files are intact, and "
        "teardown after a failed apply still restores"
    )
    manifest = adapter.manifest()
    family = manifest["capabilities"][0]
    fault = adapter.probe_fault(family, SCENARIO_ID)
    with tempfile.TemporaryDirectory() as root:
        root_path = Path(root)
        workspace = fresh_workspace(root_path)
        before = workspace_tree(workspace)
        try:
            adapter.apply(fault, workspace)
        except Exception:  # noqa: BLE001 - a failed apply still needs teardown
            pass
        try:
            report = adapter.teardown(workspace)
        except Exception as error:  # noqa: BLE001
            return check_record(
                "teardown", requirement, False,
                f"teardown raised {type(error).__name__}: {error}",
            )
        after = workspace_tree(workspace)
    if not isinstance(report, dict):
        return check_record(
            "teardown", requirement, False,
            f"teardown returned {report!r}, not a report",
        )
    if report.get("failed"):
        return check_record(
            "teardown", requirement, False,
            f"teardown reported failures: {report['failed']}",
        )
    if after != before:
        leftover = sorted(set(after) ^ set(before)) + sorted(
            name for name in set(after) & set(before)
            if after[name] != before[name]
        )
        return check_record(
            "teardown", requirement, False,
            f"workspace differs from the installed state: {sorted(set(leftover))}",
        )
    return check_record(
        "teardown", requirement, True,
        "the installed state returned after apply and teardown",
    )


def _check_cleanup_guarantee(adapter: FaultAdapter) -> dict:
    requirement = (
        "the cleanup guarantee covers every declared effect class: "
        "external_write needs external_undo, workspace_write needs at "
        "least workspace_restore"
    )
    manifest = adapter.manifest()
    declared = set(manifest["side_effect_semantics"]["declared_effects"])
    guarantee = manifest["cleanup"]["guarantee"]
    if "external_write" in declared and guarantee != "external_undo":
        return check_record(
            "cleanup-guarantee", requirement, False,
            f"external_write is only covered by external_undo, not "
            f"{guarantee!r}",
        )
    if "workspace_write" in declared and guarantee not in (
        "workspace_restore", "external_undo"
    ):
        return check_record(
            "cleanup-guarantee", requirement, False,
            f"workspace_write is not covered by guarantee {guarantee!r}",
        )
    if manifest["side_effect_semantics"]["reversible"] is True and (
        guarantee == "none"
    ):
        return check_record(
            "cleanup-guarantee", requirement, False,
            "reversible=true with guarantee none promises nothing",
        )
    return check_record(
        "cleanup-guarantee", requirement, True,
        f"guarantee {guarantee!r} covers {sorted(declared)}",
    )


def _check_isolation_coverage(adapter: FaultAdapter) -> dict:
    requirement = (
        "apply and teardown touch nothing outside the workspace, and a "
        "fault path that escapes the workspace refuses"
    )
    manifest = adapter.manifest()
    family = manifest["capabilities"][0]
    fault = adapter.probe_fault(family, SCENARIO_ID)
    with tempfile.TemporaryDirectory() as root:
        root_path = Path(root)
        workspace = fresh_workspace(root_path)
        canary = root_path / "canary.txt"
        canary.write_text(CANARY_CONTENT, encoding="utf-8")
        adapter.apply(fault, workspace)
        adapter.teardown(workspace)
        # The canary is the suite's own file; only other strays count.
        outside = sorted(
            path.relative_to(root_path).as_posix()
            for path in root_path.rglob("*")
            if path.is_file()
            and not _is_inside(path, workspace)
            and path != canary
        )
        canary_intact = canary.read_text(encoding="utf-8") == CANARY_CONTENT

        # A fault that tries to write outside the workspace refuses.
        escape_refused = None
        if "file" in manifest["capabilities"]:
            escaping = {
                "kind": "file",
                "scenario_version_id": SCENARIO_ID,
                "parameters": {"files": {ESCAPING_RELATIVE: "escaped\n"}},
            }
            try:
                adapter.apply(escaping, workspace)
                escape_refused = False
            except Exception:  # noqa: BLE001 - any refusal shape counts
                escape_refused = True
    problems: list[str] = []
    if not canary_intact:
        problems.append("the canary file outside the workspace changed")
    if outside:
        problems.append(f"files appeared outside the workspace: {outside}")
    if escape_refused is False:
        problems.append(
            f"a fault path {ESCAPING_RELATIVE!r} that escapes the "
            "workspace was not refused"
        )
    if problems:
        return check_record(
            "isolation-coverage", requirement, False, "; ".join(problems)
        )
    detail = "nothing outside the workspace changed"
    if escape_refused is True:
        detail += "; escaping fault paths refused"
    return check_record("isolation-coverage", requirement, True, detail)


def _is_inside(path: Path, workspace: Path) -> bool:
    try:
        path.resolve().relative_to(workspace.resolve())
        return True
    except ValueError:
        return False


CHECKS = (
    ("manifest-shape", _check_manifest_shape),
    ("advertised-capabilities", _check_advertised_capabilities),
    ("unsupported-paths", _check_unsupported_paths),
    ("interception-location", _check_interception_location),
    ("side-effect-semantics", _check_side_effect_semantics),
    ("logging", _check_logging),
    ("teardown", _check_teardown),
    ("cleanup-guarantee", _check_cleanup_guarantee),
    ("isolation-coverage", _check_isolation_coverage),
)


def run_conformance(adapter: FaultAdapter) -> dict:
    """Run every conformance check; return the report document.

    The report is the publishable conformance statement (AC-028): a
    failed check names its requirement, and `passed` is true only when
    every check passed. An adapter whose methods raise unexpectedly
    still gets a full report; the raised check fails.
    """
    checks: list[dict] = []
    for check_id, check in CHECKS:
        try:
            record = check(adapter)
        except Exception as error:  # noqa: BLE001 - the suite survives
            record = check_record(
                check_id, "", False,
                f"the check itself saw {type(error).__name__}: {error}",
            )
        checks.append(record)
    manifest = {}
    try:
        manifest = adapter.manifest()
    except Exception:  # noqa: BLE001
        pass
    return {
        "kind": "AdapterConformanceReport",
        "api_version": "v1",
        "adapter_id": manifest.get("adapter_id", "unknown"),
        "passed": all(record["passed"] for record in checks),
        "checks": checks,
    }


def failed_checks(report: dict) -> list[str]:
    """Ids of the failed checks in a conformance report."""
    return [
        record["id"] for record in report["checks"]
        if not record["passed"]
    ]
