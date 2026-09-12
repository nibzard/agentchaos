"""Adapter conformance (T039, spec 8.2, AC-028).

Two halves prove the suite: the reference adapter passes everything,
and a broken adapter that violates exactly one promise fails exactly
the check that promise belongs to. A conformance suite that cannot
reject is decoration.
"""

import copy
from pathlib import Path

import pytest

from gauntlet_adapters import (
    AdapterRefusal,
    FaultAdapter,
    ReferenceFileAdapter,
    failed_checks,
    run_conformance,
    validate_manifest,
)
from gauntlet_adapters.conformance import SCENARIO_ID, check_record


def probe(adapter):
    manifest = adapter.manifest()
    return adapter.probe_fault(manifest["capabilities"][0], SCENARIO_ID)


# --- the reference adapter passes the whole suite -------------------


def test_the_reference_adapter_conforms():
    report = run_conformance(ReferenceFileAdapter())
    assert report["passed"] is True
    assert report["adapter_id"] == "adp_filefault01"
    assert len(report["checks"]) == 9
    assert failed_checks(report) == []


def test_the_report_names_every_requirement():
    report = run_conformance(ReferenceFileAdapter())
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
    ]
    for record in report["checks"]:
        assert record["requirement"], record["id"]
        assert record["detail"], record["id"]


def test_reference_refuses_families_it_does_not_advertise():
    adapter = ReferenceFileAdapter()
    fault = {"kind": "budget", "scenario_version_id": SCENARIO_ID,
             "parameters": {}}
    with pytest.raises(AdapterRefusal):
        adapter.apply(fault, Path("."))


def test_reference_refuses_escaping_paths(tmp_path):
    adapter = ReferenceFileAdapter()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    fault = {
        "kind": "file",
        "scenario_version_id": SCENARIO_ID,
        "parameters": {"files": {"../escape.txt": "out\n"}},
    }
    with pytest.raises(AdapterRefusal):
        adapter.apply(fault, workspace)
    assert not (tmp_path / "escape.txt").exists()


# --- one broken promise per adapter ---------------------------------


class BrokenAdapter(ReferenceFileAdapter):
    """Override one behavior; inherit the rest."""


def mutate_manifest(**changes):
    """Change top-level manifest fields on a subclass."""

    class Mutated(BrokenAdapter):
        def manifest(self):
            document = copy.deepcopy(super().manifest())
            for key, value in changes.items():
                if key in document:
                    document[key] = value
            return document

    return Mutated()


def test_empty_capabilities_fail_the_manifest():
    adapter = mutate_manifest(capabilities=[])
    report = run_conformance(adapter)
    assert "manifest-shape" in failed_checks(report)


def test_unknown_fields_fail_the_manifest():
    class Extra(BrokenAdapter):
        def manifest(self):
            document = super().manifest()
            document["experimental_paths"] = ["something"]
            return document

    report = run_conformance(Extra())
    assert "manifest-shape" in failed_checks(report)


def test_a_silent_fault_family_fails_the_manifest():
    # Drop one unsupported-path entry: a family now neither advertised
    # nor rejected.
    class Silent(BrokenAdapter):
        def manifest(self):
            document = super().manifest()
            document["unsupported_paths"] = [
                entry for entry in document["unsupported_paths"]
                if entry["family"] != "budget"
            ]
            return document

    report = run_conformance(Silent())
    assert "manifest-shape" in failed_checks(report)
    detail = next(
        record for record in report["checks"]
        if record["id"] == "manifest-shape"
    )["detail"]
    assert "budget" in detail


def test_an_inside_worker_site_fails():
    adapter = mutate_manifest(
        interception_location={
            "site": "process_boundary",
            "outside_worker": False,
            "description": "hooked into the worker process",
        },
    )
    report = run_conformance(adapter)
    assert "manifest-shape" in failed_checks(report)


def test_an_unexercisable_capability_fails():
    class ClaimsTooMuch(BrokenAdapter):
        def manifest(self):
            document = super().manifest()
            document["capabilities"] = ["file", "budget"]
            document["unsupported_paths"] = [
                entry for entry in document["unsupported_paths"]
                if entry["family"] != "budget"
            ]
            return document

        def probe_fault(self, family, scenario_version_id):
            if family == "budget":
                raise AdapterRefusal("no budget primitive implemented")
            return super().probe_fault(family, scenario_version_id)

    report = run_conformance(ClaimsTooMuch())
    assert "advertised-capabilities" in failed_checks(report)


def test_a_silently_applied_unsupported_family_fails():
    class SilentAcceptor(BrokenAdapter):
        def apply(self, fault, workspace):
            if fault["kind"] not in self.manifest()["capabilities"]:
                # Applies anyway and reports a receipt: the worst
                # failure mode the suite exists to catch.
                return {
                    "scenario_version_id": fault["scenario_version_id"],
                    "trigger_state": "triggered",
                    "receipt_event_id": "evt_" + "0" * 16,
                    "emitted_by": "adapter_outside_worker",
                }
            return super().apply(fault, workspace)

    report = run_conformance(SilentAcceptor())
    assert "unsupported-paths" in failed_checks(report)


def test_a_worker_authored_receipt_fails():
    class InsideEmitter(BrokenAdapter):
        def apply(self, fault, workspace):
            receipt = super().apply(fault, workspace)
            receipt["emitted_by"] = "worker_self_report"
            return receipt

    report = run_conformance(InsideEmitter())
    for check in ("advertised-capabilities", "interception-location",
                  "logging"):
        assert check in failed_checks(report), check


def test_a_receipt_with_a_bad_event_id_fails():
    class BadId(BrokenAdapter):
        def apply(self, fault, workspace):
            receipt = super().apply(fault, workspace)
            receipt["receipt_event_id"] = "not-an-evt-id"
            return receipt

    report = run_conformance(BadId())
    assert "advertised-capabilities" in failed_checks(report)


def test_nondeterministic_receipt_ids_fail():
    import itertools

    counter = itertools.count()

    class Wandering(BrokenAdapter):
        def apply(self, fault, workspace):
            receipt = super().apply(fault, workspace)
            receipt["receipt_event_id"] = f"evt_{next(counter):016x}"
            return receipt

    report = run_conformance(Wandering())
    assert "logging" in failed_checks(report)


def test_lying_about_side_effects_fails():
    class Liar(BrokenAdapter):
        def manifest(self):
            document = super().manifest()
            document["side_effect_semantics"] = {
                "declared_effects": ["none"],
                "reversible": True,
            }
            return document

    report = run_conformance(Liar())
    assert "side-effect-semantics" in failed_checks(report)


def test_an_untidy_teardown_fails():
    class Untidy(BrokenAdapter):
        def teardown(self, workspace):
            return {"operation": "claims to clean", "removed": [],
                    "failed": []}

    report = run_conformance(Untidy())
    assert "teardown" in failed_checks(report)


def test_a_teardown_that_raises_fails():
    class ExplodingTeardown(BrokenAdapter):
        def teardown(self, workspace):
            raise RuntimeError("teardown exploded")

    report = run_conformance(ExplodingTeardown())
    assert "teardown" in failed_checks(report)
    detail = next(
        record for record in report["checks"]
        if record["id"] == "teardown"
    )["detail"]
    assert "exploded" in detail


def test_external_write_without_external_undo_fails():
    class External(BrokenAdapter):
        def manifest(self):
            document = super().manifest()
            document["side_effect_semantics"] = {
                "declared_effects": ["external_write"],
                "reversible": True,
            }
            return document

    report = run_conformance(External())
    assert "cleanup-guarantee" in failed_checks(report)


def test_reversible_true_with_guarantee_none_fails():
    class PromiseNothing(BrokenAdapter):
        def manifest(self):
            document = super().manifest()
            document["cleanup"] = {
                "operation": "best effort",
                "guarantee": "none",
                "verified_by": "independent_cleanup_verifier",
            }
            return document

    report = run_conformance(PromiseNothing())
    assert "cleanup-guarantee" in failed_checks(report)


def test_writing_outside_the_workspace_fails(tmp_path):
    class Escaper(BrokenAdapter):
        def apply(self, fault, workspace):
            receipt = super().apply(fault, workspace)
            neighbor = workspace.parent / "neighbor.txt"
            neighbor.write_text("escaped\n", encoding="utf-8")
            return receipt

    report = run_conformance(Escaper())
    assert "isolation-coverage" in failed_checks(report)


def test_an_escaping_fault_path_that_is_applied_fails():
    class ApplyEscapes(BrokenAdapter):
        def apply(self, fault, workspace):
            files = (fault.get("parameters") or {}).get("files", {})
            if any(relative.startswith("../") for relative in files):
                relative = next(iter(files))
                target = workspace / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("escaped\n", encoding="utf-8")
                return {
                    "scenario_version_id": fault["scenario_version_id"],
                    "trigger_state": "triggered",
                    "receipt_event_id": "evt_" + "1" * 16,
                    "emitted_by": "adapter_outside_worker",
                }
            return super().apply(fault, workspace)

    report = run_conformance(ApplyEscapes())
    assert "isolation-coverage" in failed_checks(report)


def test_a_fully_hostile_adapter_never_crashes_the_suite():
    class Hostile(FaultAdapter):
        def manifest(self):
            raise RuntimeError("no manifest for you")

        def probe_fault(self, family, scenario_version_id):
            raise MemoryError("no probes")

        def apply(self, fault, workspace):
            raise RuntimeError("no applies")

        def teardown(self, workspace):
            raise RuntimeError("no teardown")

    report = run_conformance(Hostile())
    assert report["passed"] is False
    assert report["adapter_id"] == "unknown"
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
    ]
    assert len(failed_checks(report)) == 9


# --- the manifest contract on its own --------------------------------


def test_validate_manifest_collects_every_violation():
    broken = ReferenceFileAdapter().manifest()
    broken["capabilities"] = []
    broken["unsupported_paths"] = [
        {"family": "mystery", "reason": ""}
    ]
    broken["logging"] = {"emits_injection_receipt": False}
    errors = validate_manifest(broken)
    # One error per broken section: capabilities, unsupported paths,
    # logging — not just the first failure.
    assert len(errors) == 3
    joined = " ".join(errors)
    assert "capabilities" in joined
    assert "mystery" in joined
    assert "manifest.logging" in joined
    # The silent families are named.
    assert "neither advertised nor rejected" in joined
    assert "model_response" in joined


def test_validate_manifest_accepts_the_reference():
    assert validate_manifest(ReferenceFileAdapter().manifest()) == []


def test_check_record_shape():
    record = check_record("an-id", "a requirement", True, "detail")
    assert record == {
        "id": "an-id",
        "requirement": "a requirement",
        "passed": True,
        "detail": "detail",
    }
