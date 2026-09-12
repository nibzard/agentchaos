"""Fixture runner behavior (spec 9.2)."""

import json

import pytest
from acx_schemas import ContractViolation, validate

from acx_runner import (
    Environment,
    FixtureRunner,
    LocalFixtureEnvironments,
    VariantOutcome,
    build_export,
    write_export,
)

from conftest import NOW, FixedClock, grant, plan_document

SCENARIO = "scn_7c1e9a0b3d5f2468"
RECEIPT = "evt_" + "9" * 16


class ScriptedExecutor:
    """Deterministic executor: treatment triggers, baseline does not."""

    def __init__(self, treatment_report=None, baseline_report=None):
        self.treatment_report = treatment_report or {
            "scenario_version_id": SCENARIO,
            "trigger_state": "triggered",
            "receipt_event_id": RECEIPT,
        }
        self.baseline_report = baseline_report or {
            "scenario_version_id": SCENARIO,
            "trigger_state": "not_triggered",
            "receipt_event_id": "evt_" + "8" * 16,
        }
        self.seen: list = []
        self.bundle_files: list[list[str]] = []

    def execute(self, spec) -> VariantOutcome:
        self.seen.append(spec)
        self.bundle_files.append(
            sorted(path.name for path in spec.workspace.iterdir())
        )
        report = (
            self.treatment_report
            if spec.arm == "treatment"
            else self.baseline_report
        )
        return VariantOutcome(
            observations=[{"arm": spec.arm, "step": "fixture-done"}],
            injections=[report],
        )


class ExplodingExecutor(ScriptedExecutor):
    def execute(self, spec) -> VariantOutcome:
        self.seen.append(spec)
        return VariantOutcome(
            error_code="fixture_missing", error="fixture file absent"
        )


def _runner(tmp_path, clock=None):
    state = {"n": 0}

    def root_factory(prefix=None, dir=None):  # noqa: ARG001
        state["n"] += 1
        return str(tmp_path / f"ws-{state['n']:03d}")

    environments = LocalFixtureEnvironments(
        id_factory=lambda: f"env_lfx-{state['n']:012d}",
        root_factory=root_factory,
    )
    counter = iter(range(1000))
    return FixtureRunner(
        environments,
        clock=clock or FixedClock(),
        run_id_factory=lambda: "run_" + f"{next(counter):016d}",
    )


BUNDLE = {"task.md": "close issue #7", "src/main.py": "print('ok')"}


def _run(tmp_path, executor=None, clock=None, plan=None, **kwargs):
    runner = _runner(tmp_path, clock)
    return runner.run(
        plan or plan_document(),
        grant(),
        executor or ScriptedExecutor(),
        bundle=BUNDLE,
        **kwargs,
    )


# Pairs, environments, and the identical baseline.


def test_pair_runs_baseline_and_treatment(tmp_path):
    pairs = _run(tmp_path)
    assert len(pairs) == 1
    pair = pairs[0]
    assert pair.error is None
    assert pair.baseline["variant"] == "baseline"
    assert pair.treatment["variant"] == "treatment"
    assert pair.injection_triggered is True


def test_each_variant_gets_a_fresh_environment(tmp_path):
    executor = ScriptedExecutor()
    _run(tmp_path, executor)
    workspaces = [spec.workspace for spec in executor.seen]
    assert len(workspaces) == 2
    assert workspaces[0] != workspaces[1]
    assert all(not root.exists() for root in workspaces)  # disposed


def test_baseline_install_is_identical_across_arms(tmp_path):
    pairs = _run(tmp_path)
    assert pairs[0].identical_baseline is True
    assert pairs[0].install_digest.startswith("sha256:")


def test_executor_sees_the_bundle_and_spec(tmp_path):
    executor = ScriptedExecutor()
    _run(tmp_path, executor)
    for spec, files in zip(executor.seen, executor.bundle_files):
        assert files == ["src", "task.md"]  # observed before disposal
        assert spec.profile["id"] in (
            "aup_1a2b3c4d5e6f7081",
            "aup_5b8d2e0f1a3c4966",
        )
        assert spec.scenario["id"] == SCENARIO
        assert spec.target_selection_seed == 20260911
        assert spec.tenant_id == "tnt_9d4c1e2a3b4f5c67"


def test_multiple_scenarios_pair_independently(tmp_path):
    plan = plan_document()
    plan["scenarios"].append(
        {"id": "scn_1111111111111111", "template_id": "F02-101", "version": "1.0.0"}
    )
    pairs = _run(tmp_path, plan=plan)
    assert [pair.scenario_version_id for pair in pairs] == [
        SCENARIO,
        "scn_1111111111111111",
    ]


def test_repetitions_repeat_pairs(tmp_path):
    pairs = _run(tmp_path, repetitions=3)
    assert len(pairs) == 3
    assert [pair.pair_id for pair in pairs] == [
        "pair-0-0",
        "pair-1-0",
        "pair-2-0",
    ]


def test_zero_repetitions_rejected(tmp_path):
    with pytest.raises(ValueError):
        _run(tmp_path, repetitions=0)


# Run documents satisfy the contract.


def test_run_documents_validate_against_the_contract(tmp_path):
    pairs = _run(tmp_path)
    for pair in pairs:
        validate(pair.baseline, "Run")
        validate(pair.treatment, "Run")


def test_terminal_runs_carry_outcome_and_cleanup_state(tmp_path):
    pairs = _run(tmp_path)
    run = pairs[0].treatment
    assert run["state"] == "terminal"
    assert run["outcome"] == "INCONCLUSIVE"  # triggered, assertions pending
    assert run["terminal_state"] == "CLEAN"
    assert run["injections"][0]["trigger_state"] == "triggered"
    assert run["injections"][0]["receipt_event_id"] == RECEIPT
    assert run["environment"]["fresh"] is True
    assert run["randomization"]["target_selection_seed"] == 20260911


def test_executor_error_labels_harness_error_and_unknown_cleanup(tmp_path):
    """Never infer clean cleanup from an error path (spec 13.3)."""
    pairs = _run(tmp_path, ExplodingExecutor())
    for run in (pairs[0].baseline, pairs[0].treatment):
        assert run["outcome"] == "HARNESS_ERROR"
        assert run["terminal_state"] == "UNKNOWN"
        assert run["stopped_reason"] == "fixture_missing"
        validate(run, "Run")


def test_executor_returning_wrong_type_is_a_harness_error(tmp_path):
    class BadExecutor:
        def execute(self, spec):
            return "done"

    pairs = _run(tmp_path, BadExecutor())
    assert pairs[0].baseline["outcome"] == "HARNESS_ERROR"


def test_raising_executor_is_recorded_not_propagated(tmp_path):
    """A crashing executor never destroys the run or leaks a workspace."""

    class CrashingExecutor:
        def __init__(self):
            self.workspaces: list = []

        def execute(self, spec):
            self.workspaces.append(spec.workspace)
            raise RuntimeError("worker crashed")

    executor = CrashingExecutor()
    plan = plan_document()
    plan["scenarios"] = [
        {"id": f"scn_{i:016d}", "template_id": "F01-101", "version": "1.1.0"}
        for i in range(1, 4)
    ]
    pairs = _run(tmp_path, executor, plan=plan)
    assert len(pairs) == 3  # every scenario still ran
    for pair in pairs:
        for run in (pair.baseline, pair.treatment):
            assert run["outcome"] == "HARNESS_ERROR"
            assert run["stopped_reason"] == "executor_crashed"
            assert run["terminal_state"] == "UNKNOWN"
            validate(run, "Run")
    assert all(not root.exists() for root in executor.workspaces)


def test_install_failure_reaches_the_pair_error(tmp_path):
    runner = _runner(tmp_path)
    pairs = runner.run(
        plan_document(), grant(), ScriptedExecutor(),
        bundle={"../escape.txt": "x"},
    )
    assert pairs[0].baseline is None
    assert pairs[0].treatment is None
    assert pairs[0].error is not None
    assert pairs[0].error.startswith("variant_failed: baseline:")
    document = build_export(
        plan_document(), pairs,
        plan_digest="sha256:" + "3" * 64, exported_at=NOW,
    )
    assert document["pairs"][0]["error"] == pairs[0].error


def test_conflicting_bundle_paths_are_install_failures(tmp_path):
    """{'a': 'x', 'a/b': 'y'} makes one path a file and a directory."""
    runner = _runner(tmp_path)
    pairs = runner.run(
        plan_document(), grant(), ScriptedExecutor(),
        bundle={"a": "x", "a/b": "y"},
    )
    assert pairs[0].error is not None
    assert pairs[0].error.startswith("variant_failed:")
    assert pairs[0].baseline is None


def test_long_digit_error_code_stays_within_the_pattern(tmp_path):
    class NumericExecutor(ScriptedExecutor):
        def execute(self, spec):
            return VariantOutcome(
                error_code="1" * 70, error="code starts with a digit"
            )

    pairs = _run(tmp_path, NumericExecutor())
    reason = pairs[0].baseline["stopped_reason"]
    assert len(reason) <= 64
    validate(pairs[0].baseline, "Run")


def test_report_with_bad_scenario_id_is_dropped_not_embedded(tmp_path):
    executor = ScriptedExecutor(
        treatment_report={"trigger_state": "triggered"}
    )
    pairs = _run(tmp_path, executor)
    assert pairs[0].treatment["injections"] == []
    assert pairs[0].downgraded_injections == ["None"]
    assert pairs[0].injection_triggered is None
    validate(pairs[0].treatment, "Run")


def test_not_triggered_pair_records_negative_verdict(tmp_path):
    executor = ScriptedExecutor(
        treatment_report={
            "scenario_version_id": SCENARIO,
            "trigger_state": "not_triggered",
            "receipt_event_id": "evt_" + "7" * 16,
        }
    )
    pairs = _run(tmp_path, executor)
    assert pairs[0].injection_triggered is False
    assert pairs[0].treatment["outcome"] == "NOT_TRIGGERED"
    validate(pairs[0].treatment, "Run")


def test_missing_receipt_downgrades_and_stays_inconclusive(tmp_path):
    executor = ScriptedExecutor(
        treatment_report={
            "scenario_version_id": SCENARIO,
            "trigger_state": "triggered",
        }
    )
    pairs = _run(tmp_path, executor)
    entry = pairs[0].treatment["injections"][0]
    assert entry["trigger_state"] == "unknown"
    assert "receipt_event_id" not in entry
    assert pairs[0].injection_triggered is None
    assert pairs[0].downgraded_injections == [SCENARIO]
    validate(pairs[0].treatment, "Run")


# Grant gating.


def test_expired_grant_stops_new_pairs_fail_closed(tmp_path):
    clock = FixedClock("2026-09-11T21:06:00Z")  # after 21:05 expiry
    pairs = _run(tmp_path, clock=clock)
    assert len(pairs) == 1
    assert pairs[0].error == "grant_expired: grant expired at 2026-09-11T21:05:00Z"
    assert pairs[0].baseline is None
    assert pairs[0].treatment is None
    assert pairs[0].injection_triggered is None


def test_grant_expiring_mid_run_stops_remaining_pairs(tmp_path):
    clock = FixedClock()
    executor = ScriptedExecutor()
    plan = plan_document()
    plan["scenarios"] = [
        {"id": f"scn_{i:016d}", "template_id": "F01-101", "version": "1.1.0"}
        for i in range(1, 4)
    ]

    runner = _runner(tmp_path, clock)

    original_check = runner._check_grant
    state = {"pairs": 0}

    def check_then_expire(grant_dict):
        original_check(grant_dict)
        state["pairs"] += 1
        if state["pairs"] >= 2:
            clock.advance_to("2026-09-11T21:10:00Z")

    runner._check_grant = check_then_expire
    pairs = runner.run(plan, grant(), executor, bundle=BUNDLE)
    assert pairs[0].error is None
    assert pairs[1].error is None
    assert pairs[2].error == "grant_expired: grant expired at 2026-09-11T21:05:00Z"


def test_grant_without_expiry_fails_closed(tmp_path):
    bad_grant = grant()
    del bad_grant["expires_at"]
    runner = _runner(tmp_path)
    pairs = runner.run(plan_document(), bad_grant, ScriptedExecutor())
    assert pairs[0].error == "grant_expired: grant carries no expires_at"


def test_offset_less_expiry_fails_closed_without_crashing(tmp_path):
    """A timestamp without an offset is ambiguous, so it authorizes nothing."""
    runner = _runner(tmp_path)
    pairs = runner.run(
        plan_document(), grant(expires_at="2026-09-11 21:05:00"),
        ScriptedExecutor(),
    )
    assert pairs[0].error == (
        "grant_expired: expires_at '2026-09-11 21:05:00' carries no "
        "UTC offset"
    )
    assert pairs[0].baseline is None


def test_expiry_equal_to_now_is_already_expired(tmp_path):
    clock = FixedClock(NOW)
    runner = _runner(tmp_path, clock)
    pairs = runner.run(
        plan_document(), grant(expires_at=NOW), ScriptedExecutor()
    )
    assert pairs[0].error == f"grant_expired: grant expired at {NOW}"


def test_grant_bound_to_a_different_plan_fails_closed(tmp_path):
    runner = _runner(tmp_path)
    pairs = runner.run(
        plan_document(), grant(), ScriptedExecutor(),
        plan_digest="sha256:" + "9" * 64,
    )
    assert pairs[0].error == (
        "grant_plan_mismatch: grant authorizes plan "
        "'sha256:" + "2" * 64 + "', not 'sha256:" + "9" * 64 + "'"
    )
    assert pairs[0].baseline is None
    assert pairs[0].treatment is None


def test_grant_bound_to_the_same_plan_runs(tmp_path):
    runner = _runner(tmp_path)
    pairs = runner.run(
        plan_document(), grant(), ScriptedExecutor(),
        plan_digest="sha256:" + "2" * 64,
    )
    assert pairs[0].error is None
    assert pairs[0].treatment is not None


def test_conflicting_selector_seeds_are_rejected(tmp_path):
    """The Run contract carries exactly one target selection seed."""
    plan = plan_document()
    plan["selectors"].append(
        {
            "selected": ["tgt_4a5b6c7d8e9f0a1b"],
            "excluded": [],
            "recorded_seed": 99999999,
            "mode": "isolated_reexecution",
            "tenant_id": "tnt_9d4c1e2a3b4f5c67",
        }
    )
    with pytest.raises(ValueError, match="conflicting"):
        _run(tmp_path, plan=plan)


def test_surviving_workspace_is_never_labeled_clean(tmp_path):
    """A release that leaves the workspace behind is UNKNOWN (AC-022)."""

    class LeakyEnvironment(Environment):
        def release(self) -> bool:
            return False  # workspace survived

    class LeakyEnvironments(LocalFixtureEnvironments):
        def provision(self) -> Environment:
            provisioned = super().provision()
            return LeakyEnvironment(
                instance_id=provisioned.instance_id,
                root=provisioned.root,
            )

    environments = LeakyEnvironments()
    runner = FixtureRunner(environments, clock=FixedClock())
    pairs = runner.run(
        plan_document(), grant(), ScriptedExecutor(), bundle=BUNDLE
    )
    for run in (pairs[0].baseline, pairs[0].treatment):
        assert run["terminal_state"] == "UNKNOWN"


# Export.


def test_export_carries_fingerprints_and_pairs(tmp_path):
    pairs = _run(tmp_path)
    document = build_export(
        plan_document(), pairs,
        plan_digest="sha256:" + "3" * 64,
        exported_at=NOW,
    )
    assert document["workload_fingerprint"] == "sha256:" + "1" * 64
    assert document["plan_digest"] == "sha256:" + "3" * 64
    assert document["profiles"] == {
        "baseline": "aup_1a2b3c4d5e6f7081",
        "treatment": "aup_5b8d2e0f1a3c4966",
    }
    assert document["pairs"][0]["injection_triggered"] is True
    assert document["pairs"][0]["baseline_run"]["variant"] == "baseline"


def test_write_export_round_trips(tmp_path):
    pairs = _run(tmp_path)
    target = write_export(
        build_export(
            plan_document(), pairs,
            plan_digest="sha256:" + "3" * 64, exported_at=NOW,
        ),
        tmp_path / "out" / "pairs.json",
    )
    loaded = json.loads(target.read_text(encoding="utf-8"))
    assert loaded["kind"] == "PairedRunExport"
    assert loaded["pairs"][0]["pair_id"] == "pair-0-0"


# Integration with the real compiler output.


def test_runs_from_a_real_compiled_plan(tmp_path):
    """A CompiledPlan from compile_manifest drives the runner directly."""
    from acx_compiler import (
        Ed25519Signer,
        MemoryResourceStore,
        compile_manifest,
    )
    from conftest import FIXTURE_DIR, TENANT

    def load(name):
        return json.loads(
            (FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8")
        )

    experiment = load("experiment")
    experiment["status"] = "draft"
    experiment.pop("plan", None)

    # A baseline arm derived from the treatment profile, mirroring
    # the control-plane fixtures.
    baseline = load("autonomy-profile")
    baseline["id"] = "aup_1a2b3c4d5e6f7081"
    baseline["name"] = "hard-controls-only"
    baseline["version"] = "1.0.0"
    baseline.pop("supersedes", None)
    baseline.pop("description", None)
    baseline["controls"]["allowed_action_classes"] = ["A0", "A1"]
    baseline["supervision"]["contextual_reviewer"]["enabled"] = False

    def enrolled(target_id):
        record = load("target")
        record["id"] = target_id
        return record

    store = MemoryResourceStore(
        workloads=[load("workload-version")],
        profiles=[baseline, load("autonomy-profile")],
        scenarios=[load("scenario-version")],
        # The selector selects one target and excludes another; both
        # must resolve.
        targets=[
            enrolled("tgt_4a5b6c7d8e9f0a1b"),
            enrolled("tgt_0f1e2d3c4b5a6978"),
        ],
        credentials=[
            {
                "kind": "Credential",
                "id": "cred_fixture-github-token",
                "tenant_id": TENANT,
                "credential_kind": "fixture-github-token",
                "refreshed_at": "2026-09-11T20:30:00Z",
            },
            {
                "kind": "Credential",
                "id": "cred_model-gateway",
                "tenant_id": TENANT,
                "credential_kind": "model-gateway",
                "refreshed_at": "2026-09-11T20:45:00Z",
            },
        ],
    )
    result = compile_manifest(
        experiment, store, now=NOW,
        signer=Ed25519Signer.generate("key_grants-2026q3"),
    )
    runner = _runner(tmp_path)
    pairs = runner.run(
        result.plan_document, result.grant, ScriptedExecutor(), bundle=BUNDLE
    )
    assert pairs[0].error is None
    assert pairs[0].baseline["tenant_id"] == TENANT  # from the grant
    validate(pairs[0].baseline, "Run")
    validate(pairs[0].treatment, "Run")
    export = build_export(
        result.plan_document, pairs,
        plan_digest=result.plan_digest, exported_at=NOW,
    )
    assert export["workload_fingerprint"] == (
        result.plan_document["workload"]["fingerprint"]
    )
