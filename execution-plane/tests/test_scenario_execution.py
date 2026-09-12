"""Template execution through the fixture runner (spec 12, 9.2)."""

from __future__ import annotations

import pytest
from acx_schemas import validate

from acx_runner import FixtureRunner, LocalFixtureEnvironments
from acx_scenarios import (
    TEMPLATE_IDS,
    LibraryExecutor,
    build_scenario_version,
    get_template,
    verify_outcomes,
    worst,
)
from acx_scenarios.assertions import FAILED, PASSED, UNKNOWN
from conftest import NOW, FixedClock, grant

TENANT = "tnt_9d4c1e2a3b4f5c67"


def _runner(tmp_path):
    state = {"n": 0}

    def root_factory(prefix=None, dir=None):  # noqa: ARG001
        state["n"] += 1
        return str(tmp_path / f"ws-{state['n']:03d}")

    environments = LocalFixtureEnvironments(
        id_factory=lambda: f"env_scn-{state['n']:012d}",
        root_factory=root_factory,
    )
    counter = iter(range(2000))
    return FixtureRunner(
        environments,
        clock=FixedClock(),
        run_id_factory=lambda: "run_" + f"{next(counter):016d}",
    )


def _plan_for(template):
    document = build_scenario_version(
        template, tenant_id=TENANT, created_at=NOW
    )
    plan = {
        "kind": "CompiledPlan",
        "api_version": "v1",
        "experiment_id": "exp_2e7b4d1c8a3f5092",
        "tenant_id": TENANT,
        "workload": {
            "id": "wlv_3f9a1c2d4e5b6071",
            "name": "library-fixture",
            "version": "1.0.0",
            "fingerprint": "sha256:" + "3" * 64,
            "backend": "local_container",
        },
        "profiles": {
            "baseline": {"id": "aup_1a2b3c4d5e6f7081", "version": "1.0.0"},
            "treatment": {"id": "aup_5b8d2e0f1a3c4966", "version": "2.0.0"},
        },
        "scenarios": [
            {
                "id": document["id"],
                "template_id": document["template_id"],
                "version": document["version"],
            }
        ],
        "selectors": [],
    }
    return plan, document


@pytest.mark.parametrize("template_id", TEMPLATE_IDS)
def test_every_template_runs_a_pair(tmp_path, template_id):
    template = get_template(template_id)
    plan, _ = _plan_for(template)
    executor = LibraryExecutor()  # defense holds
    pairs = _runner(tmp_path).run(
        plan, grant(), executor, bundle=dict(template.fixture)
    )
    assert len(pairs) == 1
    pair = pairs[0]
    assert pair.error is None, template_id
    assert pair.baseline is not None and pair.treatment is not None
    validate(pair.baseline, "Run")
    validate(pair.treatment, "Run")
    # Identical installed baseline (AC-003): the fault is injected
    # after install, from outside the worker.
    assert pair.identical_baseline, template_id
    assert pair.injection_triggered is True, template_id
    baseline_states = [
        entry["trigger_state"] for entry in pair.baseline["injections"]
    ]
    assert baseline_states == ["not_triggered"], template_id


@pytest.mark.parametrize("template_id", TEMPLATE_IDS)
def test_hold_scripts_pass_every_assertion(tmp_path, template_id):
    template = get_template(template_id)
    executor = LibraryExecutor()
    outcome = executor.execute(_spec_for(template, "treatment", tmp_path))
    verdicts = verify_outcomes(template, outcome.observations)
    assert all(v.verdict == PASSED for v in verdicts), [
        (v.assertion_id, v.verdict, v.note) for v in verdicts
    ]
    assert worst(verdicts) == PASSED


@pytest.mark.parametrize("template_id", TEMPLATE_IDS)
def test_break_scripts_fail_at_least_one_assertion(tmp_path, template_id):
    template = get_template(template_id)
    executor = LibraryExecutor(defense="break")
    outcome = executor.execute(_spec_for(template, "treatment", tmp_path))
    verdicts = verify_outcomes(template, outcome.observations)
    failing = [v for v in verdicts if v.verdict == FAILED]
    assert failing, [
        (v.assertion_id, v.verdict, v.note) for v in verdicts
    ]
    assert worst(verdicts) == FAILED


@pytest.mark.parametrize("template_id", TEMPLATE_IDS)
def test_benign_scripts_pass_every_assertion(tmp_path, template_id):
    template = get_template(template_id)
    executor = LibraryExecutor()
    outcome = executor.execute(_spec_for(template, "baseline", tmp_path))
    verdicts = verify_outcomes(template, outcome.observations)
    assert all(v.verdict == PASSED for v in verdicts), [
        (v.assertion_id, v.verdict, v.note) for v in verdicts
    ]
    assert outcome.injections[0]["trigger_state"] == "not_triggered"


def test_break_runs_through_the_runner_still_produce_run_documents(tmp_path):
    template = get_template("F05")
    plan, _ = _plan_for(template)
    executor = LibraryExecutor(defense="break")
    pairs = _runner(tmp_path).run(
        plan, grant(), executor, bundle=dict(template.fixture)
    )
    assert pairs[0].error is None
    assert pairs[0].injection_triggered is True
    # The false-success break keeps the deploy receipt absent: the
    # state probe fails, the receipt assertion reads unknown.
    verdicts = verify_outcomes(
        template, pairs[0].treatment_observations
    )
    by_id = {v.assertion_id: v for v in verdicts}
    assert by_id["asm_f05_state_verified"].verdict == FAILED
    assert by_id["asm_f05_receipt_matches_state"].verdict == UNKNOWN
    assert worst(verdicts) == FAILED


def test_file_family_faults_change_only_the_treatment_workspace(tmp_path):
    template = get_template("F06")
    assert template.fault_files
    plan, _ = _plan_for(template)
    executor = LibraryExecutor()
    pairs = _runner(tmp_path).run(
        plan, grant(), executor, bundle=dict(template.fixture)
    )
    injected = [
        (scenario_id, path)
        for scenario_id, path in executor.applied_faults
    ]
    assert injected, "the adapter never applied the fault files"
    assert all(
        path in template.fault_files for _, path in injected
    )
    assert len(executor.executed) == 2
    assert pairs[0].identical_baseline


def test_duplicate_external_effect_fails_the_receipt_assertion(tmp_path):
    template = get_template("F16")
    executor = LibraryExecutor(defense="break")
    outcome = executor.execute(_spec_for(template, "treatment", tmp_path))
    verdicts = {
        v.assertion_id: v for v in verify_outcomes(template, outcome.observations)
    }
    assert verdicts["asm_f16_single_issue"].verdict == FAILED
    assert "duplicated" in verdicts["asm_f16_single_issue"].note


def test_refused_receipt_for_a_forbidden_effect_passes(tmp_path):
    template = get_template("F08")
    executor = LibraryExecutor()
    outcome = executor.execute(_spec_for(template, "treatment", tmp_path))
    verdicts = {
        v.assertion_id: v for v in verify_outcomes(template, outcome.observations)
    }
    assert verdicts["asm_f08_no_credential_use"].verdict == PASSED


def _spec_for(template, arm, tmp_path):
    """A minimal VariantSpec for direct executor calls."""
    from acx_runner.runner import VariantSpec

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    document = build_scenario_version(
        template, tenant_id=TENANT, created_at=NOW
    )
    return VariantSpec(
        experiment_id="exp_2e7b4d1c8a3f5092",
        tenant_id=TENANT,
        arm=arm,
        scenario={
            "id": document["id"],
            "template_id": template.template_id,
            "version": document["version"],
        },
        profile={"id": "aup_1a2b3c4d5e6f7081"},
        workload={"id": "wlv_3f9a1c2d4e5b6071"},
        target_selection_seed=0,
        workspace=workspace,
        now=NOW,
    )
