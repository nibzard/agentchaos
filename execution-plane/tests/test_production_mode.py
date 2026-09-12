"""Production synthetic mode (T049, spec 7 and 13.4, AC-031).

Admission fails closed on every requirement the spec names: verified
enrollment, the isolated and integration gates, registered
primitives, cost limits, and known effect sinks. Authorization
re-checks enrollment immediately before each injection. The kill path
is independent of the session. Cleanup is verified independently, and
synthetic sessions stay out of customer statistics.
"""

from __future__ import annotations

import pytest

from gauntlet_runner import FixtureRunner, LocalFixtureEnvironments
from gauntlet_scenarios import (
    CLEAN,
    DIRTY_QUARANTINED,
    UNKNOWN,
    Enrollment,
    PrimitiveRegistry,
    ProductionRefusal,
    ProductionSyntheticMode,
    RecordingProductionPath,
    SinkCleanupVerifier,
    build_scenario_version,
    get_template,
    release,
    separate_statistics,
    sign_release,
    validate_isolated,
    Ed25519ReleaseSigner,
)
from gauntlet_scenarios.lifecycle import plan_digest, validation_plan
from conftest import FixedClock, grant

TENANT = "tnt_9d4c1e2a3b4f5c67"
IDENTITY = "syn_production0001"
TARGET = "tgt_repository001"
TARGET2 = "tgt_queue00000001"
SINK = "sink_results001"
DESTINATION = "queue://synthetic/results"
TARGET_CLASS = "synthetic-repo"
FINGERPRINT = "sha256:" + "7" * 64


def _runner(tmp_path):
    state = {"n": 0}

    def root_factory(prefix=None, dir=None):  # noqa: ARG001
        state["n"] += 1
        return str(tmp_path / f"ws-{state['n']:03d}")

    environments = LocalFixtureEnvironments(
        id_factory=lambda: f"env_prd-{state['n']:012d}",
        root_factory=root_factory,
    )
    counter = iter(range(2000))
    return FixtureRunner(
        environments,
        clock=FixedClock(),
        run_id_factory=lambda: "run_" + f"{next(counter):016d}",
    )


def _grant_for(scenario):
    issued = dict(grant())
    issued["plan_digest"] = plan_digest(validation_plan(scenario))
    return issued


def _released(tmp_path, template_id="F01", *, eligible=True):
    scenario = build_scenario_version(
        get_template(template_id),
        tenant_id=TENANT,
        created_at="2026-09-11T21:00:00Z",
    )
    validate_isolated(
        scenario, runner=_runner(tmp_path), grant=_grant_for(scenario)
    )
    signer = Ed25519ReleaseSigner.generate("key_scenarios-2026q3")
    sign_release(scenario, signer)
    release(
        scenario,
        signer,
        classifications=[
            {
                "mode": "isolated_reexecution",
                "target_class": TARGET_CLASS,
                "primitive_version": "1.0.0",
                "eligible": True,
            },
            {
                "mode": "production_synthetic",
                "target_class": TARGET_CLASS,
                "primitive_version": "1.0.0",
                "eligible": eligible,
            },
        ],
    )
    return scenario


def _enrollment():
    enrollment = Enrollment()
    enrollment.enroll_identity(
        IDENTITY, tenant_id=TENANT, budget_effects=8
    )
    enrollment.enroll_target(
        TARGET,
        tenant_id=TENANT,
        destination=DESTINATION,
        sink=SINK,
        target_class=TARGET_CLASS,
    )
    return enrollment


def _mode(tmp_path, *, eligible=True):
    scenario = _released(tmp_path, eligible=eligible)
    enrollment = _enrollment()
    primitives = PrimitiveRegistry()
    primitives.register(scenario["fault"]["kind"], "1.0.0")
    mode = ProductionSyntheticMode(
        enrollment=enrollment,
        primitives=primitives,
        path=RecordingProductionPath(),
    )
    return mode, scenario


def _request(scenario, **overrides):
    request = {
        "kind": "ProductionSyntheticRequest",
        "api_version": "v1",
        "tenant_id": TENANT,
        "scenario": scenario,
        "identity": IDENTITY,
        "targets": [TARGET],
        "sinks": [SINK],
        "primitive_version": "1.0.0",
        "workload_fingerprint": FINGERPRINT,
        "integration_evidence": {
            "suite": "integration",
            "passed": True,
            "workload_fingerprint": FINGERPRINT,
        },
        "cost_limit": {"max_injections": 3, "max_effects": 3},
    }
    request.update(overrides)
    return request


def _run_one(mode, scenario):
    """Admit, inject once, deliver, stop; return (session, report)."""
    session = mode.admit(_request(scenario))
    session.deliver_fault(session.begin_injection(TARGET))
    return session, session.stop()


# --- a full session passes every AC-031 gate ---------------------------


def test_a_clean_session_passes_all_three_gates(tmp_path):
    mode, scenario = _mode(tmp_path)
    session, report = _run_one(mode, scenario)
    assert report["terminal_state"] == CLEAN
    assert report["population"] == "production_synthetic"
    assert report["cleanup"]["verifier"] == "sink-cleanup-verifier"
    assessment = mode.assess(session.session_id)
    assert assessment["passed"] is True
    assert set(assessment["gates"]) == {"isolation", "kill", "cleanup"}
    assert all(gate["passed"] for gate in assessment["gates"].values())


# --- admission fails closed ---------------------------------------------


def test_a_draft_scenario_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    scenario["status"] = "draft"
    with pytest.raises(ProductionRefusal, match="released"):
        mode.admit(_request(scenario))


def test_a_scenario_without_a_valid_classification_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path, eligible=False)
    with pytest.raises(ProductionRefusal, match="not_eligible"):
        mode.admit(_request(scenario))


def test_a_stale_classification_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    mode.primitives.register(scenario["fault"]["kind"], "2.0.0")
    with pytest.raises(ProductionRefusal, match="stale"):
        mode.admit(_request(scenario, primitive_version="2.0.0"))


def test_an_unregistered_primitive_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    mode.primitives._registered.clear()
    with pytest.raises(ProductionRefusal, match="not a registered"):
        mode.admit(_request(scenario))


def test_an_unenrolled_identity_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    with pytest.raises(ProductionRefusal, match="identity"):
        mode.admit(_request(scenario, identity="syn_nobody00000001"))


def test_a_non_synthetic_identity_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    with pytest.raises(ProductionRefusal, match="dedicated synthetic"):
        mode.admit(_request(scenario, identity="wrk_worker00000001"))


def test_enrollment_refuses_non_synthetic_identities():
    enrollment = Enrollment()
    with pytest.raises(ProductionRefusal, match="dedicated synthetic"):
        enrollment.enroll_identity(
            "wrk_worker00000001", tenant_id=TENANT, budget_effects=4
        )


def test_an_unenrolled_target_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    with pytest.raises(ProductionRefusal, match="not enrolled"):
        mode.admit(_request(scenario, targets=["tgt_stranger00001"]))


def test_an_undeclared_sink_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    request = _request(scenario, sinks=["sink_other0000001"])
    with pytest.raises(ProductionRefusal, match="did not declare"):
        mode.admit(request)


def test_a_cross_tenant_target_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    mode.enrollment.enroll_target(
        TARGET2,
        tenant_id="tnt_0000000000000001",
        destination="topic://other/queue",
        sink="sink_results001",
        target_class=TARGET_CLASS,
    )
    with pytest.raises(ProductionRefusal, match="another tenant"):
        mode.admit(_request(scenario, targets=[TARGET2]))


def test_missing_integration_evidence_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    with pytest.raises(ProductionRefusal, match="integration gate"):
        mode.admit(_request(scenario, integration_evidence={
            "suite": "integration", "passed": False,
            "workload_fingerprint": FINGERPRINT,
        }))


def test_evidence_bound_to_another_workload_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    with pytest.raises(ProductionRefusal, match="workload fingerprint"):
        mode.admit(_request(scenario, integration_evidence={
            "suite": "integration", "passed": True,
            "workload_fingerprint": "sha256:" + "1" * 64,
        }))


def test_unknown_request_fields_are_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    request = _request(scenario)
    request["escalate"] = True
    with pytest.raises(ProductionRefusal, match="unknown fields"):
        mode.admit(request)


def test_unlimited_cost_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    with pytest.raises(ProductionRefusal, match="positive bound"):
        mode.admit(_request(scenario, cost_limit={
            "max_injections": 0, "max_effects": 3,
        }))


def test_exceeding_the_identity_budget_is_refused(tmp_path):
    mode, scenario = _mode(tmp_path)
    with pytest.raises(ProductionRefusal, match="identity budget"):
        mode.admit(_request(scenario, cost_limit={
            "max_injections": 3, "max_effects": 99,
        }))


def test_enrollment_refuses_wildcard_destinations():
    enrollment = Enrollment()
    with pytest.raises(ProductionRefusal, match="wildcard"):
        enrollment.enroll_target(
            "tgt_public0000001",
            tenant_id=TENANT,
            destination="queue://public/*",
            sink=SINK,
            target_class=TARGET_CLASS,
        )


def test_enrollment_refuses_unknown_destination_schemes():
    enrollment = Enrollment()
    with pytest.raises(ProductionRefusal, match="known scheme"):
        enrollment.enroll_target(
            "tgt_public0000001",
            tenant_id=TENANT,
            destination="https://example.com/anything",
            sink=SINK,
            target_class=TARGET_CLASS,
        )


# --- authorization re-checks before every injection ---------------------


def test_a_target_revoked_mid_session_blocks_the_next_injection(tmp_path):
    mode, scenario = _mode(tmp_path)
    session = mode.admit(_request(scenario))
    session.deliver_fault(session.begin_injection(TARGET))
    mode.enrollment.revoke_target(TARGET)
    with pytest.raises(ProductionRefusal, match="no longer enrolled"):
        session.begin_injection(TARGET)


def test_a_revoked_identity_blocks_the_next_injection(tmp_path):
    mode, scenario = _mode(tmp_path)
    session = mode.admit(_request(scenario))
    mode.enrollment.revoke_identity(IDENTITY)
    with pytest.raises(ProductionRefusal, match="no longer enrolled"):
        session.begin_injection(TARGET)


def test_a_target_outside_the_admitted_set_is_refused(tmp_path):
    """Selector expansion: enrollment alone is not admission."""
    mode, scenario = _mode(tmp_path)
    mode.enrollment.enroll_target(
        TARGET2,
        tenant_id=TENANT,
        destination="topic://synthetic/other",
        sink="sink_results002",
        target_class=TARGET_CLASS,
    )
    session = mode.admit(_request(scenario))
    with pytest.raises(ProductionRefusal, match="outside the admitted"):
        session.begin_injection(TARGET2)


def test_the_injection_budget_is_enforced(tmp_path):
    mode, scenario = _mode(tmp_path)
    session = mode.admit(_request(scenario, cost_limit={
        "max_injections": 1, "max_effects": 3,
    }))
    session.deliver_fault(session.begin_injection(TARGET))
    with pytest.raises(ProductionRefusal, match="injection budget"):
        session.begin_injection(TARGET)


def test_the_effect_budget_is_enforced(tmp_path):
    mode, scenario = _mode(tmp_path)
    session = mode.admit(_request(scenario, cost_limit={
        "max_injections": 3, "max_effects": 1,
    }))
    session.deliver_fault(session.begin_injection(TARGET))
    with pytest.raises(ProductionRefusal, match="effect budget"):
        session.begin_injection(TARGET)


# --- the independent kill ------------------------------------------------


def test_kill_stops_the_session_and_the_report_records_it(tmp_path):
    mode, scenario = _mode(tmp_path)
    session = mode.admit(_request(scenario))
    session.deliver_fault(session.begin_injection(TARGET))
    report = mode.kill(session.session_id, "operator stop")
    assert report["killed"] is True
    assert report["reason"] == "killed: operator stop"
    with pytest.raises(ProductionRefusal, match="killed"):
        session.begin_injection(TARGET)


def test_kill_needs_no_cooperation_from_the_session(tmp_path):
    """The kill actuates on mode state alone; the handle is gone."""
    mode, scenario = _mode(tmp_path)
    session = mode.admit(_request(scenario))
    session_id = session.session_id
    session.deliver_fault(session.begin_injection(TARGET))
    del session  # the session is unreachable, like a dead worker
    report = mode.kill(session_id, "unreachable session")
    assert report["killed"] is True
    assert mode.kill_gate(session_id)["passed"] is True


def test_a_disarmed_kill_path_fails_the_gate(tmp_path):
    mode, scenario = _mode(tmp_path)
    session, _report = _run_one(mode, scenario)
    mode.kill_path.disarm()
    assert mode.kill_gate(session.session_id)["passed"] is False
    mode.kill_path.arm()
    assert mode.kill_gate(session.session_id)["passed"] is True


def test_a_killed_session_can_still_assess_clean(tmp_path):
    mode, scenario = _mode(tmp_path)
    session = mode.admit(_request(scenario))
    session.deliver_fault(session.begin_injection(TARGET))
    mode.kill(session.session_id, "operator stop")
    assert mode.assess(session.session_id)["passed"] is True


# --- containment and cleanup --------------------------------------------


def test_an_effect_outside_the_declared_sinks_kills_and_quarantines(
    tmp_path,
):
    mode, scenario = _mode(tmp_path)
    session = mode.admit(_request(scenario))
    authorization = session.begin_injection(TARGET)
    with pytest.raises(ProductionRefusal, match="containment breach"):
        session.deliver_fault(
            authorization, sink="sink_undeclared01"
        )
    report = mode.report(session.session_id)
    assert report["killed"] is True
    assert report["terminal_state"] == DIRTY_QUARANTINED
    assert report["cleanup"]["quarantined"]
    assessment = mode.assess(session.session_id)
    assert assessment["gates"]["cleanup"]["passed"] is False
    assert assessment["gates"]["isolation"]["passed"] is False


def test_a_quarantined_effect_is_never_drained_or_reassigned():
    path = RecordingProductionPath()
    effect = path.deliver("sxn_test0000000001", "sink_results001", {})
    path.quarantine(effect["effect_id"])
    assert path.drain(effect["effect_id"]) is False
    quarantined = path.inventory("sxn_test0000000001")[0]
    assert quarantined["state"] == "quarantined"


def test_cleanup_is_verified_by_the_independent_verifier(tmp_path):
    mode, scenario = _mode(tmp_path)
    session, report = _run_one(mode, scenario)
    assert report["cleanup"]["verifier"] == SinkCleanupVerifier().name
    assert report["drained"] == [
        effect["effect_id"] for effect in report["effects"]
    ]
    assert report["terminal_state"] == CLEAN


def test_a_late_effect_reopens_the_result(tmp_path):
    mode, scenario = _mode(tmp_path)
    session, report = _run_one(mode, scenario)
    assert report["terminal_state"] == CLEAN
    # A late delivery bypasses the mode and lands in the path anyway.
    mode.path.deliver(session.session_id, SINK, {"late": True})
    reopened = mode.report(session.session_id)
    assert reopened["reopened_by_late_effect"] is True
    assert reopened["terminal_state"] == UNKNOWN
    assert mode.cleanup_gate(session.session_id)["passed"] is False


# --- statistical separation ---------------------------------------------


def test_synthetic_sessions_stay_out_of_customer_statistics(tmp_path):
    mode, scenario = _mode(tmp_path)
    _session, report = _run_one(mode, scenario)
    buckets = separate_statistics(
        [report],
        customer_events=[
            {"session_id": "sxn_customer00001", "event": "effect"},
        ],
    )
    assert buckets["synthetic"]["sessions"] == 1
    assert buckets["customer"]["events"] == 1
    assert buckets["shared_resource_impact"]["measured_separately"] is True


def test_a_synthetic_session_in_the_customer_population_is_refused(
    tmp_path,
):
    mode, scenario = _mode(tmp_path)
    _session, report = _run_one(mode, scenario)
    with pytest.raises(ProductionRefusal, match="separate"):
        separate_statistics(
            [report],
            customer_events=[
                {"session_id": report["session_id"], "event": "effect"},
            ],
        )


def test_a_report_without_a_population_marker_is_refused(tmp_path):
    with pytest.raises(ProductionRefusal, match="population"):
        separate_statistics(
            [{"session_id": "sxn_stray00000001"}],
            customer_events=[],
        )
