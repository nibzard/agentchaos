"""Compiler behavior: the happy path compiles; everything else fails closed."""

import copy

import pytest
from gauntlet_schemas import ContractViolation, validate

from gauntlet_compiler import CompileViolation, compile_manifest, verify_signature

from conftest import (
    NOW,
    OTHER_TENANT,
    _target,
    build_store,
    draft_experiment,
    load_fixture,
    make_signer,
)


def _codes(exc: CompileViolation) -> set[str]:
    return {entry.code for entry in exc.entries}


def _compile(experiment, store=None, **kwargs):
    return compile_manifest(
        experiment, store or build_store(), now=NOW, signer=make_signer(), **kwargs
    )


def test_happy_path_compiles():
    result = _compile(draft_experiment())

    assert result.risk_classification == "moderate"  # treatment arm allows A2
    assert len(result.artifact_digests) == 4  # workload, two profiles, scenario
    assert result.plan_document["workload"]["backend"] == "local_container"
    assert result.plan_document["selectors"][0]["selected"] == [
        "tgt_4a5b6c7d8e9f0a1b"
    ]
    assert result.grant["expires_at"] == "2026-09-11T21:05:00Z"


def test_compiled_experiment_validates_against_contract():
    experiment = draft_experiment()
    result = _compile(experiment)

    experiment["status"] = "compiled"
    experiment["plan"] = result.plan_block()
    validate(experiment, "Experiment")


def test_plan_block_carries_exactly_the_contract_fields():
    result = _compile(draft_experiment())
    assert set(result.plan_block()) == {
        "plan_digest",
        "artifact_digests",
        "risk_classification",
        "signed_grant",
    }


def test_plan_digest_is_deterministic():
    first = _compile(draft_experiment())
    second = _compile(draft_experiment())
    assert first.plan_digest == second.plan_digest
    assert first.artifact_digests == second.artifact_digests


def test_time_lives_only_in_the_grant():
    first = _compile(draft_experiment())
    later = compile_manifest(
        draft_experiment(), build_store(), now="2026-09-11T21:10:00Z",
        signer=make_signer(),
    )
    assert first.plan_digest == later.plan_digest
    assert first.grant["issued_at"] != later.grant["issued_at"]


def test_grant_signature_verifies():
    result, signer = _compile_with_signer()
    assert verify_signature(
        signer.public_key_bytes(),
        _canonical_grant(result),
        result.signed_grant["value"],
    )


def test_tampered_grant_fails_verification():
    result, signer = _compile_with_signer()
    assert not verify_signature(
        signer.public_key_bytes(),
        _canonical_grant(result) + b"x",
        result.signed_grant["value"],
    )


def _compile_with_signer():
    signer = make_signer()
    result = compile_manifest(
        draft_experiment(), build_store(), now=NOW, signer=signer
    )
    return result, signer


def _canonical_grant(result):
    from gauntlet_compiler.canonical import canonical_bytes

    return canonical_bytes(result.grant)


# Reference resolution fails closed.


def test_unknown_workload_rejected():
    experiment = draft_experiment()
    experiment["manifest"]["workload_version_id"] = "wlv_0000000000000000"
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "unknown_reference" in _codes(excinfo.value)


def test_mode_not_supported_by_workload_rejected():
    experiment = draft_experiment()
    experiment["manifest"]["mode"] = "govern"
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "mode_not_supported" in _codes(excinfo.value)


def test_hardened_backend_required_for_production_modes():
    workload = load_fixture("workload-version")
    workload["supported_modes"] = [
        "observe",
        "replay",
        "isolated_reexecution",
        "production_synthetic",
    ]
    experiment = draft_experiment()
    experiment["manifest"]["mode"] = "production_synthetic"
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment, build_store(workloads=[workload]))
    assert "backend_not_supported" in _codes(excinfo.value)


def test_draft_profile_rejected():
    profiles = []
    for profile in (load_fixture("autonomy-profile"),):
        profile["status"] = "draft"
        profiles.append(profile)
    # Rebuild the store so both profiles exist; treatment is draft now.
    from conftest import _baseline_profile

    store = build_store(profiles=[_baseline_profile(), profiles[0]])
    with pytest.raises(CompileViolation) as excinfo:
        _compile(draft_experiment(), store)
    assert "profile_not_published" in _codes(excinfo.value)


def test_unreleased_scenario_rejected():
    scenario = load_fixture("scenario-version")
    scenario["status"] = "signed"
    scenario.pop("mode_eligibility", None)
    with pytest.raises(CompileViolation) as excinfo:
        _compile(draft_experiment(), build_store(scenarios=[scenario]))
    assert "scenario_not_released" in _codes(excinfo.value)


def test_scenario_ineligible_for_mode_rejected():
    scenario = load_fixture("scenario-version")
    for entry in scenario["mode_eligibility"]:
        entry["eligible"] = False
    with pytest.raises(CompileViolation) as excinfo:
        _compile(draft_experiment(), build_store(scenarios=[scenario]))
    assert "scenario_not_eligible" in _codes(excinfo.value)


def test_scenario_missing_target_class_entry_rejected():
    targets = [_target(target_class="synthetic-web")]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(draft_experiment(), build_store(targets=targets))
    assert "scenario_not_eligible" in _codes(excinfo.value)


def test_schema_invalid_workload_rejected():
    workload = load_fixture("workload-version")
    del workload["fingerprint"]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(draft_experiment(), build_store(workloads=[workload]))
    assert "record_schema_invalid" in _codes(excinfo.value)


def test_cross_tenant_scenario_rejected():
    scenario = load_fixture("scenario-version")
    scenario["tenant_id"] = "tnt_ffffffffffffffff"
    with pytest.raises(CompileViolation) as excinfo:
        _compile(draft_experiment(), build_store(scenarios=[scenario]))
    assert "tenant_mismatch" in _codes(excinfo.value)


# Selector expansion fails closed.


def test_unenrolled_target_rejected():
    targets = [_target(status="paused")]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(draft_experiment(), build_store(targets=targets))
    assert "target_not_enrolled" in _codes(excinfo.value)


def test_exclusions_emptying_selection_rejected():
    experiment = draft_experiment()
    experiment["manifest"]["selectors"][0]["exclusions"] = [
        "tgt_4a5b6c7d8e9f0a1b"
    ]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "empty_selection" in _codes(excinfo.value)


def test_duplicate_target_across_selectors_rejected():
    experiment = draft_experiment()
    experiment["manifest"]["selectors"].append(
        copy.deepcopy(experiment["manifest"]["selectors"][0])
    )
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "duplicate_target" in _codes(excinfo.value)


# Manifest consistency checks.


def test_stale_credential_rejected():
    experiment = draft_experiment()
    experiment["manifest"]["credentials"]["freshness_max_age_s"] = 60
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "stale_credential" in _codes(excinfo.value)


def test_missing_credential_rejected():
    experiment = draft_experiment()
    experiment["manifest"]["credentials"]["required_kinds"] = ["absent-token"]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "unknown_reference" in _codes(excinfo.value)


def test_budget_contradiction_rejected():
    experiment = draft_experiment()
    budgets = experiment["manifest"]["budgets"]
    budgets["per_session_cost_max"]["micros"] = 999999999
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "budget_contradiction" in _codes(excinfo.value)


def test_missing_stop_rule_threshold_rejected():
    experiment = draft_experiment()
    for rule in experiment["manifest"]["stop_rules"]:
        rule.pop("threshold", None)
        rule["condition"] = "service_health_threshold"
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "missing_threshold" in _codes(excinfo.value)


def test_unsupported_rollback_claim_rejected():
    experiment = draft_experiment()
    experiment["manifest"]["rollback"] = {
        "strategy": "none",
        "compensation_effect_ids": ["compensation-rollback-fixture"],
    }
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "unsupported_rollback" in _codes(excinfo.value)


def test_enrolled_service_sink_in_isolated_mode_rejected():
    experiment = draft_experiment()
    experiment["manifest"]["effect_sinks"][0]["kind"] = "enrolled_service"
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "sink_kind_forbidden" in _codes(excinfo.value)


def test_recording_missing_injection_receipt_rejected():
    experiment = draft_experiment()
    kinds = experiment["manifest"]["recording"]["required_event_kinds"]
    kinds.remove("injection_receipt")
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "recording_missing_required_kind" in _codes(excinfo.value)


def test_unknown_manifest_field_rejected():
    experiment = draft_experiment()
    experiment["manifest"]["ignore_safety"] = True
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "experiment_schema" in _codes(excinfo.value)


def test_customer_canary_exceeds_beta_risk_policy():
    workload = load_fixture("workload-version")
    workload["supported_modes"] = ["customer_canary"]
    workload["environment"]["backend"] = "hardened_microvm"
    experiment = draft_experiment()
    experiment["manifest"]["mode"] = "customer_canary"
    experiment["manifest"]["identities"] = {"kind": "enrolled_opt_in"}
    experiment["manifest"]["effect_sinks"][0]["kind"] = "enrolled_service"
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment, build_store(workloads=[workload]))
    assert "risk_exceeds_policy" in _codes(excinfo.value)


def test_failures_accumulate():
    """One bad manifest reports every failure, not just the first."""
    experiment = draft_experiment()
    experiment["manifest"]["workload_version_id"] = "wlv_0000000000000000"
    experiment["manifest"]["rollback"] = {
        "strategy": "none",
        "compensation_effect_ids": ["compensation-rollback-fixture"],
    }
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    codes = _codes(excinfo.value)
    assert "unknown_reference" in codes
    assert "unsupported_rollback" in codes


# Regression tests for fixes from the compiler conformance review.


def test_selector_without_target_ids_fails_closed():
    """Spec 7, 9.1, AC-002: selectors must resolve to an explicit set.

    The contract leaves target_ids optional, so the compiler must
    reject an absent list, not compile an empty selection.
    """
    experiment = draft_experiment()
    del experiment["manifest"]["selectors"][0]["target_ids"]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "empty_selection" in _codes(excinfo.value)


def test_assertion_evidence_kind_must_be_recorded():
    """Spec 9.1, 9.5: assertions resolve against recording requirements."""
    experiment = draft_experiment()
    experiment["manifest"]["recording"]["required_event_kinds"].remove(
        "tool_response"
    )
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "assertion_not_recorded" in _codes(excinfo.value)


def test_preapproved_rollback_without_operations_rejected():
    experiment = draft_experiment()
    experiment["manifest"]["rollback"] = {"strategy": "preapproved_compensation"}
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "unsupported_rollback" in _codes(excinfo.value)


def test_budget_currency_mismatch_rejected():
    experiment = draft_experiment()
    budgets = experiment["manifest"]["budgets"]
    budgets["aggregate_cost_max"]["currency"] = "EUR"
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "budget_contradiction" in _codes(excinfo.value)


def test_schema_invalid_profile_reported_not_crashed():
    """A malformed profile record is a failure, never a KeyError."""
    profile = load_fixture("autonomy-profile")
    del profile["controls"]
    from conftest import _baseline_profile

    store = build_store(profiles=[_baseline_profile(), profile])
    with pytest.raises(CompileViolation) as excinfo:
        _compile(draft_experiment(), store)
    assert "record_schema_invalid" in _codes(excinfo.value)


def test_credential_without_refresh_stamp_rejected():
    credentials = [
        {
            "kind": "Credential",
            "id": "cred_fixture-github-token",
            "tenant_id": "tnt_9d4c1e2a3b4f5c67",
            "credential_kind": "fixture-github-token",
        },
        {
            "kind": "Credential",
            "id": "cred_model-gateway",
            "tenant_id": "tnt_9d4c1e2a3b4f5c67",
            "credential_kind": "model-gateway",
            "refreshed_at": "2026-09-11T20:45:00Z",
        },
    ]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(draft_experiment(), build_store(credentials=credentials))
    assert "record_schema_invalid" in _codes(excinfo.value)


@pytest.mark.parametrize("resource", ["workloads", "profiles", "scenarios"])
def test_tenant_mismatch_rejected_everywhere(resource):
    """Cross-tenant references fail for every resource kind."""
    experiment = draft_experiment()
    if resource == "workloads":
        workload = load_fixture("workload-version")
        workload["tenant_id"] = "tnt_ffffffffffffffff"
        store = build_store(workloads=[workload])
    elif resource == "profiles":
        profile = load_fixture("autonomy-profile")
        profile["tenant_id"] = "tnt_ffffffffffffffff"
        from conftest import _baseline_profile

        store = build_store(profiles=[_baseline_profile(), profile])
    else:
        scenario = load_fixture("scenario-version")
        scenario["tenant_id"] = "tnt_ffffffffffffffff"
        store = build_store(scenarios=[scenario])
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment, store)
    assert "tenant_mismatch" in _codes(excinfo.value)


def test_tenant_mismatch_target_and_credential_rejected():
    targets = [_target(tenant_id=OTHER_TENANT)]
    credentials = [
        {
            "kind": "Credential",
            "id": "cred_model-gateway",
            "tenant_id": "tnt_9d4c1e2a3b4f5c67",
            "credential_kind": "model-gateway",
            "refreshed_at": "2026-09-11T20:45:00Z",
        },
        {
            "kind": "Credential",
            "id": "cred_fixture-github-token",
            "tenant_id": "tnt_ffffffffffffffff",
            "credential_kind": "fixture-github-token",
            "refreshed_at": "2026-09-11T20:30:00Z",
        },
    ]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(draft_experiment(), build_store(targets=targets,
                                                 credentials=credentials))
    codes = _codes(excinfo.value)
    assert "tenant_mismatch" in codes


def test_unknown_reference_rejected_for_every_resource_kind():
    experiment = draft_experiment()
    experiment["manifest"]["baseline_profile_id"] = "aup_0000000000000000"
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "unknown_reference" in _codes(excinfo.value)

    experiment = draft_experiment()
    experiment["manifest"]["scenario_version_ids"] = ["scn_0000000000000000"]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "unknown_reference" in _codes(excinfo.value)

    experiment = draft_experiment()
    experiment["manifest"]["selectors"][0]["target_ids"] = ["tgt_0000000000000000"]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "unknown_reference" in _codes(excinfo.value)


def test_shared_profile_arms_dedupe_to_one_artifact():
    """Baseline and treatment may share a profile; one artifact entry."""
    from conftest import _baseline_profile

    experiment = draft_experiment()
    experiment["manifest"]["treatment_profile_id"] = "aup_1a2b3c4d5e6f7081"
    result = _compile(experiment, build_store(profiles=[_baseline_profile()]))
    assert len(result.artifact_digests) == 3


def test_artifact_path_collision_rejected():
    """Different records that sanitize to one path are an error.

    Version 1.0.0-a (prerelease) and 1.0.0+a (build metadata) are
    distinct semantic versions but sanitize to the same path segment.
    """
    from conftest import _baseline_profile

    baseline = _baseline_profile()
    baseline["version"] = "1.0.0-a"
    evil = _baseline_profile()
    evil["id"] = "aup_9999999999999999"
    evil["version"] = "1.0.0+a"
    experiment = draft_experiment()
    experiment["manifest"]["treatment_profile_id"] = evil["id"]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment, build_store(profiles=[baseline, evil]))
    assert "artifact_path_collision" in _codes(excinfo.value)


def test_semver_build_metadata_sanitized_into_contract_paths():
    import re

    from conftest import _baseline_profile

    profile = _baseline_profile()
    profile["version"] = "1.0.0+build.7"
    experiment = draft_experiment()
    result = _compile(
        experiment, build_store(profiles=[profile, load_fixture("autonomy-profile")])
    )
    paths = [e["path"] for e in result.artifact_digests]
    assert "profiles/hard-controls-only-1.0.0-build.7.json" in paths
    for path in paths:  # Every path matches the Experiment contract pattern.
        assert re.match(r"^[A-Za-z0-9._/-]{1,512}$", path)


def test_signer_rejects_key_ids_outside_the_contract_pattern():
    from gauntlet_compiler import Ed25519Signer

    with pytest.raises(ValueError):
        Ed25519Signer.generate("Key_Bad")


# Enrollment and selection integration (task T004, AC-002).


def test_target_record_without_enrollment_evidence_rejected():
    """A status string alone no longer makes a target selectable."""
    target = _target()
    del target["enrollment"]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(draft_experiment(), build_store(targets=[target]))
    assert "record_schema_invalid" in _codes(excinfo.value)


def test_unknown_exclusion_rejected():
    """An exclusion naming nothing cannot be verified to exclude."""
    experiment = draft_experiment()
    experiment["manifest"]["selectors"][0]["exclusions"] = [
        "tgt_0000000000000000"
    ]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(experiment)
    assert "unknown_reference" in _codes(excinfo.value)


def _production_workload():
    workload = load_fixture("workload-version")
    workload["supported_modes"] = ["production_synthetic"]
    workload["environment"]["backend"] = "hardened_microvm"
    return workload


def _production_experiment():
    experiment = draft_experiment()
    experiment["manifest"]["mode"] = "production_synthetic"
    experiment["manifest"]["identities"] = {
        "kind": "synthetic_dedicated",
        "max_sessions": 100,
    }
    return experiment


def test_production_synthetic_without_opt_in_rejected():
    targets = [
        _target(opt_in_modes=()),
        _target("tgt_0f1e2d3c4b5a6978"),
    ]
    with pytest.raises(CompileViolation) as excinfo:
        _compile(
            _production_experiment(),
            build_store(workloads=[_production_workload()], targets=targets),
        )
    assert "target_not_opted_in" in _codes(excinfo.value)


def test_production_synthetic_with_opt_in_compiles():
    from gauntlet_compiler import RiskPolicy

    scenario = load_fixture("scenario-version")
    scenario["mode_eligibility"].append(
        {
            "mode": "production_synthetic",
            "target_class": "synthetic-repo",
            "eligible": True,
            "compatibility_evidence_digest": (
                "sha256:" + "a" * 64
            ),
        }
    )
    result = _compile(
        _production_experiment(),
        build_store(
            workloads=[_production_workload()], scenarios=[scenario]
        ),
        policy=RiskPolicy(max_risk="high"),
    )
    assert result.plan_document["selectors"][0]["selected"] == [
        "tgt_4a5b6c7d8e9f0a1b"
    ]


def test_compiled_plan_selectors_feed_revalidation():
    """The plan snapshot is the pre-injection reference (spec 7, 13.2)."""
    from conftest import TENANT

    from gauntlet_compiler import revalidate_selection

    result = _compile(draft_experiment())
    selectors = draft_experiment()["manifest"]["selectors"]
    store = build_store()
    revalidate_selection(
        selectors, result.plan_document["selectors"], store,
        tenant_id=TENANT, mode="isolated_reexecution",
    )
    paused = build_store(targets=[_target(status="paused")])
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            selectors, result.plan_document["selectors"], paused,
            tenant_id=TENANT, mode="isolated_reexecution",
        )
    assert "target_not_enrolled" in _codes(excinfo.value)
