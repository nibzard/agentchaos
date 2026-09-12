"""Contract behavior: valid fixtures pass, hostile or malformed input fails closed."""

import copy
import json

import pytest

from gauntlet_schemas import ContractViolation

from conftest import KIND_TO_FIXTURE

ALL_KINDS = sorted(KIND_TO_FIXTURE)


def _load(kind):
    from conftest import FIXTURE_DIR

    return json.loads((FIXTURE_DIR / KIND_TO_FIXTURE[kind]).read_text(encoding="utf-8"))


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_valid_fixture_passes(registry, valid_instances, kind):
    registry.validate(valid_instances[kind], kind)


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_unknown_top_level_field_rejected(registry, valid_instances, kind):
    """AC-001: unknown fields in security-sensitive payloads fail validation."""
    instance = copy.deepcopy(valid_instances[kind])
    instance["sneaky_extra"] = 1
    with pytest.raises(ContractViolation):
        registry.validate(instance, kind)


@pytest.mark.parametrize(
    "kind,path,value",
    [
        ("WorkloadVersion", ["harness", "unforeseen"], "x"),
        ("AutonomyProfile", ["supervision", "contextual_reviewer", "extra"], 1),
        ("Experiment", ["manifest", "selectors", 0, "wildcard"], "*"),
        ("Run", ["environment", "reused"], True),
        ("Effect", ["proposed_action", "arguments"], {"raw": "object"}),
        ("EvidenceEvent", ["payload", "inline_html"], "<script>"),
        ("AssuranceClaim", ["estimate", "weighted_counts"], [1, 2]),
        ("Target", ["enrollment", "extension"], 1),
    ],
)
def test_unknown_nested_field_rejected(registry, valid_instances, kind, path, value):
    instance = copy.deepcopy(valid_instances[kind])
    node = instance
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    with pytest.raises(ContractViolation):
        registry.validate(instance, kind)


@pytest.mark.parametrize(
    "kind,path",
    [
        ("WorkloadVersion", ["supported_modes", 0]),
        ("AutonomyProfile", ["supervision", "contextual_reviewer", "on_timeout"]),
        ("ScenarioVersion", ["status"]),
        ("Run", ["outcome"]),
        ("Effect", ["state"]),
        ("EvidenceEvent", ["trust_label"]),
        ("AssuranceClaim", ["status"]),
    ],
)
def test_bad_enum_value_rejected(registry, valid_instances, kind, path):
    instance = copy.deepcopy(valid_instances[kind])
    node = instance
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = "DEFINITELY_NOT_AN_ENUM_VALUE"
    with pytest.raises(ContractViolation):
        registry.validate(instance, kind)


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_unknown_api_version_rejected(registry, valid_instances, kind):
    instance = copy.deepcopy(valid_instances[kind])
    instance["api_version"] = "v99"
    with pytest.raises(ContractViolation):
        registry.validate(instance, kind)


@pytest.mark.parametrize("kind", ALL_KINDS)
def test_wrong_kind_rejected(registry, valid_instances, kind):
    instance = copy.deepcopy(valid_instances[kind])
    instance["kind"] = "SomeOtherKind"
    with pytest.raises(ContractViolation):
        registry.validate(instance, kind)


def test_a3_action_class_not_representable_in_profile(registry, valid_instances):
    """Spec 6.1: A3 is not authorized in beta."""
    instance = copy.deepcopy(valid_instances["AutonomyProfile"])
    instance["controls"]["allowed_action_classes"] = ["A0", "A3"]
    with pytest.raises(ContractViolation):
        registry.validate(instance, "AutonomyProfile")


def test_a3_action_class_not_representable_in_effect(registry, valid_instances):
    instance = copy.deepcopy(valid_instances["Effect"])
    instance["action_class"] = "A3"
    with pytest.raises(ContractViolation):
        registry.validate(instance, "Effect")


def test_silent_allow_on_timeout_not_representable(registry, valid_instances):
    """Spec 10.2 and 21: reviewer timeout must hold or deny, never silently allow."""
    instance = copy.deepcopy(valid_instances["AutonomyProfile"])
    instance["supervision"]["contextual_reviewer"]["on_timeout"] = "allow"
    with pytest.raises(ContractViolation):
        registry.validate(instance, "AutonomyProfile")


def test_zero_deep_audit_sample_rate_rejected(registry, valid_instances):
    """AC-017: the sentinel sample must be nonzero when deep audit runs."""
    instance = copy.deepcopy(valid_instances["AutonomyProfile"])
    instance["supervision"]["deep_audit"]["uniform_sample_rate"] = 0
    with pytest.raises(ContractViolation):
        registry.validate(instance, "AutonomyProfile")


# Conditional requirements enforced through if/then.


def _mutated(kind, mutate):
    instance = _load(kind)
    mutate(instance)
    return instance


def test_signed_scenario_requires_signature(registry):
    def mutate(instance):
        del instance["signature"]
        instance["status"] = "signed"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("ScenarioVersion", mutate), "ScenarioVersion")


def test_released_scenario_requires_mode_eligibility(registry):
    def mutate(instance):
        del instance["mode_eligibility"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("ScenarioVersion", mutate), "ScenarioVersion")


def test_compiled_experiment_requires_plan(registry):
    def mutate(instance):
        del instance["plan"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Experiment", mutate), "Experiment")


def test_draft_experiment_needs_no_plan(registry):
    def mutate(instance):
        del instance["plan"]
        instance["status"] = "draft"

    registry.validate(_mutated("Experiment", mutate), "Experiment")


def test_terminal_run_requires_outcome_and_terminal_state(registry):
    def mutate(instance):
        del instance["outcome"]
        del instance["terminal_state"]
        del instance["finished_at"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Run", mutate), "Run")


def test_authorized_effect_requires_authorization(registry):
    def mutate(instance):
        del instance["authorization"]
        instance["state"] = "AUTHORIZED"
        instance["transitions"] = [
            {"state": "PROPOSED", "at": "2026-09-11T20:42:58Z"},
            {"state": "AUTHORIZED", "at": "2026-09-11T20:43:00Z"},
        ]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Effect", mutate), "Effect")


def test_committing_effect_requires_dispatch_record(registry):
    def mutate(instance):
        del instance["dispatch"]
        instance["state"] = "COMMITTING"
        instance["transitions"] = instance["transitions"][:3]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Effect", mutate), "Effect")


def test_compensating_effect_requires_origin(registry):
    def mutate(instance):
        instance["state"] = "COMPENSATING"
        instance["transitions"] = instance["transitions"][:2]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Effect", mutate), "Effect")


def test_object_ref_payload_requires_storage_fields(registry):
    def mutate(instance):
        del instance["payload"]["storage_ref"]
        del instance["payload"]["digest"]
        del instance["payload"]["size_bytes"]
        del instance["payload"]["content_type"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("EvidenceEvent", mutate), "EvidenceEvent")


def test_adjudicated_finding_requires_adjudications(registry):
    def mutate(instance):
        del instance["adjudications"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Finding", mutate), "Finding")


def test_evidence_gap_finding_requires_coverage_gap(registry):
    def mutate(instance):
        instance["category"] = "evidence_gap"
        instance.pop("coverage_gap", None)

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Finding", mutate), "Finding")


def test_stale_claim_requires_reason(registry):
    def mutate(instance):
        instance["status"] = "STALE"
        instance.pop("stale_reason", None)

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("AssuranceClaim", mutate), "AssuranceClaim")


def test_revoked_delegation_requires_timestamp(registry):
    def mutate(instance):
        instance["state"] = "revoked"
        instance.pop("revoked_at", None)

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Delegation", mutate), "Delegation")


# Digest and identifier discipline.


@pytest.mark.parametrize(
    "kind,path",
    [
        ("WorkloadVersion", ["fingerprint"]),
        ("Effect", ["proposed_action", "arguments_digest"]),
        ("EvidenceEvent", ["payload", "digest"]),
        ("AssuranceClaim", ["scope", "fingerprints", "model"]),
    ],
)
def test_malformed_digest_rejected(registry, kind, path):
    def mutate(instance):
        node = instance
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = "md5:deadbeef"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated(kind, mutate), kind)


def test_bad_timestamp_rejected(registry):
    def mutate(instance):
        instance["created_at"] = "2026-09-11 21:00:00"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Run", mutate), "Run")


@pytest.mark.parametrize(
    "kind,path",
    [
        ("Target", ["enrollment", "enrolled_at"]),
    ],
)
def test_bad_resource_timestamp_rejected(registry, kind, path):
    def mutate(instance):
        node = instance
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = "2026-09-01 10:00:00"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated(kind, mutate), kind)


def test_target_id_pattern_enforced(registry):
    def mutate(instance):
        instance["id"] = "target-1"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Target", mutate), "Target")


def test_tenant_id_pattern_enforced(registry):
    def mutate(instance):
        instance["tenant_id"] = "tenant-one"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Finding", mutate), "Finding")


# Regression tests for fixes from the spec-conformance review.


def test_unbounded_permit_rejected(registry):
    """Spec 10, AC-009: a permit must bound a quantity, money or bytes."""

    def mutate(instance):
        del instance["authorization"]["amount_limit"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Effect", mutate), "Effect")


def test_size_limit_alone_satisfies_permit_bound(registry):
    def mutate(instance):
        del instance["authorization"]["amount_limit"]
        instance["authorization"]["size_limit"] = 262144

    registry.validate(_mutated("Effect", mutate), "Effect")


def test_proposed_effect_forbids_authorization(registry):
    """Spec 10: a permit exists only after a decision; a denial cannot carry one."""

    def mutate(instance):
        instance["state"] = "PROPOSED"
        instance["transitions"] = instance["transitions"][:1]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Effect", mutate), "Effect")


def test_committed_after_timeout_requires_reconciled_receipt(registry):
    """Spec 10.1, AC-010: a timeout resolved to COMMITTED needs reconciled evidence."""

    def mutate(instance):
        instance["dispatch"]["outcome"] = "timeout_unknown"
        del instance["receipt"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Effect", mutate), "Effect")


def test_committed_after_timeout_with_unreconciled_receipt_rejected(registry):
    def mutate(instance):
        instance["dispatch"]["outcome"] = "timeout_unknown"
        instance["receipt"]["reconciled"] = False

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Effect", mutate), "Effect")


def test_review_requires_at_least_one_evidence_ref(registry):
    """AC-014: every decision cites evidence."""

    def mutate(instance):
        instance["review"]["event_refs"] = []

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Effect", mutate), "Effect")


def test_nonterminal_run_forbids_terminal_fields(registry):
    def mutate(instance):
        instance["state"] = "running"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Run", mutate), "Run")


def test_pass_over_injections_requires_a_triggered_one(registry):
    """Spec 14.2, AC-018: an untriggered attack is not a successful defense."""

    def mutate(instance):
        instance["injections"][0]["trigger_state"] = "not_triggered"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Run", mutate), "Run")


def test_not_triggered_outcome_forbids_triggered_injection(registry):
    def mutate(instance):
        instance["outcome"] = "NOT_TRIGGERED"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Run", mutate), "Run")


def test_determined_injection_requires_receipt(registry):
    """AC-004: every determined trigger verdict links to receipt evidence."""

    def mutate(instance):
        del instance["injections"][0]["receipt_event_id"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Run", mutate), "Run")


def test_delegation_budget_requires_token_limit(registry):
    def mutate(instance):
        del instance["cumulative_budget"]["max_total_tokens"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Delegation", mutate), "Delegation")


def test_expired_delegation_state_not_representable(registry):
    """Spec 18.1, 13.2: grant expiry is an experiment-grant property, not a state."""

    def mutate(instance):
        instance["state"] = "expired"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Delegation", mutate), "Delegation")


def test_metadata_only_payload_forbids_captured_content(registry):
    """Spec 9.4: a metadata-only event cannot claim a storage reference or body."""

    def mutate(instance):
        instance["payload"]["kind"] = "metadata_only"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("EvidenceEvent", mutate), "EvidenceEvent")


def test_inline_payload_requires_content(registry):
    def mutate(instance):
        instance["payload"]["kind"] = "inline"
        for key in ("storage_ref", "digest", "size_bytes", "content_type"):
            del instance["payload"][key]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("EvidenceEvent", mutate), "EvidenceEvent")


def test_inline_payload_with_content_passes(registry):
    def mutate(instance):
        instance["payload"]["kind"] = "inline"
        for key in ("storage_ref", "digest", "size_bytes", "content_type"):
            del instance["payload"][key]
        instance["payload"]["content"] = "sink accepted exactly one delivery"
        instance["payload"]["tombstone"] = False

    registry.validate(_mutated("EvidenceEvent", mutate), "EvidenceEvent")


def test_inline_payload_forbids_storage_ref(registry):
    def mutate(instance):
        instance["payload"]["kind"] = "inline"
        instance["payload"]["content"] = "sink accepted exactly one delivery"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("EvidenceEvent", mutate), "EvidenceEvent")


def test_tombstone_requires_object_ref_payload(registry):
    """Spec 19: only a stored object can be tombstoned."""

    def mutate(instance):
        instance["payload"]["kind"] = "inline"
        for key in ("storage_ref", "digest", "size_bytes", "content_type"):
            del instance["payload"][key]
        instance["payload"]["content"] = "sink accepted exactly one delivery"
        instance["payload"]["tombstone"] = True

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("EvidenceEvent", mutate), "EvidenceEvent")


def test_collector_event_requires_coverage(registry):
    """Spec 13.2: collector coverage feeds the containment trip condition."""

    def mutate(instance):
        del instance["source"]["coverage"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("EvidenceEvent", mutate), "EvidenceEvent")


def test_serious_finding_requires_outcome_reference(registry):
    """Spec 22.2 B8: serious findings cite an independent outcome reference."""

    def mutate(instance):
        instance["severity"] = "H2"
        del instance["outcome_reference"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Finding", mutate), "Finding")


def test_empty_adjudications_rejected(registry):
    def mutate(instance):
        instance["adjudications"] = []

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Finding", mutate), "Finding")


def test_challenge_set_claim_requires_injection_funnel(registry):
    """Spec 14.2, AC-018: a challenge-set rate reports its funnel."""

    def mutate(instance):
        del instance["provenance"]["injection_funnel"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("AssuranceClaim", mutate), "AssuranceClaim")


def test_clustered_claim_requires_cluster_unit(registry):
    def mutate(instance):
        instance["assumptions"]["dependence_model"] = (
            "clustered_reported_at_cluster_level"
        )
        instance["hazard"]["unit_of_observation"] = "cluster"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("AssuranceClaim", mutate), "AssuranceClaim")


def test_clustered_claim_requires_cluster_unit_of_observation(registry):
    def mutate(instance):
        instance["assumptions"]["dependence_model"] = (
            "clustered_reported_at_cluster_level"
        )
        instance["assumptions"]["cluster_unit"] = "session"
        instance["assumptions"]["cluster_id_refs"] = ["cid_sess_0001"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("AssuranceClaim", mutate), "AssuranceClaim")


def test_clustered_claim_with_full_cluster_fields_passes(registry):
    def mutate(instance):
        instance["assumptions"]["dependence_model"] = (
            "clustered_reported_at_cluster_level"
        )
        instance["hazard"]["unit_of_observation"] = "cluster"
        instance["assumptions"]["cluster_unit"] = "session"
        instance["assumptions"]["cluster_id_refs"] = ["cid_sess_0001"]

    registry.validate(_mutated("AssuranceClaim", mutate), "AssuranceClaim")


def test_profile_budgets_require_tree_token_limit(registry):
    def mutate(instance):
        del instance["controls"]["budgets"]["max_tree_tokens"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("AutonomyProfile", mutate), "AutonomyProfile")


def test_deep_audit_cannot_be_disabled(registry):
    """Spec 15.1, AC-017: the sentinel sample cannot be turned off."""

    def mutate(instance):
        instance["supervision"]["deep_audit"]["enabled"] = False

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("AutonomyProfile", mutate), "AutonomyProfile")


def test_mode_eligibility_entry_requires_target_class(registry):
    """Spec 12.1: eligibility is a property of a primitive version and target class."""

    def mutate(instance):
        del instance["mode_eligibility"][0]["target_class"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("ScenarioVersion", mutate), "ScenarioVersion")


def test_unreleased_scenario_forbids_mode_eligibility(registry):
    def mutate(instance):
        instance["status"] = "draft"
        del instance["signature"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("ScenarioVersion", mutate), "ScenarioVersion")


def test_manifest_requires_identity_declaration(registry):
    """Spec 13.4: synthetic sessions use dedicated bounded identities."""

    def mutate(instance):
        del instance["manifest"]["identities"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Experiment", mutate), "Experiment")


def test_production_synthetic_requires_dedicated_identities(registry):
    def mutate(instance):
        instance["manifest"]["mode"] = "production_synthetic"
        instance["manifest"]["identities"]["kind"] = "enrolled_opt_in"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Experiment", mutate), "Experiment")


def test_customer_canary_requires_enrolled_identities(registry):
    def mutate(instance):
        instance["manifest"]["mode"] = "customer_canary"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Experiment", mutate), "Experiment")


# Target contract (spec 7, 13.1, 13.4, AC-002).


def test_enrolled_target_requires_enrollment_evidence(registry):
    def mutate(instance):
        del instance["enrollment"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Target", mutate), "Target")


def test_paused_target_keeps_enrollment_evidence(registry):
    instance = _mutated("Target", lambda i: i.update(status="paused"))
    registry.validate(instance, "Target")


def test_unenrolled_target_drops_enrollment_evidence(registry):
    def mutate(instance):
        instance["status"] = "unenrolled"
        del instance["enrollment"]
        instance["unenrolled_at"] = "2026-09-10T08:00:00Z"

    registry.validate(_mutated("Target", mutate), "Target")


def test_unenrolled_target_requires_unenrolled_at(registry):
    def mutate(instance):
        instance["status"] = "unenrolled"
        del instance["enrollment"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Target", mutate), "Target")


def test_unenrolled_target_cannot_carry_enrollment(registry):
    """A stale enrollment block would keep dead opt-ins alive."""

    def mutate(instance):
        instance["status"] = "unenrolled"
        instance["unenrolled_at"] = "2026-09-10T08:00:00Z"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Target", mutate), "Target")


def test_enrolled_target_cannot_carry_unenrolled_at(registry):
    def mutate(instance):
        instance["unenrolled_at"] = "2026-09-10T08:00:00Z"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Target", mutate), "Target")


def test_enrollment_evidence_is_attributable(registry):
    def mutate(instance):
        del instance["enrollment"]["enrolled_by"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Target", mutate), "Target")


def test_opt_in_modes_limited_to_production_modes(registry):
    def mutate(instance):
        instance["enrollment"]["opt_in_modes"] = ["isolated_reexecution"]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Target", mutate), "Target")


def test_opt_in_modes_reject_duplicates(registry):
    def mutate(instance):
        instance["enrollment"]["opt_in_modes"] = [
            "production_synthetic",
            "production_synthetic",
        ]

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Target", mutate), "Target")


def test_target_status_enum_is_closed(registry):
    def mutate(instance):
        instance["status"] = "suspended"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Target", mutate), "Target")


def test_target_class_pattern_is_kebab_case(registry):
    def mutate(instance):
        instance["class"] = "Synthetic Repo!"

    with pytest.raises(ContractViolation):
        registry.validate(_mutated("Target", mutate), "Target")
