"""Scenario template library contracts and invariants (spec 12)."""

from __future__ import annotations

import pytest
from gauntlet_schemas import validate

from gauntlet_scenarios import (
    TEMPLATE_IDS,
    build_scenario_version,
    get_template,
    library,
    scenario_version_id,
)

TENANT = "tnt_9d4c1e2a3b4f5c67"
CREATED = "2026-09-12T09:00:00Z"

FAULT_KINDS = {
    "model_response",
    "tool_result",
    "file",
    "memory_snapshot",
    "peer_channel",
    "permission",
    "dependency",
    "budget",
    "monitor_component",
}

EVIDENCE_KINDS = {
    "proposed_action",
    "broker_decision",
    "resource_access",
    "tool_request",
    "tool_response",
    "external_receipt",
    "delegation",
    "budget_change",
    "injection_receipt",
    "collector_heartbeat",
    "recovery_action",
}


def test_the_library_covers_f01_through_f24():
    assert TEMPLATE_IDS == tuple(f"F{n:02d}" for n in range(1, 25))


@pytest.mark.parametrize("template_id", TEMPLATE_IDS)
def test_every_document_validates_against_the_shared_contract(template_id):
    document = build_scenario_version(
        get_template(template_id), tenant_id=TENANT, created_at=CREATED
    )
    validate(document, "ScenarioVersion")


def test_documents_are_deterministic():
    for template in library():
        first = build_scenario_version(
            template, tenant_id=TENANT, created_at=CREATED
        )
        second = build_scenario_version(
            template, tenant_id=TENANT, created_at=CREATED
        )
        assert first == second


def test_every_template_declares_benign_and_treatment():
    for template in library():
        kinds = {variant.kind for variant in template.variants}
        assert {"benign", "treatment"} <= kinds, template.template_id


def test_every_fault_kind_is_registered():
    for template in library():
        assert template.fault_kind in FAULT_KINDS, template.template_id
        assert 1 <= len(template.fault_parameters) <= 32
        for value in template.fault_parameters.values():
            assert isinstance(value, (str, int, float, bool))


def test_the_grader_is_never_the_sole_oracle():
    # Spec 9.5: the model reviewing the worker must not be the sole
    # ground-truth oracle.
    for template in library():
        kinds = {assertion.kind for assertion in template.assertions}
        assert kinds - {"independent_grader"}, template.template_id


def test_every_assertion_oracle_resolves():
    for template in library():
        effect_keys = {effect.key for effect in template.effects}
        probes = set()
        checks = set()
        for script in template.scripts.values():
            probes.update(probe for probe, _ in script.state)
            checks.update(check for check, _ in script.checks)
        for assertion in template.assertions:
            if assertion.kind == "service_receipt":
                assert assertion.oracle in effect_keys, (
                    template.template_id,
                    assertion.id,
                )
            elif assertion.kind == "external_state":
                assert assertion.oracle in probes, (
                    template.template_id,
                    assertion.id,
                )
            elif assertion.kind == "deterministic_fixture":
                assert assertion.oracle in checks, (
                    template.template_id,
                    assertion.id,
                )
            else:
                assert assertion.oracle == (
                    f"{template.template_id.lower()}_grader"
                ), (template.template_id, assertion.id)


def test_every_script_step_is_an_evidence_kind():
    for template in library():
        for key, script in template.scripts.items():
            for step in script.steps:
                assert step.kind in EVIDENCE_KINDS, (
                    template.template_id,
                    key,
                    step.kind,
                )


def test_receipt_fields_are_well_formed():
    import re

    pattern = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
    for template in library():
        assert 1 <= len(template.receipt_fields) <= 64
        assert len(set(template.receipt_fields)) == len(
            template.receipt_fields
        )
        for field in template.receipt_fields:
            assert pattern.match(field), (template.template_id, field)
        assert "primitive" in template.receipt_fields


def test_every_template_carries_cleanup_and_prerequisites():
    for template in library():
        assert template.cleanup_operation
        assert template.cleanup_test
        assert template.prerequisites
        assert template.expected_observation


def test_scenario_ids_are_distinct():
    ids = [scenario_version_id(tid) for tid in TEMPLATE_IDS]
    assert len(set(ids)) == 24
