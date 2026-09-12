"""Enrollment lifecycle: explicit, attributable, tenant-scoped."""

import pytest

from gauntlet_compiler import (
    CompileViolation,
    EnrollmentError,
    EnrollmentRegistry,
    MemoryResourceStore,
    compile_manifest,
)

from conftest import NOW, OPERATOR, OTHER_TENANT, TENANT, _target

TARGET_ID = "tgt_4a5b6c7d8e9f0a1b"


def _enroll(registry: EnrollmentRegistry, **overrides) -> dict:
    kwargs = dict(
        target_id=TARGET_ID,
        tenant_id=TENANT,
        target_class="synthetic-repo",
        enrolled_by=OPERATOR,
        now="2026-09-01T10:00:00Z",
        opt_in_modes=("production_synthetic",),
    )
    kwargs.update(overrides)
    return registry.enroll(**kwargs)


def _code(excinfo) -> str:
    return excinfo.value.code


# Enrollment is explicit.


def test_enroll_records_attributable_evidence():
    registry = EnrollmentRegistry()
    record = _enroll(registry)
    assert record["status"] == "enrolled"
    assert record["enrollment"]["enrolled_at"] == "2026-09-01T10:00:00Z"
    assert record["enrollment"]["enrolled_by"] == OPERATOR
    assert record["enrollment"]["opt_in_modes"] == ["production_synthetic"]


def test_enroll_rejects_a_record_outside_the_contract():
    registry = EnrollmentRegistry()
    with pytest.raises(EnrollmentError) as excinfo:
        _enroll(registry, target_class="Synthetic Repo!")
    assert _code(excinfo) == "record_schema_invalid"


def test_enroll_rejects_an_invalid_opt_in_mode():
    registry = EnrollmentRegistry()
    with pytest.raises(EnrollmentError) as excinfo:
        _enroll(registry, opt_in_modes=("isolated_reexecution",))
    assert _code(excinfo) == "record_schema_invalid"


def test_enroll_is_idempotent_failure():
    registry = EnrollmentRegistry()
    _enroll(registry)
    with pytest.raises(EnrollmentError) as excinfo:
        _enroll(registry, now="2026-09-02T10:00:00Z")
    assert _code(excinfo) == "already_enrolled"


# Transitions fail closed.


def test_pause_suspends_selection_without_losing_the_record():
    registry = EnrollmentRegistry()
    _enroll(registry)
    record = registry.pause(TENANT, TARGET_ID, now="2026-09-02T10:00:00Z")
    assert record["status"] == "paused"
    assert record["enrollment"]["opt_in_modes"] == ["production_synthetic"]


def test_resume_restores_enrolled():
    registry = EnrollmentRegistry()
    _enroll(registry)
    registry.pause(TENANT, TARGET_ID, now="2026-09-02T10:00:00Z")
    record = registry.resume(TENANT, TARGET_ID, now="2026-09-03T10:00:00Z")
    assert record["status"] == "enrolled"


def test_unenroll_drops_the_enrollment_record():
    registry = EnrollmentRegistry()
    _enroll(registry)
    record = registry.unenroll(TENANT, TARGET_ID, now="2026-09-04T10:00:00Z")
    assert record["status"] == "unenrolled"
    assert "enrollment" not in record
    assert record["unenrolled_at"] == "2026-09-04T10:00:00Z"


def test_reenroll_after_unenroll_creates_a_fresh_record():
    registry = EnrollmentRegistry()
    _enroll(registry)
    registry.unenroll(TENANT, TARGET_ID, now="2026-09-04T10:00:00Z")
    record = _enroll(registry, now="2026-09-05T10:00:00Z")
    assert record["enrollment"]["enrolled_at"] == "2026-09-05T10:00:00Z"


def test_enroll_while_paused_requires_resume():
    registry = EnrollmentRegistry()
    _enroll(registry)
    registry.pause(TENANT, TARGET_ID, now="2026-09-02T10:00:00Z")
    with pytest.raises(EnrollmentError) as excinfo:
        _enroll(registry, now="2026-09-03T10:00:00Z")
    assert _code(excinfo) == "invalid_transition"


def test_pause_an_unenrolled_target_fails():
    registry = EnrollmentRegistry()
    _enroll(registry)
    registry.unenroll(TENANT, TARGET_ID, now="2026-09-04T10:00:00Z")
    with pytest.raises(EnrollmentError) as excinfo:
        registry.pause(TENANT, TARGET_ID, now="2026-09-05T10:00:00Z")
    assert _code(excinfo) == "invalid_transition"


def test_resume_an_enrolled_target_fails():
    registry = EnrollmentRegistry()
    _enroll(registry)
    with pytest.raises(EnrollmentError) as excinfo:
        registry.resume(TENANT, TARGET_ID, now="2026-09-02T10:00:00Z")
    assert _code(excinfo) == "invalid_transition"


def test_unenroll_an_unenrolled_target_fails():
    registry = EnrollmentRegistry()
    _enroll(registry)
    registry.unenroll(TENANT, TARGET_ID, now="2026-09-04T10:00:00Z")
    with pytest.raises(EnrollmentError) as excinfo:
        registry.unenroll(TENANT, TARGET_ID, now="2026-09-05T10:00:00Z")
    assert _code(excinfo) == "invalid_transition"


# Tenant isolation: cross-tenant operations see nothing.


def test_cross_tenant_get_reports_not_found():
    registry = EnrollmentRegistry()
    _enroll(registry)
    assert registry.get(OTHER_TENANT, TARGET_ID) is None


def test_cross_tenant_pause_reports_not_found():
    registry = EnrollmentRegistry()
    _enroll(registry)
    with pytest.raises(EnrollmentError) as excinfo:
        registry.pause(OTHER_TENANT, TARGET_ID, now="2026-09-02T10:00:00Z")
    assert _code(excinfo) == "not_found"


def test_two_tenants_may_use_the_same_target_id():
    registry = EnrollmentRegistry()
    first = _enroll(registry)
    second = _enroll(
        registry,
        tenant_id=OTHER_TENANT,
        target_class="synthetic-web",
        now="2026-09-01T11:00:00Z",
    )
    assert registry.get(TENANT, TARGET_ID) == first
    assert registry.get(OTHER_TENANT, TARGET_ID) == second


# Loading and audit.


def test_loading_revalidates_every_record():
    broken = _target()
    broken["status"] = "enrolled"
    broken["unenrolled_at"] = "2026-09-10T08:00:00Z"
    with pytest.raises(EnrollmentError) as excinfo:
        EnrollmentRegistry(targets=[_target(), broken])
    assert _code(excinfo) == "record_schema_invalid"


def test_every_transition_is_audited():
    registry = EnrollmentRegistry()
    _enroll(registry)
    registry.pause(TENANT, TARGET_ID, now="2026-09-02T10:00:00Z")
    registry.resume(TENANT, TARGET_ID, now="2026-09-03T10:00:00Z")
    registry.unenroll(TENANT, TARGET_ID, now="2026-09-04T10:00:00Z")
    actions = [entry["action"] for entry in registry.audit_log]
    assert actions == ["enroll", "pause", "resume", "unenroll"]


# The registry feeds the compiler.


def test_enrolled_targets_compile():
    from conftest import build_store, draft_experiment, make_signer

    registry = EnrollmentRegistry()
    other = _target("tgt_0f1e2d3c4b5a6978")
    _enroll(registry)
    store = build_store(targets=[registry.get(TENANT, TARGET_ID), other])
    result = compile_manifest(
        draft_experiment(), store, now=NOW, signer=make_signer()
    )
    assert result.plan_document["selectors"][0]["selected"] == [TARGET_ID]


def test_unenrolled_targets_fail_compilation():
    from conftest import build_store, draft_experiment, make_signer

    registry = EnrollmentRegistry()
    other = _target("tgt_0f1e2d3c4b5a6978")
    _enroll(registry)
    registry.unenroll(TENANT, TARGET_ID, now="2026-09-10T08:00:00Z")
    store = build_store(targets=[registry.snapshot()[0], other])
    with pytest.raises(CompileViolation) as excinfo:
        compile_manifest(draft_experiment(), store, now=NOW, signer=make_signer())
    assert "target_not_enrolled" in {entry.code for entry in excinfo.value.entries}


def test_registry_snapshot_feeds_the_resource_store():
    registry = EnrollmentRegistry(targets=[_target()])
    store = MemoryResourceStore(targets=registry.snapshot())
    assert store.get_target(TARGET_ID)["status"] == "enrolled"


# Fixes from the T004 adversarial review.


def test_reads_cannot_mutate_registry_state():
    """A leaked enrollment dict could grant opt-ins with no audit."""
    registry = EnrollmentRegistry()
    _enroll(registry)
    handle = registry.get(TENANT, TARGET_ID)
    handle["enrollment"]["opt_in_modes"].append("customer_canary")
    handle["status"] = "paused"
    fresh = registry.get(TENANT, TARGET_ID)
    assert fresh["enrollment"]["opt_in_modes"] == ["production_synthetic"]
    assert fresh["status"] == "enrolled"


def test_write_returns_cannot_mutate_registry_state():
    registry = EnrollmentRegistry()
    record = _enroll(registry)
    record["status"] = "unenrolled"
    record["enrollment"]["opt_in_modes"].append("customer_canary")
    fresh = registry.get(TENANT, TARGET_ID)
    assert fresh["status"] == "enrolled"
    assert fresh["enrollment"]["opt_in_modes"] == ["production_synthetic"]


def test_loaded_records_are_isolated_from_the_caller():
    source = _target()
    registry = EnrollmentRegistry(targets=[source])
    source["status"] = "paused"
    source["enrollment"]["opt_in_modes"].append("customer_canary")
    fresh = registry.get(TENANT, TARGET_ID)
    assert fresh["status"] == "enrolled"
    assert fresh["enrollment"]["opt_in_modes"] == ["production_synthetic"]


def test_resume_an_unenrolled_target_fails():
    """Resume is for paused targets; re-enrollment is an explicit enroll."""
    registry = EnrollmentRegistry()
    _enroll(registry)
    registry.unenroll(TENANT, TARGET_ID, now="2026-09-04T10:00:00Z")
    with pytest.raises(EnrollmentError) as excinfo:
        registry.resume(TENANT, TARGET_ID, now="2026-09-05T10:00:00Z")
    assert _code(excinfo) == "invalid_transition"


def test_paused_target_can_unenroll():
    registry = EnrollmentRegistry()
    _enroll(registry)
    registry.pause(TENANT, TARGET_ID, now="2026-09-02T10:00:00Z")
    record = registry.unenroll(TENANT, TARGET_ID, now="2026-09-04T10:00:00Z")
    assert record["status"] == "unenrolled"
    assert "enrollment" not in record


def test_store_rejects_duplicate_target_ids():
    from gauntlet_compiler import MemoryResourceStore

    with pytest.raises(ValueError):
        MemoryResourceStore(targets=[_target(), _target()])
