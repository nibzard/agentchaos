"""Target selection: explicit, enrolled, rechecked before each injection."""

import pytest

from acx_compiler import (
    CompileViolation,
    SelectionPolicy,
    expand_selectors,
    resolve_selectors,
    revalidate_selection,
)

from conftest import TENANT, _target, build_store, draft_experiment

SELECTED = "tgt_4a5b6c7d8e9f0a1b"
EXCLUDED = "tgt_0f1e2d3c4b5a6978"


def _selectors():
    return draft_experiment()["manifest"]["selectors"]


def _expand(store=None, mode="isolated_reexecution", **kwargs):
    return expand_selectors(
        _selectors(), store or build_store(), tenant_id=TENANT, mode=mode,
        **kwargs
    )


def _codes(exc: CompileViolation) -> set[str]:
    return {entry.code for entry in exc.entries}


# Expansion returns an explicit, auditable set.


def test_expansion_returns_explicit_enrolled_set():
    outcome = _expand()
    assert outcome.entries == ()
    assert outcome.selectors[0]["selected"] == [SELECTED]
    assert outcome.selectors[0]["excluded"] == [EXCLUDED]
    assert outcome.selectors[0]["recorded_seed"] == 20260911
    assert outcome.target_classes == frozenset({"synthetic-repo"})


def test_expansion_is_deterministic():
    first = _expand()
    second = _expand()
    assert first.selectors == second.selectors
    assert first.target_classes == second.target_classes


def test_resolver_raises_where_collector_collects():
    store = build_store(targets=[_target(status="paused")])
    with pytest.raises(CompileViolation) as excinfo:
        resolve_selectors(
            _selectors(), store, tenant_id=TENANT, mode="isolated_reexecution"
        )
    assert "target_not_enrolled" in _codes(excinfo.value)


# Expansion fails closed (spec 7, 9.1, AC-002).


def test_selector_without_target_ids_fails_closed():
    selectors = _selectors()
    del selectors[0]["target_ids"]
    outcome = expand_selectors(
        selectors, build_store(), tenant_id=TENANT, mode="isolated_reexecution"
    )
    assert "empty_selection" in {entry.code for entry in outcome.entries}


def test_unenrolled_target_fails_closed():
    outcome = _expand(store=build_store(targets=[_target(status="paused")]))
    assert "target_not_enrolled" in {entry.code for entry in outcome.entries}
    assert outcome.selectors[0]["selected"] == []


def test_target_record_outside_contract_fails_closed():
    target = _target()
    del target["enrollment"]["enrolled_by"]
    outcome = _expand(store=build_store(targets=[target]))
    assert "record_schema_invalid" in {entry.code for entry in outcome.entries}


def test_unknown_target_fails_closed():
    selectors = _selectors()
    selectors[0]["target_ids"] = ["tgt_0000000000000000"]
    outcome = expand_selectors(
        selectors, build_store(), tenant_id=TENANT, mode="isolated_reexecution"
    )
    assert "unknown_reference" in {entry.code for entry in outcome.entries}


def test_unsupported_selector_kind_fails_closed():
    selectors = _selectors()
    selectors[0]["kind"] = "all_public_targets"
    outcome = expand_selectors(
        selectors, build_store(), tenant_id=TENANT, mode="isolated_reexecution"
    )
    assert "selector_kind_forbidden" in {entry.code for entry in outcome.entries}


def test_unknown_exclusion_fails_closed():
    """An exclusion naming nothing cannot be verified to exclude anything."""
    selectors = _selectors()
    selectors[0]["exclusions"] = ["tgt_0000000000000000"]
    outcome = expand_selectors(
        selectors, build_store(), tenant_id=TENANT, mode="isolated_reexecution"
    )
    assert "unknown_reference" in {entry.code for entry in outcome.entries}


def test_cross_tenant_exclusion_fails_closed():
    selectors = _selectors()
    selectors[0]["exclusions"] = [EXCLUDED]
    store = build_store(
        targets=[
            _target(SELECTED),
            _target(EXCLUDED, tenant_id="tnt_ffffffffffffffff"),
        ]
    )
    outcome = expand_selectors(
        selectors, store, tenant_id=TENANT, mode="isolated_reexecution"
    )
    assert "unknown_reference" in {entry.code for entry in outcome.entries}


def test_duplicate_target_across_selectors_fails_closed():
    selectors = _selectors() + _selectors()
    outcome = expand_selectors(
        selectors, build_store(), tenant_id=TENANT, mode="isolated_reexecution"
    )
    assert "duplicate_target" in {entry.code for entry in outcome.entries}


def test_excluded_target_leaves_the_selection():
    selectors = _selectors()
    selectors[0]["exclusions"] = [SELECTED]
    outcome = expand_selectors(
        selectors, build_store(), tenant_id=TENANT, mode="isolated_reexecution"
    )
    assert "empty_selection" in {entry.code for entry in outcome.entries}
    assert outcome.selectors[0]["selected"] == []
    assert outcome.selectors[0]["excluded"] == [SELECTED]


# Production selection is unambiguous or it fails closed (spec 13.4).


def test_production_mode_requires_recorded_opt_in():
    target = _target(opt_in_modes=())
    outcome = _expand(
        store=build_store(targets=[target, _target(EXCLUDED)]),
        mode="production_synthetic",
    )
    assert "target_not_opted_in" in {entry.code for entry in outcome.entries}


def test_production_mode_with_recorded_opt_in_selects():
    outcome = _expand(mode="production_synthetic")
    assert outcome.entries == ()
    assert outcome.selectors[0]["selected"] == [SELECTED]


def test_opt_in_for_one_production_mode_does_not_cover_the_other():
    outcome = _expand(mode="customer_canary")
    assert "target_not_opted_in" in {entry.code for entry in outcome.entries}


def test_widened_policy_cannot_weaken_the_default():
    """A caller-supplied policy is a server decision, not a manifest one.

    The default policy still fails closed when a widened policy is
    offered alongside it; only an explicit policy object changes
    behavior for its own call site.
    """
    widened = SelectionPolicy(production_modes=frozenset())
    permissive = _expand(mode="customer_canary", policy=widened)
    assert permissive.entries == ()
    strict = _expand(mode="customer_canary")
    assert "target_not_opted_in" in {entry.code for entry in strict.entries}


# Revalidation: checked again immediately before each injection (spec 7,
# 13.2).


def _snapshot_from(outcome):
    return [dict(entry) for entry in outcome.selectors]


def test_revalidation_passes_on_a_stable_store():
    outcome = _expand()
    revalidate_selection(
        _selectors(), _snapshot_from(outcome), build_store(),
        tenant_id=TENANT, mode="isolated_reexecution",
    )


def test_revalidation_fails_when_a_target_leaves_enrollment():
    outcome = _expand()
    paused_store = build_store(targets=[_target(status="paused")])
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            _selectors(), _snapshot_from(outcome), paused_store,
            tenant_id=TENANT, mode="isolated_reexecution",
        )
    assert "target_not_enrolled" in _codes(excinfo.value)


def test_revalidation_fails_when_opt_in_is_revoked():
    outcome = _expand(mode="production_synthetic")
    revoked = build_store(targets=[_target(opt_in_modes=()), _target(EXCLUDED)])
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            _selectors(), _snapshot_from(outcome), revoked,
            tenant_id=TENANT, mode="production_synthetic",
        )
    assert "target_not_opted_in" in _codes(excinfo.value)


def test_revalidation_fails_on_unexpected_expansion():
    """A set that grew beyond the compiled snapshot trips (spec 13.2)."""
    outcome = _expand()
    doctored = _snapshot_from(outcome)
    doctored[0]["selected"] = []
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            _selectors(), doctored, build_store(),
            tenant_id=TENANT, mode="isolated_reexecution",
        )
    assert "unexpected_target_expansion" in _codes(excinfo.value)


def test_revalidation_fails_when_the_snapshot_grew_after_compile():
    outcome = _expand()
    doctored = _snapshot_from(outcome)
    doctored[0]["selected"] = [SELECTED, EXCLUDED]
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            _selectors(), doctored, build_store(),
            tenant_id=TENANT, mode="isolated_reexecution",
        )
    assert "selection_drift" in _codes(excinfo.value)


def test_revalidation_fails_on_seed_drift():
    outcome = _expand()
    selectors = _selectors()
    selectors[0]["recorded_seed"] = 99999999
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            selectors, _snapshot_from(outcome), build_store(),
            tenant_id=TENANT, mode="isolated_reexecution",
        )
    assert "selection_drift" in _codes(excinfo.value)


def test_revalidation_fails_on_exclusion_drift():
    outcome = _expand()
    selectors = _selectors()
    selectors[0]["exclusions"] = []
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            selectors, _snapshot_from(outcome), build_store(),
            tenant_id=TENANT, mode="isolated_reexecution",
        )
    assert "selection_drift" in _codes(excinfo.value)


def test_revalidation_fails_on_selector_count_mismatch():
    outcome = _expand()
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            _selectors() + _selectors(), _snapshot_from(outcome), build_store(),
            tenant_id=TENANT, mode="isolated_reexecution",
        )
    assert "selection_drift" in _codes(excinfo.value)


def test_revalidation_fails_on_malformed_snapshot_entry():
    outcome = _expand()
    doctored = [{"selected": "not-a-list"}]
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            _selectors(), doctored, build_store(),
            tenant_id=TENANT, mode="isolated_reexecution",
        )
    assert "selection_drift" in _codes(excinfo.value)


def test_revalidation_fails_on_non_string_target_ids():
    outcome = _expand()
    doctored = _snapshot_from(outcome)
    doctored[0]["selected"] = [12345]
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            _selectors(), doctored, build_store(),
            tenant_id=TENANT, mode="isolated_reexecution",
        )
    assert "selection_drift" in _codes(excinfo.value)


# Fixes from the T004 adversarial review.


def test_revalidation_refuses_a_lowered_mode():
    """A lowered mode would skip the opt-in recheck (spec 13.4)."""
    outcome = _expand(mode="production_synthetic")
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            _selectors(), _snapshot_from(outcome), build_store(),
            tenant_id=TENANT, mode="isolated_reexecution",
        )
    assert "selection_mode_mismatch" in _codes(excinfo.value)


def test_revalidation_refuses_a_wrong_tenant():
    """Snapshot tenant binding holds even when the other tenant owns
    records under the same target ids."""
    outcome = _expand()
    foreign_store = build_store(
        targets=[
            _target(SELECTED, tenant_id="tnt_ffffffffffffffff"),
            _target(EXCLUDED, tenant_id="tnt_ffffffffffffffff"),
        ]
    )
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            _selectors(), _snapshot_from(outcome), foreign_store,
            tenant_id="tnt_ffffffffffffffff",
            mode="isolated_reexecution",
        )
    assert "selection_tenant_mismatch" in _codes(excinfo.value)


def test_snapshot_entries_bind_mode_and_tenant():
    outcome = _expand(mode="production_synthetic")
    assert outcome.selectors[0]["mode"] == "production_synthetic"
    assert outcome.selectors[0]["tenant_id"] == TENANT


def test_malformed_snapshot_entry_reports_drift_only():
    outcome = _expand()
    with pytest.raises(CompileViolation) as excinfo:
        revalidate_selection(
            _selectors(), ["not-a-dict"], build_store(),
            tenant_id=TENANT, mode="isolated_reexecution",
        )
    codes = _codes(excinfo.value)
    assert codes == {"selection_drift"}
