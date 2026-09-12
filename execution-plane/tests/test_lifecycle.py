"""Scenario version lifecycle: draft to validated to signed to released.

Exercises spec 12.1 / T016 end to end: isolated validation through the
real runner, fail-closed gates at every transition, signature coverage
and tamper detection, compatibility classification with staleness, and
the release registry's immutability freeze.
"""

from __future__ import annotations

import pytest
from gauntlet_schemas import validate

from gauntlet_runner import FixtureRunner, LocalFixtureEnvironments
from gauntlet_scenarios import (
    DRAFT,
    RELEASED,
    SIGNED,
    VALIDATED,
    TEMPLATE_IDS,
    Ed25519ReleaseSigner,
    LifecycleError,
    LibraryExecutor,
    ReleaseRegistry,
    build_scenario_version,
    classification_status,
    get_template,
    release,
    sign_release,
    validate_isolated,
    verify_release,
)
from gauntlet_scenarios.lifecycle import plan_digest, validation_plan
from conftest import FixedClock, grant

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


def _draft(template_id="F01"):
    return build_scenario_version(
        get_template(template_id), tenant_id=TENANT, created_at="2026-09-11T21:00:00Z"
    )


def _validated(tmp_path, template_id="F01", **kwargs):
    scenario = _draft(template_id)
    validate_isolated(scenario, runner=_runner(tmp_path),
                      grant=_grant_for(scenario), **kwargs)
    return scenario


def _grant_for(scenario, **overrides):
    """A grant that pins exactly this scenario's validation plan."""
    issued = dict(grant())
    issued["plan_digest"] = plan_digest(validation_plan(scenario))
    issued.update(overrides)
    return issued


def _released(tmp_path, template_id="F01", signer=None, registry=None):
    scenario = _validated(tmp_path, template_id)
    signer = signer or Ed25519ReleaseSigner.generate("key_scenarios-2026q3")
    sign_release(scenario, signer, registry=registry)
    release(
        scenario,
        signer,
        classifications=[
            {
                "mode": "isolated_reexecution",
                "target_class": "synthetic-repo",
                "primitive_version": "1.0.0",
                "eligible": True,
            },
            {
                "mode": "production_synthetic",
                "target_class": "synthetic-repo",
                "primitive_version": "1.0.0",
                "eligible": False,
            },
        ],
        registry=registry,
    )
    return scenario, signer


@pytest.mark.parametrize("template_id", TEMPLATE_IDS)
def test_every_template_validates_in_isolation(tmp_path, template_id):
    scenario = _draft(template_id)
    evidence = validate_isolated(
        scenario, runner=_runner(tmp_path), grant=_grant_for(scenario)
    )
    assert scenario["status"] == VALIDATED
    validate(scenario, "ScenarioVersion")
    for arm in ("baseline", "treatment"):
        assert all(
            entry["verdict"] == "passed" for entry in evidence["arms"][arm]
        ), (template_id, arm, evidence["arms"][arm])
    assert evidence["injection_triggered"] is True
    assert evidence["identical_baseline"] is True
    assert evidence["cleanup"]["verified"] is True
    assert evidence["cleanup"]["operation"] == scenario["cleanup"]["operation"]


def test_validation_fails_closed_when_the_property_breaks(tmp_path):
    scenario = _draft("F05")
    with pytest.raises(LifecycleError) as failure:
        validate_isolated(
            scenario, runner=_runner(tmp_path),
            grant=_grant_for(scenario), defense="break",
        )
    assert scenario["status"] == DRAFT  # nothing was promoted
    assert "failed closed" in str(failure.value)
    assert "asm_f05_state_verified" in str(failure.value)


def test_validation_requires_a_grant_for_this_plan(tmp_path):
    scenario = _draft()
    with pytest.raises(LifecycleError) as failure:
        validate_isolated(
            scenario, runner=_runner(tmp_path), grant=grant()  # pins "2"*64
        )
    assert "does not authorize" in str(failure.value)
    assert scenario["status"] == DRAFT


def test_validation_only_touches_drafts(tmp_path):
    scenario = _validated(tmp_path)
    with pytest.raises(LifecycleError) as failure:
        validate_isolated(
            scenario, runner=_runner(tmp_path), grant=_grant_for(scenario)
        )
    assert "only a draft" in str(failure.value)


def test_validation_refuses_a_document_that_is_not_its_template(tmp_path):
    scenario = _draft()
    scenario["fault"] = dict(scenario["fault"], parameter_digest="sha256:" + "9" * 64)
    with pytest.raises(LifecycleError) as failure:
        validate_isolated(
            scenario, runner=_runner(tmp_path), grant=_grant_for(scenario)
        )
    assert "diverge" in str(failure.value)


def test_cleanup_removes_what_the_fault_injected(tmp_path):
    scenario = _draft("F06")
    assert get_template("F06").fault_files
    executor = LibraryExecutor()
    evidence = validate_isolated(
        scenario, runner=_runner(tmp_path), grant=_grant_for(scenario),
        executor=executor,
    )
    assert executor.fault_targets, "the adapter injected nothing"
    assert evidence["cleanup"]["removed"] == sorted(
        {relative for _, relative in executor.fault_targets}
    )
    for workspace, relative in executor.fault_targets:
        assert not (workspace / relative).exists()


def test_signing_signs_the_content_and_freezes_it(tmp_path):
    scenario = _validated(tmp_path)
    signer = Ed25519ReleaseSigner.generate("key_scenarios-2026q3")
    registry = ReleaseRegistry()
    sign_release(scenario, signer, registry=registry)
    assert scenario["status"] == SIGNED
    validate(scenario, "ScenarioVersion")
    assert scenario["signature"]["algorithm"] == "ed25519"
    assert scenario["signature"]["key_id"] == "key_scenarios-2026q3"
    assert verify_release(scenario, signer.public_key())
    assert registry.contains(scenario)


def test_signing_requires_validation_first(tmp_path):
    scenario = _draft()
    with pytest.raises(LifecycleError) as failure:
        sign_release(scenario, Ed25519ReleaseSigner.generate("key_a-release-01"))
    assert "only a validated" in str(failure.value)
    assert scenario["status"] == DRAFT


def test_any_edit_after_signing_breaks_verification(tmp_path):
    scenario = _validated(tmp_path)
    signer = Ed25519ReleaseSigner.generate("key_scenarios-2026q3")
    sign_release(scenario, signer)
    for path, value in (
        ("description", "a softer story"),
        ("cleanup.test", "worker exits cleanly"),
    ):
        tampered = _deep_copy(scenario)
        node = tampered
        keys = path.split(".")
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
        assert not verify_release(tampered, signer.public_key()), path
    assert verify_release(scenario, signer.public_key())  # original stands


def _deep_copy(document):
    import copy

    return copy.deepcopy(document)


def test_the_registry_blocks_a_content_swap(tmp_path):
    registry = ReleaseRegistry()
    signer = Ed25519ReleaseSigner.generate("key_scenarios-2026q3")
    first = _validated(tmp_path)
    sign_release(first, signer, registry=registry)

    swapped = _validated(tmp_path)
    swapped["expected_observation"] = "something the collectors never saw"
    with pytest.raises(LifecycleError) as failure:
        sign_release(swapped, signer, registry=registry)
    assert "publish a new version" in str(failure.value)

    identical = _validated(tmp_path)
    sign_release(identical, signer, registry=registry)  # no-op freeze


def test_release_records_eligibility_and_re_signs(tmp_path):
    scenario, signer = _released(tmp_path)
    assert scenario["status"] == RELEASED
    validate(scenario, "ScenarioVersion")
    assert verify_release(scenario, signer.public_key())
    entries = {
        (entry["mode"], entry["target_class"]): entry
        for entry in scenario["mode_eligibility"]
    }
    assert entries[
        ("isolated_reexecution", "synthetic-repo")
    ]["eligible"] is True
    assert entries[
        ("production_synthetic", "synthetic-repo")
    ]["eligible"] is False

    # Editing a classification after release breaks the signature.
    tampered = _deep_copy(scenario)
    tampered["mode_eligibility"][0]["eligible"] = False
    assert not verify_release(tampered, signer.public_key())


def test_release_gates(tmp_path):
    scenario = _validated(tmp_path)
    signer = Ed25519ReleaseSigner.generate("key_scenarios-2026q3")

    with pytest.raises(LifecycleError, match="only a signed"):
        release(scenario, signer, classifications=[])
    sign_release(scenario, signer)

    stranger = Ed25519ReleaseSigner.generate("key_other-authority")
    with pytest.raises(LifecycleError) as failure:
        release(scenario, stranger, classifications=[])
    assert "release authority" in str(failure.value)

    duplicated = [
        {
            "mode": "isolated_reexecution",
            "target_class": "synthetic-repo",
            "primitive_version": "1.0.0",
            "eligible": True,
        },
    ] * 2
    with pytest.raises(LifecycleError, match="one eligibility entry"):
        release(scenario, signer, classifications=duplicated)

    bad_mode = [{
        "mode": "chaos", "target_class": "synthetic-repo",
        "primitive_version": "1.0.0", "eligible": True,
    }]
    with pytest.raises(LifecycleError, match="unknown mode"):
        release(scenario, signer, classifications=bad_mode)

    bad_version = [{
        "mode": "observe", "target_class": "synthetic-repo",
        "primitive_version": "latest", "eligible": True,
    }]
    with pytest.raises(LifecycleError, match="semver"):
        release(scenario, signer, classifications=bad_version)


def test_classification_reads_valid_stale_and_unclassified(tmp_path):
    scenario, _ = _released(tmp_path)
    read = dict(mode="isolated_reexecution", target_class="synthetic-repo")
    entry, status = classification_status(
        scenario, primitive_version="1.0.0", **read
    )
    assert status == "valid" and entry is not None

    # A primitive update invalidates the classification until new
    # compatibility tests pass (spec 12.1).
    _, status = classification_status(
        scenario, primitive_version="1.1.0", **read
    )
    assert status == "stale"

    # Edited fault parameters would read stale the same way, but the
    # release signature already refuses that edit; see the tamper test.
    _, status = classification_status(
        scenario,
        primitive_version="1.0.0",
        mode="production_synthetic",
        target_class="synthetic-repo",
    )
    assert status == "not_eligible"

    _, status = classification_status(
        scenario, primitive_version="1.0.0",
        mode="customer_canary", target_class="synthetic-repo",
    )
    assert status == "unclassified"


def test_a_new_version_can_re_release_after_a_swap_is_blocked(tmp_path):
    registry = ReleaseRegistry()
    signer = Ed25519ReleaseSigner.generate("key_scenarios-2026q3")
    first, _ = _released(tmp_path, signer=signer, registry=registry)

    # Same identity, different content: refused.
    second = _validated(tmp_path)
    second["expected_observation"] = "a sharper observation"
    with pytest.raises(LifecycleError, match="publish a new version"):
        sign_release(second, signer, registry=registry)

    # A new version of the same scenario releases cleanly.
    second["version"] = "1.1.0"
    sign_release(second, signer, registry=registry)
    release(
        second,
        signer,
        classifications=[{
            "mode": "isolated_reexecution",
            "target_class": "synthetic-repo",
            "primitive_version": "1.0.0",
            "eligible": True,
        }],
        registry=registry,
    )
    assert second["status"] == RELEASED
    assert first["version"] != second["version"]
