"""Generated long-horizon scenario tests (T054, spec 12, AC-036).

Planted specs prove each gate: generation is sandbox-only and
deterministic, artifacts store and reproduce, containment escapes never
schedule, public and private suites stay separate, and minimized
fixtures refuse unauthorized use.
"""

from __future__ import annotations

import json

import pytest

from gauntlet_scenarios.generated import (
    CONTAINED,
    ESCAPE,
    MIN_HORIZON,
    RESTRICTED_USES,
    SUITE_PRIVATE_HOLDOUT,
    SUITE_PUBLIC,
    USE_PUBLIC_EXAMPLE,
    USE_TRAINING_DATA,
    GeneratedScenarioError,
    GenerationSpec,
    SandboxGenerator,
    SuiteRegistry,
    authorize_use,
    check_use,
    evaluate_containment,
    load_artifact,
    minimize_to_fixture,
    scenario_digest,
    schedule,
)

SINKS = ("sink://sandbox-reports", "sink://sandbox-issues")


def spec(**overrides) -> GenerationSpec:
    fields = {
        "family": "long-horizon-repo",
        "seed": "seed-2026-09-delta",
        "count": 6,
        "horizon": 96,
        "fault_primitive": "delayed_effect_fault",
        "allowed_sinks": SINKS,
    }
    fields.update(overrides)
    return GenerationSpec(**fields)


@pytest.fixture()
def generator(tmp_path) -> SandboxGenerator:
    return SandboxGenerator(tmp_path / "sandbox")


def generated(generator: SandboxGenerator, **overrides) -> list[dict]:
    return generator.generate(spec(**overrides), workspace="gen-2026-09")


# --- sandbox-only generation ---------------------------------------------


def test_generation_runs_inside_the_sandbox_only(generator):
    for escape in ("../escape", "/etc", "nested/path", "."):
        with pytest.raises(GeneratedScenarioError, match="sandbox"):
            generator.generate(spec(), workspace=escape)


def test_specs_validate_their_shape():
    cases = [
        ("family", "Bad_Family"),
        ("seed", ""),
        ("count", 0),
        ("count", 257),
        ("horizon", MIN_HORIZON - 1),
        ("fault_primitive", "Not A Primitive"),
    ]
    for field, value in cases:
        with pytest.raises(GeneratedScenarioError):
            generator_spec = spec(**{field: value})
            generator_spec.validate()
        # The field name appears in the message for the failing field.
    with pytest.raises(GeneratedScenarioError, match="allowed sink"):
        spec(allowed_sinks=()).validate()
    with pytest.raises(GeneratedScenarioError, match="allowed sink"):
        spec(allowed_sinks=("https://not-a-sink",)).validate()


# --- determinism and long-horizon structure ------------------------------


def test_generation_is_deterministic(generator, tmp_path):
    other = SandboxGenerator(tmp_path / "elsewhere")
    first = generated(generator)
    second = generated(other)
    assert [s["id"] for s in first] == [s["id"] for s in second]
    assert [scenario_digest(s) for s in first] == [
        scenario_digest(s) for s in second
    ]
    reseeds = generated(generator, seed="seed-2026-09-beta")
    assert [s["id"] for s in reseeds] != [s["id"] for s in first]


def test_scenarios_are_long_horizon_by_construction(generator):
    for scenario in generated(generator):
        fires = scenario["fault"]["fires_at_step"]
        lands = scenario["fault"]["effect_lands_at_step"]
        assert scenario["horizon"] >= MIN_HORIZON
        assert lands - fires >= scenario["horizon"] // 2
        assert len(scenario["steps"]) == scenario["horizon"]


# --- containment ----------------------------------------------------------


def test_containment_catches_planted_escapes(generator):
    scenarios = generated(generator)
    verdicts = [
        evaluate_containment(s, SINKS)["verdict"] for s in scenarios
    ]
    # The seed deterministically plants at least one escape and at
    # least one contained scenario; both directions are exercised.
    assert ESCAPE in verdicts
    assert CONTAINED in verdicts
    escaping = scenarios[verdicts.index(ESCAPE)]
    report = evaluate_containment(escaping, SINKS)
    assert report["violations"], "an escape reported no violation"
    violation = report["violations"][0]
    assert violation["violation"] == "destination_outside_allowed_sinks"
    assert violation["destination"].startswith("https://external-")
    # The report binds to the scenario content it evaluated.
    assert report["scenario_digest"] == scenario_digest(escaping)


def test_containment_refuses_destination_on_non_receipt_steps(generator):
    scenario = generated(generator)[0]
    for step in scenario["steps"]:
        if step["kind"] != "external_receipt":
            step["destination"] = "sink://sandbox-reports/smuggled"
            break
    report = evaluate_containment(scenario, SINKS)
    assert report["verdict"] == ESCAPE
    assert report["violations"][0]["violation"] == (
        "destination_on_non_receipt_step"
    )
    with pytest.raises(GeneratedScenarioError, match="allowlist"):
        evaluate_containment(scenario, ())


# --- stored, reproducible artifacts ---------------------------------------


def test_artifacts_store_verify_and_reproduce(generator, tmp_path):
    scenarios = generated(generator)
    contained = next(
        s
        for s in scenarios
        if evaluate_containment(s, SINKS)["verdict"] == CONTAINED
    )
    containment = evaluate_containment(contained, SINKS)
    path = generator.store("gen-2026-09", contained, containment)
    assert (generator.root / "gen-2026-09" / f"{contained['id']}.json"
            == path)

    loaded = load_artifact(path)
    assert loaded["scenario_digest"] == scenario_digest(contained)
    assert generator.reproduces(spec(), loaded) is True
    reseeds = spec(seed="seed-2026-09-beta")
    assert generator.reproduces(reseeds, loaded) is False


def test_edited_artifacts_fail_verification(generator, tmp_path):
    scenario = generated(generator)[0]
    path = generator.store(
        "gen-2026-09", scenario, evaluate_containment(scenario, SINKS)
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    document["scenario"]["steps"][0]["detail"] = "quietly rewritten"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(GeneratedScenarioError, match="edited after"):
        load_artifact(path)


# --- the scheduling gate ---------------------------------------------------


def test_scheduling_needs_artifact_containment_and_suite(generator):
    scenarios = generated(generator)
    registry = SuiteRegistry()
    contained = next(
        s
        for s in scenarios
        if evaluate_containment(s, SINKS)["verdict"] == CONTAINED
    )
    escaping = next(
        s
        for s in scenarios
        if evaluate_containment(s, SINKS)["verdict"] == ESCAPE
    )

    # An escape never schedules, and every missing gate is named.
    escape_artifact = {
        "scenario": escaping,
        "scenario_digest": scenario_digest(escaping),
        "containment": evaluate_containment(escaping, SINKS),
    }
    with pytest.raises(GeneratedScenarioError) as refusal:
        schedule(escape_artifact, registry, suite=SUITE_PUBLIC)
    message = str(refusal.value)
    assert "containment" in message
    assert "no suite" in message

    # Containment bound to different content does not count either.
    stale = {
        "scenario": contained,
        "scenario_digest": scenario_digest(contained),
        "containment": evaluate_containment(escaping, SINKS),
    }
    with pytest.raises(GeneratedScenarioError, match="bound"):
        schedule(stale, registry, suite=SUITE_PUBLIC)

    registry.classify(contained, SUITE_PUBLIC)
    artifact = {
        "scenario": contained,
        "scenario_digest": scenario_digest(contained),
        "containment": evaluate_containment(contained, SINKS),
    }
    decision = schedule(artifact, registry, suite=SUITE_PUBLIC)
    assert decision["scenario_id"] == contained["id"]
    assert decision["suite"] == SUITE_PUBLIC
    assert decision["containment_verdict"] == CONTAINED


# --- public and private suites ---------------------------------------------


def test_suites_are_exclusive_per_scenario(generator):
    registry = SuiteRegistry()
    first, second = generated(generator)[:2]
    registry.classify(first, SUITE_PUBLIC)
    registry.classify(second, SUITE_PRIVATE_HOLDOUT)
    with pytest.raises(GeneratedScenarioError, match="separate"):
        registry.classify(first, SUITE_PRIVATE_HOLDOUT)
    # Reclassifying the same content in the same suite is a no-op.
    registry.classify(first, SUITE_PUBLIC)
    assert registry.public_suite() == [first["id"]]
    assert registry.private_holdouts() == [second["id"]]
    assert registry.suite_of(first["id"]) == SUITE_PUBLIC

    with pytest.raises(GeneratedScenarioError, match="new id"):
        drifted = json.loads(json.dumps(first))
        drifted["steps"][0]["detail"] = "drifted"
        registry.classify(drifted, SUITE_PUBLIC)
    with pytest.raises(GeneratedScenarioError, match="suite"):
        registry.classify(first, "leaderboard")


# --- minimized fixtures and data authorization ------------------------------


def test_minimized_fixtures_stay_regression_only(generator):
    scenario = next(
        s
        for s in generated(generator)
        if evaluate_containment(s, SINKS)["verdict"] == CONTAINED
    )
    fixture = minimize_to_fixture(
        scenario, failure_note="monitor held the effect late in horizon"
    )
    assert fixture["origin"]["scenario_digest"] == scenario_digest(scenario)
    # The minimized window is a fraction of the horizon.
    assert len(fixture["minimized_window"]) < scenario["horizon"]
    fires = scenario["fault"]["fires_at_step"]
    lands = scenario["fault"]["effect_lands_at_step"]
    assert fires in fixture["minimized_window"]
    assert lands in fixture["minimized_window"]
    assert set(fixture["use_restrictions"]) == set(RESTRICTED_USES)

    # Default: both restricted uses are refused.
    for use in RESTRICTED_USES:
        with pytest.raises(
            GeneratedScenarioError, match="explicit data authorization"
        ):
            check_use(fixture, use)

    # Explicit authorization opens exactly one use.
    authorize_use(
        fixture, use=USE_TRAINING_DATA, authorized_by="ops-data-lead@corp"
    )
    authorization = check_use(fixture, USE_TRAINING_DATA)
    assert authorization["authorized_by"] == "ops-data-lead@corp"
    with pytest.raises(GeneratedScenarioError):
        check_use(fixture, USE_PUBLIC_EXAMPLE)

    # An authorization bound to another fixture's digest does not carry.
    other_scenario = generated(generator)[1]
    other_fixture = minimize_to_fixture(
        other_scenario, failure_note="same failure elsewhere"
    )
    other_fixture["authorizations"] = list(fixture["authorizations"])
    with pytest.raises(GeneratedScenarioError):
        check_use(other_fixture, USE_TRAINING_DATA)


def test_minimization_validates_its_inputs(generator):
    scenario = generated(generator)[0]
    with pytest.raises(GeneratedScenarioError, match="failure note"):
        minimize_to_fixture(scenario, failure_note="")
    fixture = minimize_to_fixture(scenario, failure_note="late hold")
    with pytest.raises(GeneratedScenarioError, match="authorizer"):
        authorize_use(fixture, use=USE_PUBLIC_EXAMPLE, authorized_by="No")
    with pytest.raises(GeneratedScenarioError, match="not one of"):
        authorize_use(fixture, use="marketing", authorized_by="ops-lead")
    with pytest.raises(GeneratedScenarioError, match="not one of"):
        check_use(fixture, "marketing")
