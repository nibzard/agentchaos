"""Real-customer canary design tests (T055, spec 7, AC-035).

Planted classes, consents, and readings prove each gate: admission
collects every problem, consent is per class and bound to the limits
consented to, targets are explicit and re-checked per application,
stop rules are mechanical, reversal verifies against independently
read state, and the residual-risk document is part of admission.
"""

from __future__ import annotations

import pytest

from gauntlet_scenarios.canary import (
    FLAG_FLIP,
    RESPONSE_DELAY,
    TRAFFIC_SHIFT,
    TRANSIENT_ERROR,
    CanaryClassRegistry,
    CanaryPrimitiveClass,
    CanaryRefusal,
    CanaryTargets,
    ConsentLedger,
    CustomerCanaryMode,
    containment_digest,
    evaluate_stop,
    stop_rule_problems,
)

TENANT = "tnt_5f4a3b2c1d0e6f77"
OTHER_TENANT = "tnt_0a1b2c3d4e5f6071"
TARGET_A = "tgt_4a5b6c7d8e9f0a1b"
TARGET_B = "tgt_0f1e2d3c4b5a6978"
TARGET_C = "tgt_9c8d7e6f5a4b3c2d"


class Clock:
    """A monotonic clock the test advances by hand."""

    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def registry() -> CanaryClassRegistry:
    return CanaryClassRegistry(
        RESPONSE_DELAY, TRANSIENT_ERROR, FLAG_FLIP, TRAFFIC_SHIFT
    )


def mode(clock: Clock | None = None) -> tuple[CustomerCanaryMode, Clock]:
    clock = clock or Clock()
    classes = registry()
    consents = ConsentLedger()
    targets = CanaryTargets()
    targets.enroll(TARGET_A, tenant_id=TENANT)
    targets.enroll(TARGET_B, tenant_id=TENANT)
    targets.enroll(TARGET_C, tenant_id=OTHER_TENANT)
    for canary_class in (RESPONSE_DELAY, TRANSIENT_ERROR, FLAG_FLIP):
        consents.record(
            TENANT,
            canary_class,
            consented_by="customer-ops@tenant",
            scope_targets=[TARGET_A, TARGET_B],
        )
    consents.record(
        OTHER_TENANT,
        RESPONSE_DELAY,
        consented_by="other-ops@tenant",
        scope_targets=[TARGET_C],
    )
    return (
        CustomerCanaryMode(
            classes=classes, consents=consents, targets=targets,
            clock=clock,
        ),
        clock,
    )


def evidence(canary_class, version="1.0.0", **edits) -> dict:
    document = {
        "passed": True,
        "digest": containment_digest(canary_class, version),
        "verified_limits": dict(canary_class.effect_limit),
    }
    document.update(edits)
    return document


def request(**overrides) -> dict:
    fields = {
        "kind": "CustomerCanaryRequest",
        "api_version": "v1",
        "tenant_id": TENANT,
        "primitive_class": RESPONSE_DELAY.class_id,
        "primitive_version": "1.0.0",
        "targets": [TARGET_A],
        "duration_seconds": 300,
        "max_applications": 10,
        "stop_rules": {
            "max_error_rate_delta": 0.02,
            "max_latency_delta_ms": 250,
            "reversal_grace_seconds": 30,
        },
        "containment_evidence": evidence(RESPONSE_DELAY),
        "residual_risk_acknowledged_by": "release-lead@operator",
    }
    fields.update(overrides)
    return fields


# --- opt-in primitive classes ---------------------------------------------


def test_classes_are_narrow_and_validated():
    with pytest.raises(CanaryRefusal, match="effect limits"):
        CanaryPrimitiveClass(
            "cpc_unbounded",
            description="No limits declared.",
            reversal_kind="stateless_stop",
            effect_limit={},
            max_targets=1,
            max_duration_seconds=60,
            max_applications=1,
        )
    with pytest.raises(CanaryRefusal, match="reversal kind"):
        CanaryPrimitiveClass(
            "cpc_forever",
            description="Cannot reverse.",
            reversal_kind="best_effort_hope",
            effect_limit={"max_x": 1},
            max_targets=1,
            max_duration_seconds=60,
            max_applications=1,
        )
    with pytest.raises(CanaryRefusal, match="twice"):
        CanaryClassRegistry(RESPONSE_DELAY, RESPONSE_DELAY)


# --- admission ------------------------------------------------------------


def test_admission_passes_and_builds_residual_risk():
    canary_mode, _ = mode()
    record = canary_mode.admit(request())
    assert record["canary_id"].startswith("cnr_")
    risk = record["residual_risk"]
    assert risk["acknowledged_by"] == "release-lead@operator"
    assert risk["worst_case"]["targets"] == 1
    assert risk["worst_case"]["effect_limit"] == (
        RESPONSE_DELAY.effect_limit
    )
    # The residual list names what the canary cannot rule out.
    assert any("not a production assurance certificate" in item
               for item in risk["residual"])


def test_admission_collects_every_problem():
    canary_mode, _ = mode()
    broken = request(
        primitive_class="cpc_unknown",
        targets=[TARGET_A, TARGET_C, "prod-*"],
        stop_rules={"max_error_rate_delta": -1},
        containment_evidence={"passed": False},
        residual_risk_acknowledged_by="",
    )
    with pytest.raises(CanaryRefusal) as refusal:
        canary_mode.admit(broken)
    message = str(refusal.value)
    for needle in (
        "not in the registry",
        "another tenant",
        "not enrolled",
        "stop rule",
        "acknowledge",
    ):
        assert needle in message, f"missing {needle!r} in {message}"


def test_admission_enforces_the_class_caps():
    canary_mode, _ = mode()
    broken = request(
        targets=[TARGET_A, TARGET_B],
        duration_seconds=99999,
        max_applications=99999,
        containment_evidence={"passed": False},
    )
    with pytest.raises(CanaryRefusal) as refusal:
        canary_mode.admit(broken)
    message = str(refusal.value)
    for needle in (
        "class cap",
        "duration",
        "max_applications",
        "containment",
    ):
        assert needle in message, f"missing {needle!r} in {message}"


def test_unacknowledged_residual_risk_refuses():
    canary_mode, _ = mode()
    with pytest.raises(CanaryRefusal, match="residual-risk"):
        canary_mode.admit(request(residual_risk_acknowledged_by="??"))


# --- consent is explicit, per class, and limit-bound ------------------------


def test_consent_does_not_cross_classes_or_tenants():
    canary_mode, _ = mode()
    with pytest.raises(CanaryRefusal, match="no active consent"):
        canary_mode.admit(
            request(primitive_class=TRAFFIC_SHIFT.class_id)
        )
    with pytest.raises(CanaryRefusal, match="no active consent"):
        canary_mode.admit(
            request(
                tenant_id=OTHER_TENANT,
                primitive_class=TRANSIENT_ERROR.class_id,
                targets=[TARGET_C],
            )
        )


def test_limit_drift_stales_the_consent():
    canary_mode, _ = mode()
    drifted = CanaryPrimitiveClass(
        RESPONSE_DELAY.class_id,
        description=RESPONSE_DELAY.description,
        reversal_kind="stateless_stop",
        effect_limit={"max_added_latency_ms": 5000},
        max_targets=5,
        max_duration_seconds=900,
        max_applications=200,
    )
    canary_mode.classes = CanaryClassRegistry(drifted)
    with pytest.raises(CanaryRefusal, match="no active consent"):
        canary_mode.admit(
            request(containment_evidence=evidence(drifted))
        )


def test_targets_outside_the_consent_scope_refuse():
    canary_mode, _ = mode()
    consents = canary_mode.consents
    consents.record(
        TENANT,
        RESPONSE_DELAY,
        consented_by="narrower@tenant",
        scope_targets=[TARGET_B],
    )
    with pytest.raises(CanaryRefusal, match="outside the consented"):
        canary_mode.admit(request())


# --- containment evidence binds -------------------------------------------


def test_containment_evidence_must_pass_and_bind():
    canary_mode, _ = mode()
    with pytest.raises(CanaryRefusal, match="have not passed"):
        canary_mode.admit(
            request(containment_evidence=evidence(RESPONSE_DELAY,
                                                  passed=False))
        )
    with pytest.raises(CanaryRefusal, match="not bound"):
        canary_mode.admit(
            request(containment_evidence=evidence(RESPONSE_DELAY,
                                                  version="2.0.0"))
        )
    with pytest.raises(CanaryRefusal, match="not asserted"):
        canary_mode.admit(
            request(
                containment_evidence=evidence(
                    RESPONSE_DELAY,
                    verified_limits={"max_added_latency_ms": 50000},
                )
            )
        )


# --- per-application re-checks ---------------------------------------------


def test_applications_recheck_consent_and_targets():
    canary_mode, _ = mode()
    record = canary_mode.admit(request(max_applications=1))
    application = canary_mode.apply(record["canary_id"], TARGET_A)
    assert application["application_id"].startswith("cap_")
    assert application["reverse_deadline"] == application["applied_at"] + 300

    # Budget exhausted.
    with pytest.raises(CanaryRefusal, match="budget"):
        canary_mode.apply(record["canary_id"], TARGET_A)

    record = canary_mode.admit(request())
    # Consent revoked since admission.
    canary_mode.consents.revoke(TENANT, RESPONSE_DELAY.class_id)
    with pytest.raises(CanaryRefusal, match="revoked"):
        canary_mode.apply(record["canary_id"], TARGET_A)
    # Fresh consent unblocks, then a revoked target blocks.
    canary_mode.consents.record(
        TENANT,
        RESPONSE_DELAY,
        consented_by="customer-ops@tenant",
        scope_targets=[TARGET_A],
    )
    canary_mode.targets.revoke(TARGET_A)
    with pytest.raises(CanaryRefusal, match="no longer enrolled"):
        canary_mode.apply(record["canary_id"], TARGET_A)


def test_duration_exhaustion_refuses_late_applications():
    clock = Clock()
    canary_mode, _ = mode(clock)
    record = canary_mode.admit(request(duration_seconds=120))
    clock.advance(121)
    with pytest.raises(CanaryRefusal, match="duration"):
        canary_mode.apply(record["canary_id"], TARGET_A)


# --- automatic stop rules ---------------------------------------------------


def test_stop_rules_must_be_declared_numbers():
    for bad in (
        {},
        {"max_error_rate_delta": 0, "max_latency_delta_ms": 10,
         "reversal_grace_seconds": 10},
        {"max_error_rate_delta": 1.5, "max_latency_delta_ms": 10,
         "reversal_grace_seconds": 10},
        {"max_error_rate_delta": 0.01, "max_latency_delta_ms": 10,
         "reversal_grace_seconds": 10, "vibes": 1},
    ):
        assert stop_rule_problems(bad), f"accepted {bad}"


def test_stops_are_mechanical():
    rules = {
        "max_error_rate_delta": 0.02,
        "max_latency_delta_ms": 250,
        "reversal_grace_seconds": 30,
    }
    quiet = evaluate_stop(rules, {"error_rate_delta": 0.01,
                                  "latency_delta_ms": 100})
    assert quiet["stop"] is False
    error = evaluate_stop(rules, {"error_rate_delta": 0.03})
    assert error["stop"] is True and error["fence"] is False
    latency = evaluate_stop(rules, {"latency_delta_ms": 400})
    assert latency["stop"] is True and latency["fence"] is False
    unauthorized = evaluate_stop(
        rules, {"unauthorized_effects": 1}
    )
    assert unauthorized["stop"] is True and unauthorized["fence"] is True
    late = evaluate_stop(rules, {"reversal_past_grace": True})
    assert late["stop"] is True and late["fence"] is True


def test_observing_a_breach_stops_and_reverses():
    canary_mode, _ = mode()
    record = canary_mode.admit(request())
    canary_mode.apply(record["canary_id"], TARGET_A)
    decision = canary_mode.observe(
        record["canary_id"], {"unauthorized_effects": 1}
    )
    assert decision["stop"] is True and decision["fence"] is True
    report = canary_mode.report(record["canary_id"])
    assert report["stopped"] is True
    with pytest.raises(CanaryRefusal, match="fenced"):
        canary_mode.admit(request())
    # The fence records its reason and clears only with one.
    assert canary_mode.fenced(TENANT, RESPONSE_DELAY.class_id)
    with pytest.raises(CanaryRefusal, match="reason"):
        canary_mode.unfence(TENANT, RESPONSE_DELAY.class_id, "")
    canary_mode.unfence(
        TENANT, RESPONSE_DELAY.class_id, "post-incident review done"
    )
    assert canary_mode.fenced(TENANT, RESPONSE_DELAY.class_id) is None


# --- reversal verification ---------------------------------------------------


def test_reversal_verifies_against_independent_state():
    canary_mode, _ = mode()
    record = canary_mode.admit(request())
    application = canary_mode.apply(record["canary_id"], TARGET_A)
    canary_mode.stop(record["canary_id"], "completed")

    verified = canary_mode.verify_reversal(
        record["canary_id"],
        {TARGET_A: {"observed_effect_magnitude": 0}},
    )
    assert verified["verified"] is True
    assert verified["verified_by"] == "independent_state_read"

    still = canary_mode.verify_reversal(
        record["canary_id"],
        {TARGET_A: {"observed_effect_magnitude": 500}},
    )
    assert still["verified"] is False
    assert still["unverified_targets"] == [TARGET_A]
    assert canary_mode.fenced(TENANT, RESPONSE_DELAY.class_id)


def test_missing_readings_are_unverified():
    canary_mode, _ = mode()
    record = canary_mode.admit(request())
    canary_mode.apply(record["canary_id"], TARGET_A)
    canary_mode.stop(record["canary_id"], "completed")
    result = canary_mode.verify_reversal(record["canary_id"], {})
    assert result["verified"] is False
    assert result["unverified_targets"] == [TARGET_A]


def test_flag_reversal_reads_the_registry():
    canary_mode, _ = mode()
    record = canary_mode.admit(
        request(
            primitive_class=FLAG_FLIP.class_id,
            targets=[TARGET_B],
            duration_seconds=900,
            max_applications=1,
            containment_evidence=evidence(FLAG_FLIP),
        )
    )
    canary_mode.apply(record["canary_id"], TARGET_B)
    canary_mode.stop(record["canary_id"], "completed")
    reverted = canary_mode.verify_reversal(
        record["canary_id"],
        {TARGET_B: {"flag_value": False, "original_value": False}},
    )
    assert reverted["verified"] is True
    flipped = canary_mode.verify_reversal(
        record["canary_id"],
        {TARGET_B: {"flag_value": True, "original_value": False}},
    )
    assert flipped["verified"] is False
    assert canary_mode.fenced(TENANT, FLAG_FLIP.class_id)


# --- the AC-035 gates -------------------------------------------------------


def test_assess_passes_only_after_clean_stop():
    canary_mode, _ = mode()
    record = canary_mode.admit(request())
    before = canary_mode.assess(record["canary_id"])
    assert before["passed"] is False
    assert before["gates"]["reversal"]["passed"] is False

    canary_mode.apply(record["canary_id"], TARGET_A)
    canary_mode.stop(record["canary_id"], "completed")
    canary_mode.verify_reversal(
        record["canary_id"],
        {TARGET_A: {"observed_effect_magnitude": 0}},
    )
    after = canary_mode.assess(record["canary_id"])
    assert after["passed"] is True
    for gate in ("opt_in", "containment", "reversal"):
        assert after["gates"][gate]["passed"], gate
