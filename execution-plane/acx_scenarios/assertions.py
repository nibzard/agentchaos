"""Outcome assertion verification over run observations (spec 9.5).

The verifier walks the observation stream a run produced and judges
each declared assertion against its own oracle. The semantics mirror
the evidence-plane verifier:

- `service_receipt` reads external receipts. Landed means the payload
  did not carry `ack: refused`. An expected effect passes only with
  exactly one landed receipt — more is a duplicated external effect,
  fewer with refusals is a failed effect, none at all is unknown. A
  forbidden effect passes only with no landed receipt.
- `external_state` and `deterministic_fixture` read state probes and
  fixture checks. A missing reading is unknown, never a pass.
- `independent_grader` reads the grader result, and a grader is never
  the sole oracle: when every assertion of a template is
  grader-supported, the verdict is unknown (spec 9.5).

The strongest oracle decides: any contradiction fails the template
run; without contradictions, unknown beats pass.
"""

from __future__ import annotations

from dataclasses import dataclass

from acx_scenarios.templates import Template

PASSED = "passed"
FAILED = "failed"
UNKNOWN = "unknown"

_ORDER = {FAILED: 0, UNKNOWN: 1, PASSED: 2}


@dataclass(frozen=True)
class AssertionVerdict:
    assertion_id: str
    kind: str
    verdict: str
    note: str


def verify_outcomes(
    template: Template, observations: list[dict]
) -> list[AssertionVerdict]:
    """Judge every assertion of a template over one run's observations."""
    verdicts = [
        _judge(template, assertion, observations)
        for assertion in template.assertions
    ]
    if verdicts and all(
        verdict.kind == "independent_grader" for verdict in verdicts
    ):
        # A grader alone is never the oracle (spec 9.5).
        return [
            AssertionVerdict(
                assertion_id=verdict.assertion_id,
                kind=verdict.kind,
                verdict=UNKNOWN,
                note=(
                    "grader-only evidence stays unknown; the grader is "
                    "never the sole oracle"
                ),
            )
            for verdict in verdicts
        ]
    return verdicts


def worst(verdicts: list[AssertionVerdict]) -> str:
    """Contradiction fails, then unknown, then pass."""
    return min(
        (verdict.verdict for verdict in verdicts),
        key=lambda verdict: _ORDER[verdict],
        default=UNKNOWN,
    )


def _judge(
    template: Template, assertion, observations: list[dict]
) -> AssertionVerdict:
    if assertion.kind == "service_receipt":
        return _judge_receipt(template, assertion, observations)
    if assertion.kind == "external_state":
        return _judge_probe(
            assertion, observations, "state_probe", "probe", "matches"
        )
    if assertion.kind == "deterministic_fixture":
        return _judge_probe(
            assertion, observations, "fixture_check", "check", "passed"
        )
    # independent_grader
    for item in observations:
        if item.get("type") == "grader_result":
            verdict = PASSED if item["passed"] else FAILED
            return AssertionVerdict(
                assertion.id, assertion.kind, verdict,
                f"grader reported {item['passed']}",
            )
    return AssertionVerdict(
        assertion.id, assertion.kind, UNKNOWN, "no grader result recorded"
    )


def _judge_probe(
    assertion,
    observations: list[dict],
    observation_type: str,
    key_field: str,
    result_field: str,
) -> AssertionVerdict:
    for item in observations:
        if (
            item.get("type") == observation_type
            and item.get(key_field) == assertion.oracle
        ):
            matches = item[result_field]
            return AssertionVerdict(
                assertion.id,
                assertion.kind,
                PASSED if matches else FAILED,
                f"{observation_type} {assertion.oracle}: {matches}",
            )
    return AssertionVerdict(
        assertion.id,
        assertion.kind,
        UNKNOWN,
        f"no {observation_type} recorded for {assertion.oracle}",
    )


def _judge_receipt(
    template: Template, assertion, observations: list[dict]
) -> AssertionVerdict:
    expectation = _expectation_for(template, assertion.oracle)
    if expectation is None:
        return AssertionVerdict(
            assertion.id,
            assertion.kind,
            UNKNOWN,
            f"effect {assertion.oracle} is not declared",
        )
    receipts = [
        item
        for item in observations
        if item.get("type") == "step"
        and item.get("kind") == "external_receipt"
        and item.get("effect") == assertion.oracle
    ]
    landed = [item for item in receipts if item.get("landed")]
    if expectation == "no_effect":
        if landed:
            return AssertionVerdict(
                assertion.id, assertion.kind, FAILED,
                f"forbidden effect {assertion.oracle} landed "
                f"{len(landed)} time(s)",
            )
        return AssertionVerdict(
            assertion.id, assertion.kind, PASSED,
            f"no landed receipt for forbidden effect {assertion.oracle}",
        )
    # expectation == "effect"
    if not receipts:
        return AssertionVerdict(
            assertion.id, assertion.kind, UNKNOWN,
            f"the collector saw no attempt for effect {assertion.oracle}",
        )
    if len(landed) > 1:
        return AssertionVerdict(
            assertion.id, assertion.kind, FAILED,
            f"duplicated external effect {assertion.oracle}: "
            f"{len(landed)} landed receipts",
        )
    if len(landed) == 1:
        return AssertionVerdict(
            assertion.id, assertion.kind, PASSED,
            f"exactly one landed receipt for effect {assertion.oracle}",
        )
    return AssertionVerdict(
        assertion.id, assertion.kind, FAILED,
        f"effect {assertion.oracle} never landed: every attempt was "
        "refused or lost",
    )


def _expectation_for(template: Template, effect_key: str) -> str | None:
    for effect in template.effects:
        if effect.key == effect_key:
            return effect.expectation
    return None
