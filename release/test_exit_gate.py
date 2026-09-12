"""Tests for the exit gate checker itself (T044, spec 22.2)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import exit_gate  # noqa: E402

PASSING = {
    suite_id: {"label": suite_id, "passed": True, "exit_code": 0,
               "seconds": 1.0, "log": f"release/raw/{suite_id}.log"}
    for suite_id in exit_gate.SUITES
}


def _results(**overrides):
    results = dict(PASSING)
    for key, value in overrides.items():
        results[key] = dict(results[key], passed=value)
    return results


def test_every_p0_criterion_is_mapped():
    expected = {f"AC-{n:03d}" for n in range(1, 29)}
    assert set(exit_gate.AC_MAP) == expected


def test_every_mapped_suite_exists():
    for suite_ids in exit_gate.AC_MAP.values():
        for suite_id in suite_ids:
            assert suite_id in exit_gate.SUITES, suite_id


def test_b1_is_met_only_when_every_mapped_suite_passes():
    assert exit_gate.gate_b1(_results())["status"] == exit_gate.MET
    failed = _results(**{"broker-go": False})
    gate = exit_gate.gate_b1(failed)
    assert gate["status"] == exit_gate.NOT_MET
    assert any("AC-007" in gap for gap in gate["gaps"])


def test_b2_stays_partial_even_when_fixtures_pass():
    gate = exit_gate.gate_b2(_results())
    assert gate["status"] == exit_gate.PARTIAL
    assert any("scheduled" in gap for gap in gate["gaps"])


def test_b4_never_reaches_met_without_independent_review():
    gate = exit_gate.gate_b4(_results())
    assert gate["status"] == exit_gate.PARTIAL
    assert any("independent review" in gap for gap in gate["gaps"])


def test_b4_fails_when_the_sweep_suite_fails():
    gate = exit_gate.gate_b4(_results(**{"broker-go": False}))
    assert gate["status"] == exit_gate.NOT_MET


def test_b5_b6_b10_report_not_met_with_named_gaps():
    for gate in (exit_gate.gate_b5(), exit_gate.gate_b6(),
                 exit_gate.gate_b10()):
        assert gate["status"] == exit_gate.NOT_MET
        assert gate["gaps"], gate["gate"]


def test_b7_fails_when_a_predeclared_case_disappears():
    problems = [{
        "suite": "broker-go",
        "case": "TestExitGateAdversarialSweep",
        "problem": "test missing from suite listing",
    }]
    gate = exit_gate.gate_b7(_results(), problems)
    assert gate["status"] == exit_gate.NOT_MET
    assert any("missing" in gap for gap in gate["gaps"])


def test_b7_is_partial_on_a_clean_local_model():
    gate = exit_gate.gate_b7(_results(), [])
    assert gate["status"] == exit_gate.PARTIAL
    assert any("hardened" in gap for gap in gate["gaps"])


def test_case_listing_detects_renamed_tests():
    listings = {"broker-go": ["TestSomethingElse"]}
    problems = exit_gate.check_required_cases(listings)
    assert problems and problems[0]["problem"].startswith("test missing")


def test_verdict_names_every_unmet_gate():
    gates = [exit_gate.gate_b1(_results()), exit_gate.gate_b5()]
    unmet = [g["gate"] for g in gates if g["status"] != exit_gate.MET]
    assert unmet == ["B5"]
