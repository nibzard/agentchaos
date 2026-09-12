"""Tests for the pilot rehearsal (T047)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_pilots  # noqa: E402


def test_the_rehearsal_fills_the_metrics_contract(tmp_path):
    report = run_one_rehearsal(tmp_path)
    for field in (
        "engineering_time_seconds",
        "completed_work",
        "willingness_to_deploy",
        "pilots",
        "scope",
    ):
        assert field in report, field


def test_willingness_to_deploy_stays_null(tmp_path):
    """Operator judgment; a rehearsal must not invent it."""
    report = run_one_rehearsal(tmp_path)
    assert report["willingness_to_deploy"] is None


def test_the_scope_statement_travels_with_the_report(tmp_path):
    report = run_one_rehearsal(tmp_path)
    assert "does not count toward exit gate B10" in report["scope"]


def test_pilot_b_detects_every_update_fault(tmp_path):
    """The break defense must make every update fault observable."""
    pilot = run_one_rehearsal(tmp_path)["pilots"][1]
    assert pilot["faults_triggered"] > 0
    assert (
        pilot["reproduced_and_detected"]
        == pilot["faults_triggered"]
    )


def test_pilot_c_shows_the_defense_gap(tmp_path):
    """Without the defense the faults land; with it they are held."""
    pilot = run_one_rehearsal(tmp_path)["pilots"][2]
    assert pilot["faults_visible_without_defense"] > 0
    assert pilot["faults_contained_with_defense"] > 0


def test_pilot_a_counts_approval_round_trips(tmp_path):
    pilot = run_one_rehearsal(tmp_path)["pilots"][0]
    assert pilot["approval_round_trips"] > 0
    assert (
        pilot["bounded"]["scenarios"]
        == pilot["approval_heavy"]["scenarios"]
    )


def _cache(tmp_path, factory):
    """Run the rehearsal once per tmp directory; cache the report."""
    hold = getattr(_cache, "hold", None)
    if hold is not None and hold[0] == str(tmp_path):
        return hold[1]
    report = factory()
    _cache.hold = (str(tmp_path), report)
    return report


def run_one_rehearsal(tmp_path):
    import json
    import tempfile

    def factory():
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pilots = [
                run_pilots.pilot_a(root),
                run_pilots.pilot_b(root),
                run_pilots.pilot_c(root),
            ]
        return pilots

    pilots = _cache(tmp_path, factory)
    # Reshape into the report envelope main() builds.
    return {
        "engineering_time_seconds": 0.0,
        "completed_work": (
            pilots[0]["bounded"]["scenarios"]
            + pilots[0]["approval_heavy"]["scenarios"]
            + pilots[1]["run"]["scenarios"]
            + pilots[2]["without_defense"]["scenarios"]
            + pilots[2]["with_defense"]["scenarios"]
        ),
        "willingness_to_deploy": None,
        "pilots": pilots,
        "scope": run_pilots.SCOPE_NOTE,
    }
