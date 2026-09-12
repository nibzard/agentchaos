"""The design partner pilot rehearsal (T047, spec 21 pilots, line 697).

The spec defines three pilot experiments:

1. Compare a customer's approval-heavy workflow to a bounded
   autonomous profile on the same tasks.
2. Find and reproduce failures caused by a model, tool, or prompt
   update.
3. Compare the customer's existing tests to system-level monitor and
   cleanup faults.

No design partner exists yet, so this module cannot run a pilot. What
it can do — and does — is rehearse the measurement protocol end to end
against the fixture library, so the kit a partner receives is known to
execute and the metrics contract is known to fill. Every report
carries the scope statement; nothing here counts toward exit gate B10.

Run from the repository root:

    python3 pilots/run_pilots.py --out pilots/results/pilot_report.json
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                       / "execution-plane"))

from gauntlet_runner import FixtureRunner, LocalFixtureEnvironments
from gauntlet_runner.runner import VariantOutcome
from gauntlet_scenarios import (
    LibraryExecutor,
    get_template,
    verify_outcomes,
    worst,
)
from gauntlet_scenarios.executor import BREAK, HOLD

TENANT = "tnt_9d4c1e2a3b4f5c67"
NOW = "2026-09-12T00:00:00Z"
GRANT = {
    "kind": "Grant",
    "api_version": "v1",
    "experiment_id": "exp_pilot000000001",
    "plan_digest": "sha256:" + "6" * 64,
    "issued_at": NOW,
    "expires_at": "2099-01-01T00:00:00Z",
}

# Fault families that stand in for "an update changed behavior": the
# model's responses drift, its memory drifts, or a dependency shifts
# under it.
UPDATE_FAMILIES = {"model_response", "memory_snapshot", "dependency"}
# System-level faults the customer's own component tests rarely cover.
SYSTEM_FAMILIES = {"monitor_component", "file"}

SCOPE_NOTE = (
    "fixture rehearsal of the pilot protocol; no design partner, no "
    "customer workflow, and no production system was involved. This "
    "report does not count toward exit gate B10."
)


def templates_with_kinds(kinds: set[str]) -> list:
    return [
        template for template in
        [get_template(template_id) for template_id in
         sorted({t.template_id for t in _library()})]
        if template.fault_kind in kinds
    ]


def _library():
    from gauntlet_scenarios import library
    return library()


def _runner(root: Path, prefix: str) -> FixtureRunner:
    state = {"n": 0}

    def root_factory(prefix=None, dir=None):  # noqa: ARG001
        state["n"] += 1
        return str(root / f"{prefix}-{state['n']:03d}")

    counter = iter(range(100000))
    return FixtureRunner(
        LocalFixtureEnvironments(
            id_factory=lambda: f"env_{prefix}-{next(counter):012d}",
            root_factory=root_factory,
        ),
        run_id_factory=lambda: "run_" + f"{next(counter):016d}",
    )


def _plan(experiment_id: str, template_ids: list[str]) -> dict:
    return {
        "kind": "CompiledPlan",
        "api_version": "v1",
        "experiment_id": experiment_id,
        "tenant_id": TENANT,
        "workload": {
            "id": "wlv_pilot00000001",
            "name": "pilot-rehearsal",
            "version": "1.0.0",
            "fingerprint": "sha256:" + "7" * 64,
            "backend": "local_container",
        },
        "profiles": {
            "baseline": {"id": "aup_pilotbaseline01", "version": "1.0.0"},
            "treatment": {"id": "aup_pilottreatment1", "version": "1.0.0"},
        },
        "scenarios": [
            {
                "id": f"scn_pilot{n:012d}",
                "template_id": template_id,
                "version": "1.0.0",
            }
            for n, template_id in enumerate(template_ids)
        ],
        "selectors": [],
    }


class ApprovalGatedExecutor:
    """Wraps a VariantExecutor with an approval round trip per effect.

    The stub approver grants immediately but records every round trip,
    so the rehearsal measures the workflow cost of approval gating on
    identical tasks without simulating human latency.
    """

    def __init__(self, inner) -> None:  # noqa: ANN001
        self.inner = inner
        self.round_trips = 0

    def execute(self, spec) -> VariantOutcome:  # noqa: ANN001
        self.round_trips += 1
        outcome = self.inner.execute(spec)
        approval = {
            "kind": "ApprovalRecord",
            "arm": spec.arm,
            "scenario_id": spec.scenario["id"],
            "requested_at": NOW,
            "decided_at": NOW,
            "decision": "approved",
            "approver": "pilot-stub-approver",
        }
        return VariantOutcome(
            observations=outcome.observations + [approval],
            injections=outcome.injections,
        )


def run_scenarios(
    root: Path, prefix: str, experiment_id: str, template_ids: list[str],
    executor,
) -> dict:
    """Run one paired experiment over the given templates."""
    plan = _plan(experiment_id, template_ids)
    template_by_scenario = {
        scenario["id"]: scenario["template_id"]
        for scenario in plan["scenarios"]
    }
    runner = _runner(root, prefix)
    started = time.perf_counter()
    pairs = runner.run(
        plan, GRANT, executor, bundle={"task.md": "pilot rehearsal\n"},
    )
    wall = time.perf_counter() - started

    rows = []
    caught, missed, unknown = 0, 0, 0
    for pair in pairs:
        template = get_template(
            template_by_scenario[pair.scenario_version_id]
        )
        # Judge arms separately, as the lifecycle does: merging them
        # lets clean baseline observations mask treatment failures.
        baseline_outcome = worst(
            verify_outcomes(template, pair.baseline_observations)
        )
        treatment_outcome = worst(
            verify_outcomes(template, pair.treatment_observations)
        )
        if treatment_outcome == "failed":
            caught += 1
        elif treatment_outcome == "unknown":
            unknown += 1
        else:
            missed += 1
        rows.append({
            "template_id": template.template_id,
            "fault_kind": template.fault_kind,
            "triggered": pair.injection_triggered,
            "baseline_outcome": baseline_outcome,
            "treatment_outcome": treatment_outcome,
        })
    return {
        "experiment_id": experiment_id,
        "wall_seconds": round(wall, 3),
        "scenarios": len(pairs),
        "rows": rows,
        "faults_detected": caught,
        "faults_missed": missed,
        "outcomes_unknown": unknown,
    }


def pilot_a(root: Path) -> dict:
    """Approval-heavy versus bounded profile on the same tasks.

    Both arms run the benign library workload; the approval-heavy arm
    routes every effect through an approval round trip. The rehearsal
    measures the added wall time and the round-trip count.
    """
    templates = sorted(
        {t.template_id for t in _library()
         if t.fault_kind == "permission"} |
        {t.template_id for t in _library()
         if t.fault_kind == "tool_result"}
    )[:6]
    bounded = run_scenarios(
        root, "pilota-bounded", "exp_pilotA-bounded", templates,
        LibraryExecutor(),
    )
    gated_executor = ApprovalGatedExecutor(LibraryExecutor())
    approval = run_scenarios(
        root, "pilota-approval", "exp_pilotA-approval", templates,
        gated_executor,
    )
    return {
        "pilot": "A",
        "question": (
            "what does an approval-heavy workflow cost against a "
            "bounded autonomous profile on the same tasks?"
        ),
        "bounded": bounded,
        "approval_heavy": approval,
        "approval_round_trips": gated_executor.round_trips,
        "added_wall_seconds": round(
            approval["wall_seconds"] - bounded["wall_seconds"], 3
        ),
    }


def pilot_b(root: Path) -> dict:
    """Reproduce failures caused by an update.

    The break defense lets the fault land: the worker proceeds as if
    nothing changed, and a failed assertion verdict is the failure
    reproduced and observed. A passing verdict with the fault
    triggered would mean the fault never became observable.
    """
    templates = [
        t.template_id for t in templates_with_kinds(UPDATE_FAMILIES)
    ]
    result = run_scenarios(
        root, "pilotb", "exp_pilotB-update0001", templates,
        LibraryExecutor(defense=BREAK),
    )
    triggered = sum(1 for row in result["rows"] if row["triggered"])
    return {
        "pilot": "B",
        "question": (
            "which update-caused failures (model response, memory, "
            "dependency drift) reproduce and get detected?"
        ),
        "run": result,
        "faults_triggered": triggered,
        "reproduced_and_detected": result["faults_detected"],
        "triggered_but_not_observable": result["faults_missed"],
    }


def pilot_c(root: Path) -> dict:
    """Existing tests versus system-level faults.

    Two runs over the same system-level faults. The break run stands
    in for the workflow's own checks: no monitoring defense, so the
    fault lands and the assertion verdicts show what breaks. The hold
    run adds the system defense: the same fault, contained. The gap
    between them is what the customer's existing tests miss.
    """
    templates = [
        t.template_id for t in templates_with_kinds(SYSTEM_FAMILIES)
    ]
    undefended = run_scenarios(
        root, "pilotc-break", "exp_pilotC-break001", templates,
        LibraryExecutor(defense=BREAK),
    )
    defended = run_scenarios(
        root, "pilotc-hold", "exp_pilotC-hold001", templates,
        LibraryExecutor(defense=HOLD),
    )
    return {
        "pilot": "C",
        "question": (
            "which system-level monitor and cleanup faults do "
            "the workflow's own checks miss, and what does the "
            "system defense contain?"
        ),
        "without_defense": undefended,
        "with_defense": defended,
        "faults_visible_without_defense":
            undefended["faults_detected"],
        "faults_contained_with_defense": sum(
            1 for row in defended["rows"]
            if row["triggered"] and row["treatment_outcome"] == "passed"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        started = time.perf_counter()
        pilots = [pilot_a(root), pilot_b(root), pilot_c(root)]
        engineering_seconds = round(time.perf_counter() - started, 3)

    report = {
        "kind": "PilotReport",
        "api_version": "v1",
        "generated_at": NOW,
        "scope": SCOPE_NOTE,
        "metrics_contract": {
            "engineering_time_seconds": (
                "wall time to execute the three pilot experiments in "
                "fixture rehearsal"
            ),
            "completed_work": "scenarios executed to a terminal pair",
            "incidents_within_test": (
                "faults triggered; detected means the assertion "
                "verdict failed, missed means it passed"
            ),
            "willingness_to_deploy": (
                "operator judgment recorded by hand after a real "
                "pilot; not automatable and left null here"
            ),
        },
        "engineering_time_seconds": engineering_seconds,
        "completed_work": (
            pilots[0]["bounded"]["scenarios"]
            + pilots[0]["approval_heavy"]["scenarios"]
            + pilots[1]["run"]["scenarios"]
            + pilots[2]["without_defense"]["scenarios"]
            + pilots[2]["with_defense"]["scenarios"]
        ),
        "willingness_to_deploy": None,
        "pilots": pilots,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")

    lines = [
        "# Design partner pilot rehearsal",
        "",
        f"Scope: {SCOPE_NOTE}",
        "",
        f"Engineering time: {engineering_seconds} s for all three "
        "experiments in fixture rehearsal.",
        "",
        "| Pilot | Question | Result |",
        "|---|---|---|",
        f"| A approval-heavy vs bounded | "
        f"{report['pilots'][0]['question']} | "
        f"{report['pilots'][0]['approval_round_trips']} approval "
        f"round trips, {report['pilots'][0]['added_wall_seconds']} s "
        "added wall time |",
        f"| B update-caused failures | "
        f"{report['pilots'][1]['question']} | "
        f"{report['pilots'][1]['faults_triggered']} triggered, "
        f"{report['pilots'][1]['reproduced_and_detected']} reproduced "
        "and detected |",
        f"| C existing tests vs system faults | "
        f"{report['pilots'][2]['question']} | "
        f"{report['pilots'][2]['faults_visible_without_defense']} "
        "visible without the defense, "
        f"{report['pilots'][2]['faults_contained_with_defense']} "
        "contained with it |",
        "",
        "Willingness to deploy is an operator judgment after a real "
        "pilot; this rehearsal records null.",
        "",
    ]
    args.out.with_suffix(".md").write_text("\n".join(lines))
    print(json.dumps({
        "engineering_time_seconds": engineering_seconds,
        "completed_work": report["completed_work"],
        "out": str(args.out),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
