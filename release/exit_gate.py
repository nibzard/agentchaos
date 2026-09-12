"""Controlled-beta exit gate checker (T044, spec 22.2).

Runs the evidence suites this repository can run, checks each exit
gate B1 through B10 against what the runs actually show, and writes
release/exit_gate_report.json and exit_gate_report.md. Raw suite
output lands in release/raw/.

Exit codes follow the gate, not the tooling: 0 when every gate is
met, 3 when the report was written but one or more gates are unmet,
1 when the checker itself failed. A reassuring report that waves an
unmeasured gate through is the failure mode spec 22.2 forbids, so
every gate without evidence is reported not met with its gap named.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "release" / "raw"

MET = "met"
PARTIAL = "partial"
NOT_MET = "not met"

# Every evidence suite the checker can run. Order is report order.
SUITES = {
    "broker-go": {
        "label": "Broker (Go)",
        "cwd": "broker",
        "command": ["go", "test", "./..."],
    },
    "evidence-go": {
        "label": "Evidence plane (Go)",
        "cwd": "evidence-plane",
        "command": ["go", "test", "./..."],
    },
    "supervisor-go": {
        "label": "Supervisor (Go)",
        "cwd": "supervisor",
        "command": ["go", "test", "./..."],
    },
    "governor-go": {
        "label": "Governor (Go)",
        "cwd": "governor",
        "command": ["go", "test", "./..."],
    },
    "control-plane-go": {
        "label": "Control plane (Go)",
        "cwd": "control-plane",
        "command": ["go", "test", "./..."],
    },
    "analysis-go": {
        "label": "Analysis (Go)",
        "cwd": "analysis",
        "command": ["go", "test", "./..."],
    },
    "cli-go": {
        "label": "CLI (Go)",
        "cwd": "cli",
        "command": ["go", "test", "./..."],
    },
    "integration-go": {
        "label": "Cross-component integration (Go)",
        "cwd": "integration",
        "command": ["go", "test", "./..."],
    },
    "control-plane-py": {
        "label": "Control plane compiler (Python)",
        "cwd": "control-plane",
        "command": [sys.executable, "-m", "pytest", "tests", "-q"],
    },
    "execution-plane-py": {
        "label": "Execution plane (Python)",
        "cwd": "execution-plane",
        "command": [sys.executable, "-m", "pytest", "tests", "-q"],
    },
    "ui-bun": {
        "label": "UI (Bun)",
        "cwd": "ui",
        "command": ["bun", "test"],
    },
}

# The documented acceptance review for B1: every P0 acceptance
# criterion (spec 22.1) mapped to the suite that carries its
# automated evidence. A criterion with no mapped suite fails B1.
AC_MAP = {
    "AC-001": ["control-plane-py"],
    "AC-002": ["control-plane-py"],
    "AC-003": ["execution-plane-py"],
    "AC-004": ["execution-plane-py"],
    "AC-005": ["execution-plane-py"],
    "AC-006": ["governor-go"],
    "AC-007": ["broker-go", "integration-go"],
    "AC-008": ["broker-go"],
    "AC-009": ["broker-go"],
    "AC-010": ["broker-go"],
    "AC-011": ["evidence-go"],
    "AC-012": ["evidence-go"],
    "AC-013": ["execution-plane-py"],
    "AC-014": ["supervisor-go"],
    "AC-015": ["supervisor-go"],
    "AC-016": ["supervisor-go", "control-plane-go"],
    "AC-017": ["supervisor-go"],
    "AC-018": ["control-plane-go", "analysis-go"],
    "AC-019": ["control-plane-go"],
    "AC-020": ["control-plane-go"],
    "AC-021": ["supervisor-go", "integration-go"],
    "AC-022": ["governor-go", "execution-plane-py"],
    "AC-023": ["ui-bun"],
    "AC-024": ["governor-go", "broker-go"],
    "AC-025": ["cli-go", "analysis-go"],
    "AC-026": ["analysis-go"],
    "AC-027": ["governor-go"],
    "AC-028": ["execution-plane-py"],
}

# The predeclared outage and dirty-cleanup cases for B7. Each entry
# must exist as a test in its suite, and that suite must pass. The
# sweep for B4 lives here too, so the ten-thousand-case suite cannot
# silently disappear.
REQUIRED_CASES = {
    "broker-go": [
        "TestCommitWithoutSinkFailsClosed",
        "TestPrepareTimeoutStaysUnknown",
        "TestUnrecognizedSinkOutcomeStaysUnknown",
        "TestEvidenceFenceDeniesNewProposals",
        "TestGateDeniesExpiredGrant",
        "TestRevokeFencesAPendingCommit",
        "TestExitGateAdversarialSweep",
    ],
    "governor-go": [
        "TestGrantExpirySurvivesRunnerOutage",
        "TestEmergencyStopTerminatesWithoutUI",
        "TestCleanupTerminalStateArrivesOnlyThroughReport",
        "TestStaleAndRetriedGenerations",
    ],
    "supervisor-go": [
        "TestReviewerFailureDegradesButNeverStopsLocalWork",
        "TestEvidenceCaptureFailureFencesNewExternalEffects",
        "TestGovernorLeaseLossFencesNewExternalEffects",
    ],
    "evidence-go": [
        "TestAnExpiredHoldStopsProtecting",
        "TestUnhealthyVerifierAnswersUnknown",
    ],
    "integration-go": [
        "TestReviewerOutageHoldsEffectsWhileLocalWorkContinues",
        "TestEvidenceCaptureFailureFencesNewEffects",
        "TestUnknownDispatchOutcomeResolvesFromSinkState",
    ],
    "analysis-go": [
        "TestUnknownOutcomesStayUnknown",
    ],
}


def run_suites(selected: list[str]) -> dict[str, dict]:
    """Run each suite, capture output, and return pass/fail results."""
    results = {}
    RAW.mkdir(parents=True, exist_ok=True)
    for suite_id in selected:
        spec = SUITES[suite_id]
        log_path = RAW / f"{suite_id}.log"
        started = time.monotonic()
        completed = subprocess.run(
            spec["command"],
            cwd=ROOT / spec["cwd"],
            capture_output=True,
            text=True,
            timeout=1200,
        )
        elapsed = time.monotonic() - started
        log_path.write_text(
            f"$ {' '.join(spec['command'])} (in {spec['cwd']})\n"
            f"{completed.stdout}{completed.stderr}"
        )
        results[suite_id] = {
            "label": spec["label"],
            "passed": completed.returncode == 0,
            "exit_code": completed.returncode,
            "seconds": round(elapsed, 1),
            "log": str(log_path.relative_to(ROOT)),
        }
        print(
            f"{'PASS' if completed.returncode == 0 else 'FAIL'} "
            f"{suite_id} ({elapsed:.1f}s)"
        )
    (RAW / "results.json").write_text(json.dumps(results, indent=2))
    return results


def load_previous_results() -> dict[str, dict]:
    path = RAW / "results.json"
    if not path.exists():
        raise SystemExit(
            "no previous results under release/raw/; run without "
            "--skip-run first"
        )
    return json.loads(path.read_text())


def load_listings() -> dict[str, list[str]]:
    """Collect the test names each Go module declares."""
    names: dict[str, list[str]] = {}
    for suite_id, spec in SUITES.items():
        if not spec["command"][:2] == ["go", "test"]:
            continue
        completed = subprocess.run(
            ["go", "test", "-list", ".*", "./..."],
            cwd=ROOT / spec["cwd"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        found = [
            line.strip()
            for line in completed.stdout.splitlines()
            if line.strip().startswith("Test")
        ]
        names[suite_id] = found
    return names


def check_required_cases(
    listings: dict[str, list[str]]
) -> list[dict]:
    """Verify every predeclared case still exists by name."""
    problems = []
    for suite_id, required in REQUIRED_CASES.items():
        declared = set(listings.get(suite_id, []))
        for case in required:
            if case not in declared:
                problems.append({
                    "suite": suite_id,
                    "case": case,
                    "problem": "test missing from suite listing",
                })
    return problems


def all_pass(results: dict[str, dict], suite_ids: list[str]) -> bool:
    return all(
        suite_id in results and results[suite_id]["passed"]
        for suite_id in suite_ids
    )


def gate_b1(results: dict[str, dict]) -> dict:
    """P0 acceptance criteria: every AC mapped and its suites pass."""
    gaps = []
    for ac, suite_ids in AC_MAP.items():
        for suite_id in suite_ids:
            if suite_id not in SUITES:
                gaps.append(f"{ac} maps to unknown suite {suite_id}")
            elif not results.get(suite_id, {}).get("passed"):
                gaps.append(f"{ac} evidence suite {suite_id} did not pass")
    return {
        "gate": "B1",
        "requirement": (
            "All P0 requirements have automated evidence or a "
            "documented acceptance review"
        ),
        "status": MET if not gaps else NOT_MET,
        "evidence": (
            f"28 acceptance criteria mapped to suites in "
            f"release/exit_gate.py AC_MAP; suite runs in release/raw/"
        ),
        "gaps": gaps,
    }


def gate_b2(results: dict[str, dict]) -> dict:
    """Scenario templates trigger; trigger coverage above 95%."""
    problems = []
    template_count = None
    counted = subprocess.run(
        [sys.executable, "-c",
         "from gauntlet_scenarios import TEMPLATE_IDS; "
         "print(len(TEMPLATE_IDS))"],
        cwd=ROOT / "execution-plane",
        capture_output=True, text=True, timeout=120,
    )
    if counted.returncode == 0:
        template_count = int(counted.stdout.strip())
        if template_count != 24:
            problems.append(
                f"library holds {template_count} templates, not 24"
            )
    else:
        problems.append("template library could not be imported")
    if not results.get("execution-plane-py", {}).get("passed"):
        problems.append("execution-plane suite did not pass")

    scope_gap = (
        "fixture scope only: no scheduled campaign has run, so "
        "coverage over eligible scheduled cases is unmeasured"
    )
    return {
        "gate": "B2",
        "requirement": (
            "All 24 scenario templates trigger in reference fixtures; "
            "valid trigger coverage exceeds 95% of eligible scheduled "
            "cases, the remainder explained"
        ),
        "status": PARTIAL if not problems else NOT_MET,
        "evidence": (
            f"library holds {template_count} templates; the execution "
            "suite executes each through the fixture runner and "
            "asserts trigger plus nontrigger evidence per pair"
        ),
        "gaps": problems + [scope_gap],
    }


def gate_b3(results: dict[str, dict]) -> dict:
    gaps = []
    if not results.get("execution-plane-py", {}).get("passed"):
        gaps.append("adapter conformance suite did not pass")
    return {
        "gate": "B3",
        "requirement": (
            "No known unsupported external path is represented as "
            "mediated"
        ),
        "status": PARTIAL if not gaps else NOT_MET,
        "evidence": (
            "adapter manifests must enumerate unsupported families, "
            "and capabilities plus unsupported paths must cover all "
            "nine fault families; the conformance suite rejects a "
            "silent family and a lying capability"
        ),
        "gaps": gaps + [
            "contract scope only: no deployed mediation surface "
            "exists to audit, so the product-wide claim is untested"
        ],
    }


def gate_b4(results: dict[str, dict]) -> dict:
    problems = []
    if not results.get("broker-go", {}).get("passed"):
        problems.append("broker suite did not pass")
    if not results.get("integration-go", {}).get("passed"):
        problems.append("integration suite did not pass")
    return {
        "gate": "B4",
        "requirement": (
            "No successful hard-boundary bypass in a predeclared "
            "10,000-case conformance/adversarial suite, plus "
            "independent review"
        ),
        "status": NOT_MET if problems else PARTIAL,
        "evidence": (
            "the automated half: TestExitGateAdversarialSweep runs "
            "10,000 seeded cases (7,100 violations across 11 boundary "
            "categories, 2,900 controls) with zero allows on "
            "violations, plus the integration boundary tests"
        ),
        "gaps": problems + [
            "no independent review has been performed",
        ],
    }


def gate_b5() -> dict:
    return {
        "gate": "B5",
        "requirement": (
            "On a held-out benign cohort of at least 1,000 sessions, "
            "the reference control profile's one-sided 95% upper "
            "bound for material false intervention is below 1%"
        ),
        "status": NOT_MET,
        "evidence": "none",
        "gaps": [
            "no benign cohort exists: the bound calculator and its "
            "property tests exist in control-plane, but no sessions "
            "have run",
            "requires a documented cohort with dependence assumptions "
            "before the number means anything",
        ],
    }


def gate_b6() -> dict:
    return {
        "gate": "B6",
        "requirement": (
            "Authorized task completion is no more than three "
            "percentage points below the hard-controls-only baseline "
            "on the specified solvable cohort, with paired uncertainty"
        ),
        "status": NOT_MET,
        "evidence": "none",
        "gaps": [
            "no solvable cohort and no paired baseline runs exist",
            "paired-uncertainty reporting is specified but unexercised",
        ],
    }


def gate_b7(
    results: dict[str, dict], case_problems: list[dict]
) -> dict:
    problems = [f"{p['suite']}: {p['case']} {p['problem']}"
                for p in case_problems]
    for suite_id in REQUIRED_CASES:
        if not results.get(suite_id, {}).get("passed"):
            problems.append(f"{suite_id} did not pass")
    scope_gap = (
        "the hardened ephemeral execution backend is not implemented "
        "in this repository, so fail-safe behavior is verified on the "
        "local fixture model only"
    )
    return {
        "gate": "B7",
        "requirement": (
            "All outage and dirty-cleanup cases fail safely under the "
            "stated supported model"
        ),
        "status": PARTIAL if not problems else NOT_MET,
        "evidence": (
            "predeclared case list in release/exit_gate.py "
            "REQUIRED_CASES; sink failures, reviewer outages, capture "
            "failures, lease loss, expired grants, and dirty cleanup "
            "each hold or fence"
        ),
        "gaps": problems + [scope_gap],
    }


def gate_b8(results: dict[str, dict]) -> dict:
    gaps = []
    if not results.get("analysis-go", {}).get("passed"):
        gaps.append("analysis suite did not pass")
    return {
        "gate": "B8",
        "requirement": (
            "Every serious finding has raw evidence and an "
            "independent outcome reference"
        ),
        "status": NOT_MET,
        "evidence": (
            "the plumbing is tested: portable reports must name their "
            "evidence chain and artifacts by digest, and outcome "
            "assertions come from outside the acting monitor"
        ),
        "gaps": gaps + [
            "no beta campaign has run, so no serious findings exist "
            "to audit; the gate cannot be met without real operations"
        ],
    }


def gate_b9() -> dict:
    gaps = []
    report_path = ROOT / "benchmarks" / "report.json"
    if not report_path.exists():
        return {
            "gate": "B9",
            "requirement": (
                "Latency, cost, privacy, and operator-control targets "
                "have actual benchmark reports"
            ),
            "status": NOT_MET,
            "evidence": "benchmarks/report.json is absent",
            "gaps": ["run benchmarks/run.sh to generate the report"],
        }
    report = json.loads(report_path.read_text())
    areas = {row["area"] for row in report.get("rows", [])}
    unmeasured = [
        row["area"] for row in report.get("rows", [])
        if row["status"] == "not measured"
    ]
    required_areas = {
        "Local deterministic gate",
        "End-to-end overhead",
        "Event ingest",
        "Broker throughput",
    }
    missing = sorted(required_areas - areas)
    if missing:
        gaps.append(f"report lacks measured areas: {missing}")
    return {
        "gate": "B9",
        "requirement": (
            "Latency, cost, privacy, and operator-control targets "
            "have actual benchmark reports"
        ),
        "status": PARTIAL if not missing else NOT_MET,
        "evidence": (
            "benchmarks/report.json covers the measurable targets "
            "in-process with conditions and raw output"
        ),
        "gaps": gaps + [
            f"areas without an honest number: {unmeasured}",
            "cost, privacy, and operator control have no benchmark "
            "surface yet; deployment-scale reports do not exist",
        ],
    }


def gate_b10() -> dict:
    return {
        "gate": "B10",
        "requirement": (
            "At least three design partners integrated, two intend "
            "to pay under a pilot agreement, and naming clearance is "
            "complete"
        ),
        "status": NOT_MET,
        "evidence": "none",
        "gaps": [
            "no design partners have integrated a workflow",
            "no pilot agreements exist",
            "the AgentChaos name conflict (spec 23.3) is unresolved",
        ],
    }


def render_markdown(
    gates: list[dict], results: dict[str, dict], verdict: str
) -> str:
    lines = [
        "# Controlled-beta exit gate report",
        "",
        f"Verdict: **{verdict}**",
        "",
        "Gate statuses follow spec 22.2. A gate is met only on "
        "automated evidence or a documented acceptance review; "
        "everything else names its gap. A reassuring narrative does "
        "not waive a failing gate.",
        "",
        "## Gates",
        "",
        "| Gate | Status | Evidence | Gaps |",
        "|---|---|---|---|",
    ]
    for gate in gates:
        gaps = "; ".join(gate["gaps"]) or "none"
        lines.append(
            f"| {gate['gate']} {gate['requirement']} "
            f"| {gate['status']} | {gate['evidence']} | {gaps} |"
        )
    lines += [
        "",
        "## Evidence suites",
        "",
        "| Suite | Result | Seconds | Log |",
        "|---|---|---|---|",
    ]
    for suite_id, result in results.items():
        outcome = "pass" if result["passed"] else "FAIL"
        lines.append(
            f"| {result['label']} ({suite_id}) | {outcome} "
            f"| {result['seconds']} | {result['log']} |"
        )
    lines += [
        "",
        "## Predeclared cases",
        "",
        "The outage, dirty-cleanup, and adversarial cases each gate "
        "rests on are listed in REQUIRED_CASES in "
        "`release/exit_gate.py`; a renamed or deleted test fails the "
        "check rather than passing silently.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-run",
        action="store_true",
        help="reuse the suite results in release/raw/ without rerunning",
    )
    args = parser.parse_args()

    if args.skip_run:
        results = load_previous_results()
        print(f"reusing {len(results)} suite results from release/raw/")
    else:
        results = run_suites(list(SUITES))

    listings = load_listings()
    case_problems = check_required_cases(listings)

    gates = [
        gate_b1(results),
        gate_b2(results),
        gate_b3(results),
        gate_b4(results),
        gate_b5(),
        gate_b6(),
        gate_b7(results, case_problems),
        gate_b8(results),
        gate_b9(),
        gate_b10(),
    ]
    verdict = (
        "all gates met"
        if all(g["status"] == MET for g in gates)
        else "gates unmet: "
        + ", ".join(g["gate"] for g in gates if g["status"] != MET)
    )

    report = {
        "kind": "ExitGateReport",
        "api_version": "v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "verdict": verdict,
        "suites": results,
        "missing_required_cases": case_problems,
        "gates": gates,
    }
    (ROOT / "release" / "exit_gate_report.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    (ROOT / "release" / "exit_gate_report.md").write_text(
        render_markdown(gates, results, verdict) + "\n"
    )
    print(f"verdict: {verdict}")
    return 0 if verdict == "all gates met" else 3


if __name__ == "__main__":
    sys.exit(main())
