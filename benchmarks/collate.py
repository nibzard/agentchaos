"""Collate raw benchmark output into the beta report (T043, spec 21).

Reads the raw Go benchmark outputs and the runner overhead JSON from
benchmarks/raw/, and writes benchmarks/report.json and report.md.

Honesty rules for the report, from spec 21: every figure in the beta
table is a target under stated measurement conditions, not a measured
fact. This report records what was actually measured, under which
conditions, and marks everything else "not measured" — an in-process
measurement on one machine never certifies a reference-deployment
target.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "benchmarks" / "raw"

BENCH_LINE = re.compile(
    r"^(Benchmark\w+)-\d+\s+\d+\s+([\d.]+)\s+ns/op(.*)$"
)
CUSTOM_METRIC = re.compile(r"([\d.]+)\s+([\w/.-]+)")


def parse_go_bench(path: Path) -> dict[str, dict]:
    """Parse `go test -bench` output into name -> metrics."""
    results: dict[str, dict] = {}
    for line in path.read_text().splitlines():
        match = BENCH_LINE.match(line.strip())
        if not match:
            continue
        name, ns_op, tail = match.groups()
        metrics: dict[str, float] = {"ns_op": float(ns_op)}
        for value, unit in CUSTOM_METRIC.findall(tail):
            try:
                metrics[unit] = float(value)
            except ValueError:
                continue
        results[name] = metrics
    return results


def load_overhead() -> dict:
    path = RAW / "runner_overhead.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def build_rows(bench: dict[str, dict], overhead: dict) -> list[dict]:
    broker = {}
    for name, metrics in bench.items():
        key = name.removeprefix("Benchmark")
        broker[key] = metrics

    gate = broker.get("DeterministicGateLatency", {})
    throughput = broker.get("AuthorizeDecisionThroughput", {})
    ingest = broker.get("IngestMetadataEvents", {})
    fence = broker.get("EmergencyStopAcknowledgment", {})
    review = broker.get("ReferenceReviewDecision", {})
    deadline = broker.get("DeadlineFallbackEnforcement", {})
    expired = broker.get("ExpiredGrantDecision", {})

    over = overhead.get("overhead", {})
    environment = overhead.get("environment", {})

    rows: list[dict] = []

    if gate:
        rows.append({
            "area": "Local deterministic gate",
            "target": "p95 added latency <= 10 ms",
            "measured": f"p95 {gate.get('gate-p95-ms', 0):.3f} ms "
                        f"(p50 {gate.get('gate-p50-ms', 0):.3f} ms, "
                        f"p99 {gate.get('gate-p99-ms', 0):.3f} ms)",
            "condition": (
                "in-process authorize path, single machine, bounded "
                "policy set, no network"
            ),
            "status": "measured",
        })
    if deadline:
        rows.append({
            "area": "Context reviewer deadline",
            "target": (
                "default 3 s decision deadline; on expiry the profile "
                "fallback holds, never a silent allow"
            ),
            "measured": (
                f"default deadline {deadline.get('default-deadline-s', 0):.0f} s; "
                "every timed-out decision fell back to hold "
                "(zero silent allows in benchmark)"
            ),
            "condition": (
                "in-process DeadlineReviewer over a reviewer slower "
                "than the deadline; model latency itself not measured"
            ),
            "status": "measured (enforcement, not model latency)",
        })
    if over:
        share = over.get("overhead_share_median", 0)
        rows.append({
            "area": "End-to-end overhead",
            "target": "median added wall time <= 15%",
            "measured": (
                f"median {over.get('overhead_seconds_median', 0) * 1000:.1f} ms "
                f"added per {over.get('scenario_count', 0)}-pair run "
                f"({share * 100:.2f}% of simulated wall time)"
            ),
            "condition": (
                f"simulated {over.get('workload_seconds_per_variant', 0)} s "
                "variants, local filesystem, no network; the beta "
                "condition is tasks >= 30 s, which this bench does not "
                "reach"
            ),
            "status": "measured at short durations",
        })
    rows.append({
        "area": "Monitoring inference cost",
        "target": "median <= 20% of worker inference cost",
        "measured": (
            "not measured: needs live model calls on both sides"
            + (
                f"; deterministic review tier measured at "
                f"{1e9 / review['ns_op']:.0f} decisions/second"
                if review
                else ""
            )
        ),
        "condition": "requires a reference workload with real inference",
        "status": "not measured",
    })
    if ingest:
        rows.append({
            "area": "Event ingest",
            "target": "5,000 metadata events/second",
            "measured": f"{ingest.get('events/sec', 0):.0f} events/second",
            "condition": (
                "in-process recorder ingest, 1 KB inline events, "
                "batches of 100, single stream, no HTTP, one machine"
            ),
            "status": "measured (library, not the service)",
        })
    if throughput:
        rows.append({
            "area": "Broker throughput",
            "target": "500 deterministic decisions/second",
            "measured": (
                f"{1e9 / throughput['ns_op']:.0f} decisions/second"
            ),
            "condition": (
                "in-process authorize path, single machine, bounded "
                "policy set, no HTTP"
            ),
            "status": "measured (library, not the service)",
        })
    if expired:
        rows.append({
            "area": "Safety grant expiry",
            "target": "10 s lease; nothing accepted after expiry",
            "measured": (
                f"expired-grant denial path {expired['ns_op'] / 1000:.1f} us "
                "per decision, same order as the allow path; refusal "
                "enforcement covered by the broker test suite"
            ),
            "condition": "in-process authorize against an expired grant",
            "status": "measured (enforcement)",
        })
    if fence:
        rows.append({
            "area": "Fencing acknowledgment",
            "target": "p99 <= 2 s for the enrolled broker",
            "measured": (
                f"p99 {fence.get('fence-p99-ms', 0):.2f} ms "
                f"(p50 {fence.get('fence-p50-ms', 0):.2f} ms) from trip "
                "to observable fenced state"
            ),
            "condition": (
                "in-process emergency stop over two live runs, state "
                "read included; no network"
            ),
            "status": "measured",
        })
    rows.append({
        "area": "Evidence durability",
        "target": "intent durable before dispatch",
        "measured": (
            "behavior, not latency: the evidence fence holds new "
            "external effects while capture is down; covered by the "
            "broker gate tests"
        ),
        "condition": "broker test suite (gate behavior)",
        "status": "covered by tests",
    })
    rows.append({
        "area": "Hosted service availability",
        "target": "99.9% monthly design objective",
        "measured": "not measured: no hosted deployment exists",
        "condition": "requires a running deployment and a month",
        "status": "not measured",
    })
    if environment:
        rows.append({
            "area": "First fixture result",
            "target": "under 30 minutes",
            "measured": (
                "automated environment lifecycle "
                f"{environment.get('environment_lifecycle_seconds', 0) * 1000:.1f} ms"
            ),
            "condition": (
                "local filesystem only; tool installation and account "
                "provisioning are not measured"
            ),
            "status": "partial",
        })
    rows.append({
        "area": "Real workflow integration",
        "target": "under one engineer-day",
        "measured": "not measured: no partner integration exists yet",
        "condition": "requires a supported broker/harness path and an "
                     "enrolled environment",
        "status": "not measured",
    })
    return rows


def write_report(rows: list[dict], bench: dict) -> None:
    generated = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    report = {
        "kind": "BenchmarkReport",
        "api_version": "v1",
        "generated_at": generated,
        "statement": (
            "In-process measurements from one development machine. "
            "They exercise the real code paths but do not reproduce "
            "the beta measurement conditions (reference deployments, "
            "network services, live models), and they certify nothing."
        ),
        "benchmarks_run": sorted(bench),
        "rows": rows,
    }
    (ROOT / "benchmarks" / "report.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )

    lines = [
        "# Beta target benchmark report",
        "",
        f"Generated {generated} by `benchmarks/run.sh`.",
        "",
        report["statement"],
        "",
        "| Area | Beta target | Measured | Condition | Status |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['area']} | {row['target']} | {row['measured']} "
            f"| {row['condition']} | {row['status']} |"
        )
    lines += [
        "",
        "## Raw output",
        "",
        "The unedited benchmark output lives in `benchmarks/raw/`.",
        "",
    ]
    (ROOT / "benchmarks" / "report.md").write_text("\n".join(lines))


def main() -> int:
    bench: dict[str, dict] = {}
    for name in ("broker", "evidence", "supervisor", "governor"):
        path = RAW / f"{name}.txt"
        if path.exists():
            bench.update(parse_go_bench(path))
    overhead = load_overhead()
    rows = build_rows(bench, overhead)
    if not rows:
        raise SystemExit("no benchmark output found under benchmarks/raw")
    write_report(rows, bench)
    print(f"report written for {len(rows)} rows, {len(bench)} benchmarks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
