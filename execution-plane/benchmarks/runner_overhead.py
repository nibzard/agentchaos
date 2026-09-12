"""Runner overhead and fixture setup benchmark (T043, spec 21).

Measures what the local fixture runner adds around the workload it
executes: a synthetic executor sleeps a fixed workload time per
variant, and the difference between pair wall time and simulated
workload time is the harness overhead. Also times one environment
lifecycle (acquire, install, release) as the automated share of
first-fixture setup.

Beta target context: median added wall time <= 15% on reference tasks
of 30 seconds or more. This benchmark measures the same ratio on
shorter simulated tasks, single machine, no network services; it does
not claim the beta target, it measures the overhead mechanism.

Run from the repository root:

    python3 execution-plane/benchmarks/runner_overhead.py \
        --out benchmarks/raw/runner_overhead.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gauntlet_runner import FixtureRunner, LocalFixtureEnvironments
from gauntlet_runner.runner import VariantOutcome

TENANT = "tnt_9d4c1e2a3b4f5c67"
GRANT = {
    "kind": "Grant",
    "api_version": "v1",
    "experiment_id": "exp_overhead00001",
    "plan_digest": "sha256:" + "4" * 64,
    "issued_at": "2026-09-12T00:00:00Z",
    "expires_at": "2099-01-01T00:00:00Z",
}


def plan_with(scenario_count: int) -> dict:
    return {
        "kind": "CompiledPlan",
        "api_version": "v1",
        "experiment_id": "exp_overhead00001",
        "tenant_id": TENANT,
        "workload": {
            "id": "wlv_overhead0001",
            "name": "overhead-fixture",
            "version": "1.0.0",
            "fingerprint": "sha256:" + "5" * 64,
            "backend": "local_container",
        },
        "profiles": {
            "baseline": {"id": "aup_1a2b3c4d5e6f7081", "version": "1.0.0"},
            "treatment": {"id": "aup_5b8d2e0f1a3c4966", "version": "2.0.0"},
        },
        "scenarios": [
            {
                "id": f"scn_overhead{n:012d}",
                "template_id": "overhead",
                "version": "1.0.0",
            }
            for n in range(scenario_count)
        ],
        "selectors": [],
    }


class SleepingExecutor:
    """VariantExecutor that stands in for a timed workload."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds

    def execute(self, spec) -> VariantOutcome:  # noqa: ANN001
        time.sleep(self.seconds)
        return VariantOutcome(observations=[], injections=[])


def build_runner(root: Path) -> FixtureRunner:
    state = {"n": 0}

    def root_factory(prefix=None, dir=None):  # noqa: ARG001
        state["n"] += 1
        return str(root / f"ws-{state['n']:03d}")

    counter = iter(range(100000))
    return FixtureRunner(
        LocalFixtureEnvironments(
            id_factory=lambda: f"env_bench-{next(counter):012d}",
            root_factory=root_factory,
        ),
        run_id_factory=lambda: "run_bench" + f"{next(counter):012d}",
    )


def measure_overhead(
    workload_seconds: float, scenario_count: int, repetitions: int
) -> dict:
    """Run paired variants and subtract the simulated workload time."""
    samples: list[float] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for repetition in range(repetitions):
            runner = build_runner(root)
            executor = SleepingExecutor(workload_seconds)
            start = time.perf_counter()
            pairs = runner.run(
                plan_with(scenario_count),
                GRANT,
                executor,
                bundle={"task.md": "overhead measurement\n"},
            )
            wall = time.perf_counter() - start
            errors = [pair.error for pair in pairs if pair.error]
            if errors:
                raise SystemExit(f"a pair errored: {errors}")
            simulated = 2 * workload_seconds * scenario_count
            samples.append(wall - simulated)
            # The next repetition reuses the temp root; environments
            # are released per variant so the directories are free.
    return {
        "workload_seconds_per_variant": workload_seconds,
        "scenario_count": scenario_count,
        "repetitions": repetitions,
        "overhead_seconds_median": statistics.median(samples),
        "overhead_seconds_min": min(samples),
        "overhead_seconds_max": max(samples),
        "overhead_samples": samples,
        "overhead_share_median": statistics.median(samples)
        / (2 * workload_seconds * scenario_count),
        "machine_note": (
            "single machine, local filesystem, no network services, "
            "simulated workload time excluded from the overhead"
        ),
    }


def measure_environment_lifecycle() -> dict:
    """Time provision, install, and release for one environment."""
    with tempfile.TemporaryDirectory() as tmp:
        environments = LocalFixtureEnvironments(
            id_factory=lambda: "env_bench-setup-00000001",
            root_factory=lambda prefix=None, dir=None: str(
                Path(tmp) / "ws-setup"
            ),
        )
        start = time.perf_counter()
        environment = environments.provision()
        environment.install({"task.md": "fixture setup timing\n"})
        environment.release()
        elapsed = time.perf_counter() - start
    return {
        "environment_lifecycle_seconds": elapsed,
        "machine_note": (
            "local filesystem only; the beta first-fixture target also "
            "includes tool installation and account provisioning, which "
            "this does not measure"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workload-seconds", type=float, default=0.5,
        help="simulated workload time per variant",
    )
    parser.add_argument("--scenarios", type=int, default=3)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    report = {
        "kind": "RunnerOverheadBenchmark",
        "overhead": measure_overhead(
            args.workload_seconds, args.scenarios, args.repetitions
        ),
        "environment": measure_environment_lifecycle(),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["overhead"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
