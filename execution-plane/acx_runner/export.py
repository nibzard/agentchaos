"""Paired-result export with workload fingerprints (spec 9.2, 18.1).

The export is the runner's durable artifact: every pair with its Run
documents, observations, and injection verdicts, bound to the compiled
plan digest and the workload fingerprint. Analysis and report tasks
(T021, T030) consume this shape.

This is a derived artifact, not a registered contract; it stays a
documented internal format until those tasks stabilize it.
"""

from __future__ import annotations

import json
from pathlib import Path

from acx_runner.runner import PairedRun, utc_now


def build_export(
    plan_document: dict,
    pairs: list[PairedRun],
    *,
    plan_digest: str,
    exported_at: str | None = None,
) -> dict:
    """Assemble the export document for executed pairs.

    `plan_digest` comes from the CompiledPlan; the plan document does
    not carry its own digest.
    """
    workload = plan_document.get("workload", {})
    return {
        "kind": "PairedRunExport",
        "api_version": "v1",
        "experiment_id": plan_document.get("experiment_id"),
        "plan_digest": plan_digest,
        "workload_version_id": workload.get("id"),
        "workload_fingerprint": workload.get("fingerprint"),
        "profiles": {
            "baseline": plan_document.get("profiles", {})
            .get("baseline", {})
            .get("id"),
            "treatment": plan_document.get("profiles", {})
            .get("treatment", {})
            .get("id"),
        },
        "pairs": [_pair_entry(pair) for pair in pairs],
        "exported_at": exported_at or utc_now(),
    }


def _pair_entry(pair: PairedRun) -> dict:
    return {
        "pair_id": pair.pair_id,
        "scenario_version_id": pair.scenario_version_id,
        "baseline_run": pair.baseline,
        "treatment_run": pair.treatment,
        "baseline_observations": pair.baseline_observations,
        "treatment_observations": pair.treatment_observations,
        "injection_triggered": pair.injection_triggered,
        "install_digest": pair.install_digest,
        "identical_baseline": pair.identical_baseline,
        "downgraded_injections": pair.downgraded_injections,
        "error": pair.error,
    }


def write_export(document: dict, path: Path | str) -> Path:
    """Write the export as sorted, indented JSON."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target
