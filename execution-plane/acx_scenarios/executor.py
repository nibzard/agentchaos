"""Deterministic executor for the scenario template library (spec 12).

The executor plays one of each template's authored scripts:

- the baseline arm always plays `benign`;
- the treatment arm plays `treatment_hold` or `treatment_break`
  depending on the `defense` the harness wants to exhibit.

The executor stands in for the adapter and the system under test. It
applies file-family faults into the workspace before the worker starts
(from outside the worker, so the install digest recorded at install
time still proves the identical baseline), then emits the simulated
evidence stream and the injection receipt.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from acx_runner.runner import VariantOutcome, VariantSpec
from acx_scenarios.templates import Template, get_template

HOLD = "hold"
BREAK = "break"


def receipt_event_id(template_id: str, script_key: str) -> str:
    """Deterministic injection-receipt event id for a script."""
    digest = hashlib.sha256(
        f"{template_id}:{script_key}:injection".encode("utf-8")
    ).hexdigest()[:16]
    return "evt_" + digest


class LibraryExecutor:
    """VariantExecutor over the template library."""

    def __init__(self, defense: str = HOLD):
        if defense not in (HOLD, BREAK):
            raise ValueError(f"defense must be {HOLD!r} or {BREAK!r}")
        self.defense = defense
        self.applied_faults: list[tuple[str, str]] = []
        # Workspace plus relative path for every injected fault file,
        # so the lifecycle's cleanup verifier can find them again.
        self.fault_targets: list[tuple[Path, str]] = []
        self.executed: list[tuple[str, str]] = []

    def execute(self, spec: VariantSpec) -> VariantOutcome:
        template = get_template(spec.scenario["template_id"])
        script_key = (
            "benign" if spec.arm == "baseline" else f"treatment_{self.defense}"
        )
        script = template.scripts[script_key]
        self.executed.append((spec.scenario["id"], script_key))

        if script_key != "benign" and template.fault_files:
            # The adapter injects file-family faults into the installed
            # fixture from outside the worker (spec 9.3). It may add
            # files the baseline bundle never carried.
            for relative, content in sorted(template.fault_files.items()):
                target = spec.workspace / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
                self.applied_faults.append((spec.scenario["id"], relative))
                self.fault_targets.append((spec.workspace, relative))

        observations: list[dict] = []
        for step in script.steps:
            entry: dict = {
                "type": "step",
                "template_id": template.template_id,
                "arm": spec.arm,
                "kind": step.kind,
                "detail": step.detail,
            }
            if step.effect is not None:
                entry["effect"] = step.effect
                entry["landed"] = step.landed
            observations.append(entry)
        for probe, matches in script.state:
            observations.append(
                {
                    "type": "state_probe",
                    "template_id": template.template_id,
                    "arm": spec.arm,
                    "probe": probe,
                    "matches": matches,
                }
            )
        for check, passed in script.checks:
            observations.append(
                {
                    "type": "fixture_check",
                    "template_id": template.template_id,
                    "arm": spec.arm,
                    "check": check,
                    "passed": passed,
                }
            )
        if script.graded is not None:
            observations.append(
                {
                    "type": "grader_result",
                    "template_id": template.template_id,
                    "arm": spec.arm,
                    "passed": script.graded,
                }
            )

        receipt = {
            "scenario_version_id": spec.scenario["id"],
            "trigger_state": (
                "triggered" if script.fault_fired else "not_triggered"
            ),
            "receipt_event_id": receipt_event_id(
                template.template_id, script_key
            ),
        }
        receipt_observation = {
            "type": "injection_receipt",
            "template_id": template.template_id,
            "arm": spec.arm,
            "trigger_state": receipt["trigger_state"],
            "receipt_event_id": receipt["receipt_event_id"],
        }
        # The receipt fields name what the real adapter must record
        # (AC-004); values that come from the fault parameters are
        # filled in here so scripts carry the same evidence.
        for field in template.receipt_fields:
            if field in template.fault_parameters:
                receipt_observation[field] = template.fault_parameters[field]
        observations.append(receipt_observation)
        return VariantOutcome(
            observations=observations, injections=[receipt]
        )
