"""Injection receipts and provisional outcome labels (spec 9.2, AC-004).

The runner records which injections actually triggered. A determined
verdict (`triggered` or `not_triggered`) must carry an injection
receipt emitted from outside the worker (spec 9.3); a verdict without a
well-formed receipt is downgraded to `unknown`, because evidence-free
determinations must never count (AC-004, AC-018).

Outcome labeling here is deliberately conservative and provisional.
Task T013 adds independent outcome assertions and task T014 the real
classifier. Until then the runner never labels PASS or FAIL:

- an executor error is HARNESS_ERROR;
- any undetermined injection makes the run INCONCLUSIVE;
- a fully determined run with no triggered injection is NOT_TRIGGERED;
- a run with a triggered injection is INCONCLUSIVE, because whether
  the treatment defended against it is exactly what T013/T014 decide.
"""

from __future__ import annotations

from acx_runner.ids import is_evidence_event_id, is_scenario_version_id

DETERMINED = ("triggered", "not_triggered")

# The Run contract caps the injections array at 1024 entries.
MAX_INJECTIONS = 1024


def normalize_injections(reported: list[dict]) -> tuple[list[dict], list[str]]:
    """Shape executor injection reports into Run contract entries.

    Each report is `{scenario_version_id, trigger_state,
    receipt_event_id?}`. Every returned entry satisfies the Run
    contract's closed shape:

    - a report whose `scenario_version_id` does not match the
      contract pattern is dropped; no Run document may carry it;
    - a determined verdict without a contract-valid receipt becomes
      `unknown`;
    - entries past the contract cap of 1024 are dropped.

    The second return value lists the scenario ids affected by any of
    these downgrades, for the export record.
    """
    entries: list[dict] = []
    downgraded: list[str] = []
    for report in reported or []:
        scenario_id = report.get("scenario_version_id")
        if not is_scenario_version_id(scenario_id):
            downgraded.append(str(scenario_id))
            continue
        entry = {
            "scenario_version_id": scenario_id,
            "trigger_state": report.get("trigger_state"),
        }
        if entry["trigger_state"] not in DETERMINED + ("unknown",):
            entry["trigger_state"] = "unknown"
        receipt = report.get("receipt_event_id")
        if entry["trigger_state"] in DETERMINED:
            if is_evidence_event_id(receipt or ""):
                entry["receipt_event_id"] = receipt
            else:
                entry["trigger_state"] = "unknown"
                downgraded.append(scenario_id)
        if len(entries) < MAX_INJECTIONS:
            entries.append(entry)
        else:
            downgraded.append(scenario_id)
    return entries, downgraded


def provisional_outcome(
    *, executor_error: bool, injections: list[dict]
) -> str:
    if executor_error:
        return "HARNESS_ERROR"
    states = [entry["trigger_state"] for entry in injections]
    if not states or "unknown" in states:
        return "INCONCLUSIVE"
    if "triggered" in states:
        return "INCONCLUSIVE"
    return "NOT_TRIGGERED"


def terminal_state_for(*, executor_error: bool, released_clean: bool) -> str:
    """Cleanup verdict, never inferred from worker exit (spec 13.3).

    CLEAN requires a verified environment release and no executor
    error. An error leaves cleanup unverified: UNKNOWN, not clean.
    """
    if executor_error:
        return "UNKNOWN"
    return "CLEAN" if released_clean else "UNKNOWN"
