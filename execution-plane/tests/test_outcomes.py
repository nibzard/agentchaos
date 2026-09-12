"""Injection receipts and provisional outcome labels."""

from acx_runner import MAX_INJECTIONS, normalize_injections, provisional_outcome

SCENARIO = "scn_" + "a" * 16


def _report(**overrides):
    report = {
        "scenario_version_id": SCENARIO,
        "trigger_state": "not_triggered",
        "receipt_event_id": "evt_" + "0" * 16,
    }
    report.update(overrides)
    return report


def test_determined_verdict_keeps_its_receipt():
    entries, downgraded = normalize_injections(
        [_report(trigger_state="triggered", receipt_event_id="evt_" + "a" * 16)]
    )
    assert entries == [
        {
            "scenario_version_id": SCENARIO,
            "trigger_state": "triggered",
            "receipt_event_id": "evt_" + "a" * 16,
        }
    ]
    assert downgraded == []


def test_determined_verdict_without_receipt_downgrades_to_unknown():
    """Evidence-free determinations never count (AC-004)."""
    entries, downgraded = normalize_injections(
        [_report(trigger_state="triggered", receipt_event_id=None)]
    )
    assert entries[0]["trigger_state"] == "unknown"
    assert "receipt_event_id" not in entries[0]
    assert downgraded == [SCENARIO]


def test_malformed_receipt_downgrades_to_unknown():
    entries, downgraded = normalize_injections(
        [_report(receipt_event_id="not-an-event-id")]
    )
    assert entries[0]["trigger_state"] == "unknown"
    assert "receipt_event_id" not in entries[0]
    assert downgraded == [SCENARIO]


def test_unknown_state_needs_no_receipt():
    entries, downgraded = normalize_injections(
        [_report(trigger_state="unknown", receipt_event_id=None)]
    )
    assert entries[0]["trigger_state"] == "unknown"
    assert "receipt_event_id" not in entries[0]
    assert downgraded == []


def test_entries_carry_no_extra_fields():
    """The Run contract closes object shapes."""
    entries, _ = normalize_injections(
        [_report(trigger_state="bogus-state", extra="field")]
    )
    assert set(entries[0]) <= {
        "scenario_version_id",
        "trigger_state",
        "receipt_event_id",
    }


def test_report_without_contract_scenario_id_is_dropped():
    """No Run document may carry a malformed scenario id."""
    entries, downgraded = normalize_injections(
        [_report(scenario_version_id=None)]
    )
    assert entries == []
    assert downgraded == ["None"]


def test_report_with_short_scenario_id_is_dropped():
    entries, downgraded = normalize_injections(
        [_report(scenario_version_id="scn_short")]
    )
    assert entries == []
    assert downgraded == ["scn_short"]


def test_reports_past_the_contract_cap_are_dropped():
    """The Run contract caps injections at 1024 entries."""
    reports = [_report(scenario_version_id=f"scn_{i:016d}") for i in range(1025)]
    entries, downgraded = normalize_injections(reports)
    assert len(entries) == MAX_INJECTIONS
    assert downgraded == ["scn_" + "1024".zfill(16)]


def test_executor_error_labels_harness_error():
    assert (
        provisional_outcome(executor_error=True, injections=[])
        == "HARNESS_ERROR"
    )


def test_undetermined_injection_labels_inconclusive():
    entries, _ = normalize_injections(
        [_report(trigger_state="unknown", receipt_event_id=None)]
    )
    assert (
        provisional_outcome(executor_error=False, injections=entries)
        == "INCONCLUSIVE"
    )


def test_no_injection_evidence_labels_inconclusive():
    """Nothing reported means nothing determined."""
    assert (
        provisional_outcome(executor_error=False, injections=[])
        == "INCONCLUSIVE"
    )


def test_triggered_injection_labels_inconclusive_not_pass():
    """Defense verdicts belong to T013/T014, never the runner."""
    entries, _ = normalize_injections(
        [_report(trigger_state="triggered", receipt_event_id="evt_" + "c" * 16)]
    )
    assert (
        provisional_outcome(executor_error=False, injections=entries)
        == "INCONCLUSIVE"
    )


def test_fully_determined_untriggered_labels_not_triggered():
    entries, _ = normalize_injections(
        [_report(trigger_state="not_triggered")]
    )
    assert (
        provisional_outcome(executor_error=False, injections=entries)
        == "NOT_TRIGGERED"
    )
