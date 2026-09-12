# Design partner pilots

The three pilot experiments the spec defines (section 21, pilots), the
runbook for running them with a real partner, and the fixture
rehearsal that proves the kit executes.

## The three pilots

1. **Approval-heavy versus bounded autonomy.** The same tasks run two
   ways: every effect behind an approval round trip, and a bounded
   autonomous profile. Measures completed work, wall time, and
   approval round trips.
2. **Update-caused failures.** Inject behavior drift a model, tool, or
   prompt update could cause (response drift, memory drift,
   dependency shift), and verify the failure reproduces and is
   observed.
3. **Existing tests versus system faults.** The same system-level
   monitor and cleanup faults run twice: without the monitoring
   defense, which stands in for the workflow's own checks, and with
   it. The gap is what the customer's tests miss.

## Rehearse the kit

```sh
python3 pilots/run_pilots.py --out pilots/results/pilot_report.json
```

The rehearsal runs all three pilots against the fixture library and
writes the JSON report and a markdown summary. It proves the kit
executes and the metrics contract fills. It is not a pilot: no
partner, customer workflow, or production system is involved, and it
does not count toward exit gate B10. The report says so.

## Metrics contract

Every pilot records the four things the spec demands, not only
positive interview comments:

- **Engineering time**: wall time to integrate and execute.
- **Completed work**: scenarios executed to a terminal pair.
- **Incidents within the test**: faults triggered; detected means an
  assertion verdict failed, contained means the defense held.
- **Willingness to deploy**: operator judgment, recorded by hand
  after a real pilot. Not automatable; the rehearsal records null.

## Runbook for a real pilot

1. Sign the pilot agreement: a scoped 6–8 week evaluation at the
   proposed $5,000–$15,000 band (spec 24), excluding substantial
   third-party compute; the data boundary and evidence redaction
   rules agreed in writing.
2. Enroll one target environment and one workflow the partner already
   runs; record the workload fingerprint.
3. Run the three pilots against the partner's workflow with the same
   commands as the rehearsal, replacing the fixture library with the
   partner's scenario pack.
4. Record engineering time per pilot from first command to report.
5. Review every serious finding with the partner against raw evidence
   and the independent outcome reference.
6. Ask the willingness-to-deploy question explicitly and record the
   answer with its conditions.
7. Write the pilot report with the same metrics contract; a failing
   result changes scope or delays the feature, per spec 22.2.

## Tests

```sh
python3 -m pytest pilots/test_pilots.py -q
```
