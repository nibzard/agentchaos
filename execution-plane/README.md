# Execution plane

Local fixture runner for paired experiment execution (ADR-0001, spec
9.2). The runner takes a compiled plan and its signed grant, runs one
baseline variant and one treatment variant per scenario in fresh
disposable environments, and exports paired results bound to the
workload fingerprint.

## acx_runner

```python
from acx_runner import (
    FixtureRunner, LocalFixtureEnvironments, build_export, write_export,
)

runner = FixtureRunner(LocalFixtureEnvironments())
pairs = runner.run(
    compiled.plan_document,   # CompiledPlan from compile_manifest
    compiled.grant,           # short-lived signed grant
    executor,                 # VariantExecutor for the workload
    bundle={"task.md": "close issue #7"},
    plan_digest=compiled.plan_digest,  # binds grant to this plan
)

document = build_export(
    compiled.plan_document, pairs, plan_digest=compiled.plan_digest,
)
write_export(document, "pairs.json")
```

`FixtureRunner.run` returns one `PairedRun` per scenario and
repetition. The grant is checked before every pair; an expired,
offset-less, or malformed expiry and a grant bound to a different
`plan_digest` stop new work with a pair-level error, never a silent
skip.

The executor is the untrusted edge. An executor that raises, returns
the wrong type, or reports malformed injections never crashes the
run: the variant is labeled `HARNESS_ERROR` (stopped reasons
`executor_crashed` and `executor_protocol`), the workspace is still
released, and the remaining scenarios still execute. A variant that
fails before provisioning (install errors, escaping bundle paths)
leaves no Run document; its failure is reported on the pair as
`variant_failed: <arm>: <reason>` so harness errors are never
omitted from the export (spec 14.2).

Each variant runs in its own `Environment`: a private workspace
directory, created empty, populated from the explicit bundle, removed
on release. Bundle paths that try to escape the workspace fail the
install. The install returns a manifest digest over the installed
files; equal digests across both arms set `identical_baseline`, so a
contaminated baseline is detectable instead of assumed away (AC-003).

The workload execution is a `VariantExecutor` protocol. The executor
receives a `VariantSpec` — arm, scenario, profile, workload, target
selection seed, workspace, time — and returns a `VariantOutcome` with
observations, injection reports, or an error. Shipped executors are
deterministic fixture scripts; real workload adapters arrive with the
adapter tasks.

Injection reports become Run contract entries through
`normalize_injections`:

- `triggered` and `not_triggered` verdicts require a well-formed
  `receipt_event_id` (AC-004). A missing or malformed receipt downgrades
  the entry to `unknown` and lists the scenario in
  `downgraded_injections`.
- A report whose `scenario_version_id` does not match the contract
  pattern is dropped; no Run document may carry it.
- Entries past the Run contract cap of 1024 are dropped.
- Entries carry no fields beyond the Run contract's closed shape.

Provisioned variants emit Run contract documents. Provisional outcome
labels stay conservative: `HARNESS_ERROR` when the executor failed,
`NOT_TRIGGERED` when every selected injection has receipt-backed
non-trigger evidence, `INCONCLUSIVE` otherwise. The runner never
labels `PASS` or `FAIL`; defense verdicts belong to the analysis tasks
(T013, T014). Cleanup is reported independently: `terminal_state` is
`CLEAN` only when the workspace removal was verified, `UNKNOWN` on any
error path (spec 13.3, AC-022).

The export (`PairedRunExport`) carries every pair with both Run
documents, the observations, the injection verdict, and the install
digest, bound to the plan digest and workload fingerprint. Analysis
and report tasks (T021, T030) consume this shape. It is a derived
internal format, not a registered contract, until those tasks
stabilize it.

## acx_scenarios: the initial template library

The 24 scenario templates F01 through F24 (spec 12) live in
`acx_scenarios/templates.py` as pure data. Each template carries
everything spec 12 demands: benign and treatment variants,
prerequisites, the injection receipt fields, the expected observation,
independent outcome assertions, and a cleanup test.

```python
from acx_scenarios import (
    LibraryExecutor, build_scenario_version, get_template, verify_outcomes,
)

template = get_template("F08")  # synthetic credential bait
document = build_scenario_version(
    template,
    tenant_id="tnt_9d4c1e2a3b4f5c67",
    created_at="2026-09-12T09:00:00Z",
)  # draft ScenarioVersion under the shared contract

pairs = runner.run(
    plan, grant, LibraryExecutor(), bundle=dict(template.fixture),
)
verdicts = verify_outcomes(template, pairs[0].treatment_observations)
```

`build_scenario_version` is deterministic: the same template, tenant,
and timestamp always produce the same document, ids, and digests. The
lifecycle task (T016) moves these drafts through validation, signing,
and release; this package only authors the draft.

`LibraryExecutor` is the deterministic fixture executor for the
library. It plays one of three authored scripts per template:

- `benign` — the fault never fires; the baseline arm always plays it.
- `treatment_hold` — the fault fires and the system under test keeps
  the property the template tests.
- `treatment_break` — the fault fires and the property is violated.

Break scripts exist so every assertion can be shown to fail, not only
to pass. File-family faults (F02, F06, F07, F08, F10, F15, F17, F20)
are applied by the executor into the workspace before the simulated
worker starts — from outside the worker, after the install digest was
recorded, so the identical-baseline proof still holds.

`verify_outcomes` judges a template's assertions over one run's
observations, with the same semantics as the evidence-plane verifier
(spec 9.5): an expected effect needs exactly one landed receipt (a
duplicate is a duplicated external effect), a forbidden effect passes
only with no landed receipt, missing state readings stay unknown, and
a grader is never the sole oracle. Contradiction fails the run;
without contradictions, unknown beats pass.

The template count is a development target, not test coverage or a
statistical sample size (spec 12).

## Tests

```bash
cd execution-plane && python3 -m pytest -q
```
