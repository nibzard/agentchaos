# Control plane

Services for definitions, scheduling, and result comparison (ADR-0001).
The Python package `acx_compiler` compiles experiment manifests. The Go
module `agentchaos/control` classifies finished runs.

## acx_compiler

Compile an Experiment manifest into a signed plan (spec 9.1). Only the
compiler can authorize execution; an LLM may draft the manifest.

```python
from acx_compiler import (
    Ed25519Signer, MemoryResourceStore, compile_manifest,
)

result = compile_manifest(
    experiment,          # Experiment record, status draft
    store,               # ResourceStore with the referenced records
    now="2026-09-11T21:00:00Z",
    signer=Ed25519Signer.generate("key_grants-2026q3"),
)
```

The result is a `CompiledPlan` with:

- `plan_digest`: digest over the canonical, timestamp-free plan
  document. Same manifest and records always produce the same digest.
- `artifact_digests`: one digest per resolved artifact (workload,
  profiles, every scenario), with sanitized, collision-checked paths.
  Two references to the same artifact collapse to one entry; two
  different records that share a path are a compile failure.
- `risk_classification`: `low`, `moderate`, or `high` from a pure
  function of the resolved manifest (spec G6).
- `signed_grant` plus `grant`: short-lived ed25519-signed grant for the
  execution plane. Time appears only here, never in the plan digest.
- `plan_document`: the full plan document.

Call `plan_block()` and attach it to the Experiment record as its
`plan` block; it carries exactly the four fields the Experiment
contract allows and validates as a compiled experiment.

Failures raise `CompileViolation` with one entry per problem: code,
message, and JSON path. Compilation fails closed. Missing dependencies,
ambiguous selectors, unsupported rollback claims, stale credentials,
and absent or wrong-kind effect sinks are failures, never warnings.

The `ResourceStore` protocol supplies workload versions, autonomy
profiles, scenario versions, targets, and credentials. Targets validate
against the Target contract in `shared/schemas`; credentials have no
shared contract yet, so their record shape is in
`acx_compiler/records.py`.

## Enrollment and selection

`acx_compiler/enrollment.py` owns the explicit target lifecycle (spec
7, 13.1, AC-002):

```python
from acx_compiler import EnrollmentRegistry

registry = EnrollmentRegistry()
registry.enroll(
    target_id="tgt_4a5b6c7d8e9f0a1b",
    tenant_id="tnt_9d4c1e2a3b4f5c67",
    target_class="synthetic-repo",
    enrolled_by="act_platform-operator-01",
    now="2026-09-01T10:00:00Z",
    opt_in_modes=("production_synthetic",),
)
registry.pause(tenant_id, target_id, now=now)    # suspends selection
registry.resume(tenant_id, target_id, now=now)
registry.unenroll(tenant_id, target_id, now=now)  # drops all opt-ins
```

Enrollment never happens implicitly. The registry stamps the time,
validates every record against the Target contract, refuses invalid
transitions, keeps an audit log, and reports cross-tenant lookups as
`not_found` so it never confirms another tenant's target exists.

`acx_compiler/selection.py` resolves selectors to an explicit enrolled
set and fails closed on everything else:

- a selector without explicit `target_ids`;
- a target record outside the Target contract;
- an unknown or cross-tenant target, in selections and exclusions;
- an unenrolled or paused target;
- production selection without a recorded per-target opt-in (spec 13.4);
- one target selected by two selectors.

```python
from acx_compiler import resolve_selectors, revalidate_selection

outcome = resolve_selectors(
    manifest["selectors"], store,
    tenant_id=tenant_id, mode=manifest["mode"],
)
# ... immediately before each injection (spec 7, 13.2):
revalidate_selection(
    manifest["selectors"], plan["selectors"], store,
    tenant_id=tenant_id, mode=manifest["mode"],
)
```

`revalidate_selection` re-expands the selectors against the live store
and compares the result with the compiled plan's snapshot. A target
that left enrollment, a revoked opt-in, a changed seed or exclusion
list, or any growth of the set fails closed; growth is reported as the
`unexpected_target_expansion` trip condition. Each snapshot entry also
records the compile-time mode and tenant, so a revalidation call that
lowers the mode or switches tenants fails closed instead of silently
skipping the production opt-in recheck.

## Run result classification

The Go module `agentchaos/control` labels finished runs (spec 9.2). The
classifier is deterministic: no model call participates in the decision.
It consumes three inputs and nothing else:

- the injection status: expected and triggered, where "triggered" means
  an injection receipt from outside the worker (spec 9.3);
- the harness health: any verifier or recorder self-check failure;
- the outcome verdicts from independent outcome verification (spec 9.5).

The labels, in precedence order:

1. `HARNESS_ERROR` (exit 5) — broken instrumentation cannot adjudicate.
   A failure judged by a sick verifier is not adjudicated.
2. `FAIL` (exit 2) — authoritative evidence contradicted an
   expectation. A real violation stands even when the injection never
   fired.
3. `NOT_TRIGGERED` (exit 3) — the expected fault never fired, so no
   defense was tested. Never counted as a pass, never omitted from
   experiment-health statistics (spec 14.2).
4. `INCONCLUSIVE` (exit 3) — outcomes stayed unknown, or nothing was
   asserted. Insufficient evidence is not a pass.
5. `PASS` (exit 0) — every outcome passed and the injection fired when
   one was expected.

Exit code 4 (invalid configuration, spec 20) happens before a run
exists. It is never a run result.

The output is a `RunResult` document under the shared contract
(`shared/schemas/run-result.schema.json`). The contract enforces the
label discipline: a `PASS` with a failed or unknown outcome, and a
`NOT_TRIGGERED` without an expected-then-unfired injection, are not
representable.

```go
classifier := control.NewClassifier()
result, err := classifier.Classify(control.ClassificationInput{
    TenantID: "tnt_9d4c1e2a3b4f5c67",
    RunID:    "run_0f1e2d3c4b5a6970",
    InjectionExpected:  true,
    InjectionTriggered: true,
    Outcomes: []control.OutcomeAssertion{
        {EffectID: "eff_0123456789abcdef", Verdict: control.VerdictPassed},
    },
    OutcomeReportID: "ovr_0123456789abcdef",
})
```

## Tests

```bash
cd control-plane && python3 -m pytest -q
cd control-plane && go test ./...
```

The Go tests feed one result per label through the shared Python
validator, so a classifier change that breaks the shared contract
fails the Go suite.
