# Control plane

Python services for definitions, scheduling, and result comparison
(ADR-0001). The first component is the deterministic experiment
manifest compiler.

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
profiles, scenario versions, targets, and credentials. Targets and
credentials have no shared contract yet; their record shapes are in
`acx_compiler/records.py`.

## Tests

```bash
cd control-plane && python3 -m pytest -q
```
