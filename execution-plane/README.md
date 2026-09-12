# Execution plane

Local fixture runner for paired experiment execution (ADR-0001, spec
9.2). The runner takes a compiled plan and its signed grant, runs one
baseline variant and one treatment variant per scenario in fresh
disposable environments, and exports paired results bound to the
workload fingerprint.

## gauntlet_runner

```python
from gauntlet_runner import (
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

## gauntlet_scenarios: the initial template library

The 24 scenario templates F01 through F24 (spec 12) live in
`gauntlet_scenarios/templates.py` as pure data. Each template carries
everything spec 12 demands: benign and treatment variants,
prerequisites, the injection receipt fields, the expected observation,
independent outcome assertions, and a cleanup test.

```python
from gauntlet_scenarios import (
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
and timestamp always produce the same document, ids, and digests.

## Scenario lifecycle

`gauntlet_scenarios.lifecycle` moves a draft ScenarioVersion through the
four states of spec 12.1 (T016). Every transition has one gate and
fails closed — a refused transition changes nothing:

1. **Draft.** `build_scenario_version` authors the document. Nothing
   has run.
2. **Validated.** `validate_isolated` runs one paired execution through
   the real runner under a grant that pins the validation plan's
   digest. Promotion requires: identical installed baselines (AC-003),
   the injection triggering in the treatment arm only, every outcome
   assertion passing in both arms, and a cleanup that removes what the
   fault injected — verified independently, never by worker exit (spec
   13.3). The scenario document must still be the library document for
   its template: the id and the fault parameter digest are checked
   against the template before anything runs.
3. **Signed.** `sign_release` signs the canonical bytes of the document
   with an Ed25519 key. Any later edit — content or classification —
   breaks `verify_release`.
4. **Released.** `release` records compatibility tests as
   `mode_eligibility` entries, then re-signs the whole document so the
   signature covers the classification.

```python
from gauntlet_scenarios import (
    Ed25519ReleaseSigner, ReleaseRegistry, classification_status,
    release, sign_release, validate_isolated, verify_release,
)

signer = Ed25519ReleaseSigner.generate("key_scenarios-2026q3")
registry = ReleaseRegistry()  # freezes (id, version) to content

evidence = validate_isolated(document, runner=runner, grant=grant)
sign_release(document, signer, registry=registry)
release(document, signer, classifications=[
    {"mode": "isolated_reexecution", "target_class": "synthetic-repo",
     "primitive_version": "1.0.0", "eligible": True},
], registry=registry)
assert verify_release(document, signer.public_key())
entry, status = classification_status(
    document, mode="isolated_reexecution",
    target_class="synthetic-repo", primitive_version="1.1.0",
)  # ("stale"): a primitive update invalidates until tests pass again
```

Immutability: the registry freezes `(id, version)` to a content digest
at first signing. Different content under the same identity is
refused — publish a new version. The same release authority that
signed must record the compatibility tests.

The compiler only schedules `released` scenarios and checks their
eligibility for the experiment's mode and target classes, so a
scenario that skipped any gate cannot reach an experiment.

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

The executor records every injected fault file (`fault_targets`), which
is what the lifecycle's cleanup verifier walks after the pair.

## Production synthetic mode

`gauntlet_scenarios.production` is the P1 operating mode (T049, spec 7
and 13.4, AC-031): enrolled synthetic sessions through production-path
services, only after the isolated and integration gates pass. The
spec's five admission requirements — verified enrollment, an
independent kill path, cost limits, known effect sinks, and cleanup
evidence — are checked at admission with the whole problem list, and
again immediately before every single injection:

- **Enrollment.** `Enrollment` holds dedicated `syn_` identities and
  explicit targets. Wildcard and unknown-scheme destinations are
  refused. A target revoked after admission blocks the next injection.
- **Gates.** The scenario must be `released`, its
  `production_synthetic` classification valid for the target class and
  primitive version, the fault kind registered in the primitive
  registry, and integration evidence bound to the workload
  fingerprint and passed.
- **Cost.** Sessions carry bounded injection and effect budgets, and
  the identity's own budget caps the session.
- **Kill.** `mode.kill` actuates a kill path outside every session's
  call stack. The session is never called, so an unreachable session
  cannot prevent its own stop.
- **Cleanup.** `stop` drains what compensation can undo, quarantines
  the rest, and an independent verifier walks the path's own records.
  Terminal states are `CLEAN`, `DIRTY_QUARANTINED`, and `UNKNOWN`; a
  late effect reopens the result.

`assess` runs the three AC-031 gates — isolation, kill, cleanup — and
`passed` means all three. `separate_statistics` keeps synthetic
sessions out of ordinary customer outcome statistics and reports them
as shared-resource impact; a synthetic session inside a customer
population is refused.

Honest scope: the production path here is a recording stand-in. No
production-path service exists in this repository. The deliverable is
the admission contract, the per-injection re-checks, the independent
kill, the cleanup verdicts, and the statistical separation — the parts
a real path plugs into.

## Fault adapters and conformance

`gauntlet_adapters` is the adapter interface and its conformance suite
(spec 8.2, 9.3, AC-028). An adapter MUST advertise its capabilities,
its unsupported paths, its interception location, its side-effect
semantics, and its cleanup guarantee, and it MUST pass the suite
before the product calls it contained.

The manifest is a strict closed contract: unknown fields fail, every
enumerated value comes from a fixed set, and together `capabilities`
and `unsupported_paths` must cover all nine fault families — silence
about a family is ambiguity, and ambiguity fails validation.

`run_conformance(adapter)` drives the adapter itself and returns a
publishable report. Nine checks, one per promise:

- `manifest-shape` — the advertisement validates.
- `advertised-capabilities` — every claimed family has a probe fault
  the adapter can actually apply.
- `unsupported-paths` — an unadvertised family refuses explicitly;
  silent application fails.
- `interception-location` — the site is outside the worker, and a
  receipt arrives with no worker running at all.
- `side-effect-semantics` — observed writes match the declared effect
  classes; declaring `none` while writing fails.
- `logging` — every apply emits one complete receipt
  (`emitted_by: adapter_outside_worker`), and the same fault yields
  the same receipt event id.
- `teardown` — the workspace returns to its installed state, even
  after a failed apply.
- `cleanup-guarantee` — the guarantee covers the declared effects
  (`external_write` needs `external_undo`).
- `isolation-coverage` — nothing outside the workspace changes, and
  fault paths that escape the workspace refuse.

The suite treats adapters as untrusted: any exception other than
`AdapterRefusal` fails the check that saw it, and a hostile adapter
that raises everywhere still gets a full report with nine failures.
The test suite proves rejections the same way — the reference adapter
passes whole, and one broken adapter per promise fails exactly its own
check.

`ReferenceFileAdapter` targets the file family and mirrors what the
scenario library's executor simulates: fault files written into the
workspace from outside the worker, receipts deterministic over the
fault's identity, teardown removing exactly what apply added.

## The MCP adapter

`gauntlet_adapters.mcp` is the Model Context Protocol adapter (T048,
spec 18.3, source S18, AC-032). The specification's one protocol-level
rule: an MCP integration "must preserve audience-bound authorization
rather than pass downstream tokens through indiscriminately." The
adapter sits at the `network_edge` between the worker's MCP client and
an MCP server, and enforces that rule on every tool call:

- **Audience binding.** Every call presents a worker credential whose
  `aud` claim must equal the target server's identity. A missing,
  malformed, wrong-audience, or audience-less credential refuses with
  an `AdapterRefusal` before anything dispatches — the server's call
  count does not move.
- **No passthrough.** The worker credential is consumed at the adapter
  boundary. The server authenticates the adapter's own audience-bound
  credential, so a token minted for the worker's purpose never travels
  downstream.
- **Redaction.** Server records, the adapter's dispatch log, and
  receipts carry keyed fingerprints (`hk_` HMAC pseudonyms, spec 19),
  never raw credential material.

The fault capability is `tool_result`. `apply` writes the client fault
config into the workspace (`.gauntlet/mcp-fault.json`) and arms an
in-flight mutation for one tool — `corrupt_payload` garbles the result
payload, `swap_error` replaces the result with an error. Other tools
pass through untouched, and `teardown` removes the config and disarms.

```python
from gauntlet_adapters import (
    MCPServer, MCPToolAdapter, default_tools, issue_credential,
    run_mcp_conformance,
)

adapter = MCPToolAdapter(MCPServer("srv_repos0000001", default_tools()))
token = issue_credential("srv_repos0000001", "worker:wlv001")
result = adapter.call_tool(workspace, "fetch_document",
                           {"path": "task.md"}, token)
```

`run_mcp_conformance(adapter)` returns the canonical nine-check report
plus four MCP-specific checks — `mcp-audience-binding`,
`mcp-no-passthrough`, `mcp-record-redaction`, `mcp-fault-in-flight` —
because AC-032 demands auth conformance and the canonical suite does
not test it. Each extra check is proven able to reject: an adapter
that launders wrong-audience tokens, forwards the worker token, logs
raw credentials, or never applies its fault fails exactly its own
check.

Honest scope: the server is a simulated in-process MCP server and the
credentials are an unsigned fixture encoding. The audience check is
the point, not the cryptography; a real deployment signs both tokens
and speaks the real transport, and the checks stay the same.

## Tests

```bash
cd execution-plane && python3 -m pytest -q
```
