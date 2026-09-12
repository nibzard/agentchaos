# 0002: Contract schema conventions

## Status

Accepted

## Context

Task T002 defines strict schemas for the ten primary resources in
specification section 18.1: WorkloadVersion, AutonomyProfile,
ScenarioVersion, Experiment, Run, Delegation, Effect, EvidenceEvent,
Finding, and AssuranceClaim. The specification requires that unknown
fields in security-sensitive manifests and verdicts fail validation
(section 18.3, AC-001) and that version compatibility is explicit.

The contracts must serve the Python control plane, execution plane,
evidence plane, and CLI, and stay consumable by the Go broker and
governor and the TypeScript UI later.

## Decision

Write the contracts as JSON Schema draft 2020-12 files in
`shared/schemas/`, one file per resource plus `common.schema.json`
for shared definitions. A machine-readable `registry.json` lists
every contract and its resource kind. The `acx-schemas` Python
package under `shared/python/` loads the registry and validates
instances fail-closed.

### Strictness rules

Every object shape is closed. `additionalProperties` is `false`, or a
restricted subschema, everywhere a schema defines a value's shape.
Applicator conditions (`if`, `then`, `else`, `not`, `contains`) add
constraints but never open a shape. The meta-checker in
`acx_schemas.strictness` walks every schema, resolves references, and
fails on open shapes, `format` keywords (patterns are used instead, so
validation never depends on a format checker being enabled), empty
enums, and `required` keys without property definitions.

### Identity and tenancy

Every resource carries `kind` (a const), `api_version` (enum, `v1`),
`tenant_id`, and a prefixed `id`. Identifier prefixes: `tnt_`, `wlv_`,
`aup_`, `scn_`, `exp_`, `run_`, `dlg_`, `eff_`, `evt_`, `fnd_`,
`clm_`, plus `act_`, `src_`, and `tgt_` for actors, sources, and
enrolled targets. Tenant binding happens server-side (section 18.3);
the fields exist so every stored record is auditable per tenant.

### Enumeration policy

Shared enums live in `common.schema.json` and use the exact value
names from the specification: effect states from section 10.1, run
outcomes from 9.2, terminal states from 13.3, review verdicts from
11.2, assurance statuses from 14.1, severity classes from 14.6, trust
labels from 9.4, evidence kinds from 9.4, fault kinds from 9.3, and
operating modes from section 7. Where the specification forbids a
state in beta, the contract makes it unrepresentable rather than
forbidden by convention: `A3` is absent from effect action classes and
profile action-class lists, `allow` is absent from reviewer-timeout
fallbacks, and selector kinds resolve only to enrolled targets.

### Delegation of enforcement

Schemas fix structure, not behavior. Signature verification,
cross-field arithmetic, budget accounting, subset checks for
delegation, and statistical computation belong to the compiler (T003),
broker (T007), governor (T009), evidence plane (T011), and statistics
code (T022). Schema descriptions record this split so a reader can
tell an intentional delegation from a gap.

### Canonical formats

- Timestamps: RFC 3339, UTC, explicit `Z`, optional fractional
  seconds. Clock uncertainty is a separate field on evidence events.
- Digests: `sha256:` plus 64 lowercase hex characters.
- Money: integer micro-units with an ISO-4217 currency code.
- Contract URIs: `https://gauntlet.invalid/schemas/v1/...`. The
  reserved `.invalid` top-level domain marks a working-name product
  whose public naming is unresolved (spec S01).

### Versioning

An unknown `api_version` fails validation. Contract changes that
alter meaning require a new version identifier, not an edit to `v1`.
Additive-only changes within `v1` are permitted only when every
existing valid instance stays valid.

## Consequences

Downstream tasks get one import surface (`acx_schemas.validate`) and
machine-readable contracts for Go and TypeScript consumption. The
meta-checker keeps future edits strict without relying on review
discipline alone. Fixtures in `shared/fixtures/valid/` double as
documentation and compiler test inputs.

The strictness comes at a cost: any field a future feature needs must
be added as a new contract revision or a new `api_version`, and the
schema files themselves are the only place enums can change.
