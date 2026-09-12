# Effect broker

Go service that owns the mandatory effect broker's HTTP tool
interface (ADR-0001, spec 6.1, 10, 18.2). Workers propose effects;
the broker decides them against a deterministic policy and dispatches
only through bound permits with recorded receipts. The broker is part
of the trusted computing base: it runs outside the worker environment
and holds the only downstream credentials.

## Surface

```text
POST /v1/effects/authorizations   evaluate a proposal (allow or deny)
POST /v1/effects/{id}/commit      dispatch a bound effect
GET  /healthz                     liveness
```

Callers authenticate through the identity headers `X-ACX-Actor`,
`X-ACX-Tenant`, and `X-ACX-Role`, set by the deployment's
authentication front end. A tenant in a request body never overrides
the authenticated tenant (spec 18.3). Worker and collector roles are
refused on both mutations: workers cannot issue their own permits.

A deny is a successful evaluation. `authorizations` returns 200 with
the `DENIED` effect and the decision (verdict, reason, policy
references, evidence event id); transport and schema failures return
problem bodies with a stable code, a safe message, retryability, and
a request id.

Every mutation requires an `Idempotency-Key` header matching
`idk_[A-Za-z0-9_-]{8,128}`. Reuse with the same body replays the
first reply; reuse with a different body is a 409 conflict. The
ledger is scoped by tenant, and authentication and role checks run
before it, so a replay from an unauthenticated caller, another
tenant, or a worker never surfaces a stored reply. Reservation is
atomic: concurrent requests sharing a key execute the mutation once.

## Deterministic gate

The operation registry in `policy.json` is the boundary of supported
external tool calls. Each operation declares its action class, its
side-effect semantics (`read` or `mutate`), allowed destinations, a
size ceiling, and an optional money limit. The gate fails closed on:

- an operation with no rule (`unknown_operation`);
- a run the broker does not know, or a run from another tenant;
- an expired grant (expiry equal to now authorizes nothing);
- a class the run does not permit, or a proposal whose class label
  disagrees with the rule (a worker cannot downgrade semantics);
- a destination outside the rule's scope: http(s) entries match the
  exact scheme, host, and port plus a path prefix, so a host that
  merely starts with an allowed host's name is denied;
- content above the size ceiling.

Reads are not assumed harmless (spec 6.1): `http.request` is an A1
brokered read with destination and size checks.

An allowed proposal gets a bound permit: task id, policy version and
digest, destination and argument digest from the proposal, a size or
money limit, a five-minute expiry clamped to the grant window, and a
single-use nonce. A new authorization mints a fresh nonce. Denied
effects carry no permit, so a replayed denial cannot later look
pre-authorized (AC-009).

## Dispatch and receipts

`commit` runs a two-phase dispatch where the sink's service supports
it (spec 10.1):

1. **Preparation.** If the sink implements `PreparingSink`, the
   staged write happens before any send: `AUTHORIZED → PREPARED`,
   journaled as a `tool_request` event. A refused stage cancels the
   effect without sending. An unresolved stage leaves the effect
   `UNKNOWN_EFFECT`, because a staged write may exist. Sinks without
   preparation dispatch directly from `AUTHORIZED`; the limitation is
   declared by the absence of a stage record, never by a fabricated
   one.
2. **Dispatch.** The effect moves to `COMMITTING` — or to
   `COMPENSATING` when it carries `compensation_of` — and the sink
   that owns the destination performs the send. The dispatch record
   carries the commit request's idempotency key, so the external
   service can deduplicate.

The outcome decides the resting state:

- `acknowledged` → `COMMITTED` with a reconciled receipt (source,
  digest, evidence event id);
- `timeout_unknown` → `UNKNOWN_EFFECT` with an unreconciled receipt.
  A timeout after dispatch is an unknown outcome that reconciliation
  must resolve before any retry; the broker never reissues blindly
  (spec 10.1, AC-010);
- `failed` → `CANCELLED`; the send never took effect.

An outcome the broker does not recognize also stays `UNKNOWN_EFFECT`:
it is never recorded as "no effect happened". Every attempted
dispatch, including a failed one, lands in the evidence journal.

## Reconciliation and compensation

A commit of an `UNKNOWN_EFFECT` effect performs a state read through
the sink's `ReconcilingSink` interface instead of a dispatch. The
read resolves the outcome:

- the send took effect → `COMMITTED` with a reconciled receipt;
- the send never happened → `CANCELLED`;
- still unresolved → the state stands and the attempt is journaled as
  a `recovery_action` event.

A destination with no state read refuses the commit: reconciliation
is manual, and the refusal says so. A repeated commit can be retried
until the read resolves.

A compensation is a new authorized effect that references a
`COMMITTED` original through `compensation_of` (spec 10.1). The
reference must resolve to a committed effect in the same tenant;
anything else denies with `compensation_target_invalid`. The
compensating effect dispatches through `COMPENSATING` and keeps its
own record. The original effect keeps its own state, and the broker
never claims a compensation restores it.

An expired permit transitions the effect to `EXPIRED` and refuses the
commit. A commit of a denied, committed, or cancelled effect is an
`invalid_transition` conflict. A re-proposal under an effect id that
already has a record conflicts with `effect_exists`; the lifecycle is
append-only, so a re-proposal uses a fresh id. A destination no sink
owns fails closed: unsupported paths never dispatch. A permit whose
task binding no longer matches the run never dispatches.

Dispatch attempts on one effect serialize on a per-effect gate, and
the external sink calls run with the broker lock released: a slow or
hung sink fences only its own effect, never the journal, the
idempotency ledger, or other tenants (spec 10.2). Racing commits of
one effect reach the sink exactly once. The authorize path evaluates,
journals the decision, and stores the record in one critical section,
so racing proposals under one effect id produce exactly one decision
event and one record. The idempotency ledger keeps exactly one reply
per key; a retried execution that reaches `Complete` after another
executor already settled the key is dropped, never a second
`Settled`-style channel close.

Every decision, stage, receipt, and recovery action is recorded as an
`EvidenceEvent` (`broker_decision`, `tool_request`,
`external_receipt`, `recovery_action`) with the broker as its source,
`collector_fact` trust, and an inline minimized payload. Sequences
increase per source. The evidence plane's collector consumes this
journal in a later task.

The Effect records and evidence events this broker emits validate
against the shared contracts in `shared/schemas/`. A cross-language
test (`crosslang_test.go`) feeds every emitted shape — including
staged, compensating, and reconciled documents — through the
`acx-schemas` Python validator and skips when it is not installed.

## Later tasks

Risk-routed machine review attaches `Review` records later; the
deterministic gate alone decides these effects.

## Build and test

```bash
cd broker && go test ./...
go run ./cmd/brokerd            # serve on 127.0.0.1:8081
go run ./cmd/brokerd -policy ./policy.json -addr :8081
```
