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

`commit` moves an `AUTHORIZED` effect to `COMMITTING` and hands it to
the sink that owns the destination. Sinks sit outside the worker;
`SyntheticSink` owns `sink:` destinations for fixture runs. The
outcome decides the state:

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

An expired permit transitions the effect to `EXPIRED` and refuses the
commit. A second commit, or a commit of a denied, unknown, or
cancelled effect, is an `invalid_transition` conflict. A re-proposal
under an effect id that already has a record conflicts with
`effect_exists`; the lifecycle is append-only, so a re-proposal uses
a fresh id. A destination no sink owns fails closed: unsupported
paths never dispatch.

Every decision and receipt is recorded as an `EvidenceEvent`
(`broker_decision`, `external_receipt`) with the broker as its
source, `collector_fact` trust, and an inline minimized payload.
Sequences increase per source. The evidence plane's collector
consumes this journal in a later task.

The Effect records and evidence events this broker emits validate
against the shared contracts in `shared/schemas/`. A cross-language
test (`crosslang_test.go`) feeds every emitted shape through the
`acx-schemas` Python validator and skips when it is not installed.

## Later tasks

The full lifecycle state machine (PREPARED, COMPENSATING,
reconciliation of `UNKNOWN_EFFECT`) is T007. Risk-routed machine
review attaches `Review` records later; the deterministic gate alone
decides T006 effects.

## Build and test

```bash
cd broker && go test ./...
go run ./cmd/brokerd            # serve on 127.0.0.1:8081
go run ./cmd/brokerd -policy ./policy.json -addr :8081
```
