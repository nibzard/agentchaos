# Beta API

The API monolith (ADR-0001, spec 8.1, 18.2, T026). One Go service owns
the experiment lifecycle, mounts the governor and the evidence plane in
process, computes assurance claims, and forwards effect traffic to the
separately isolated broker.

## Composition

Spec 8.1 prefers a modular monolith plus a separately isolated broker
over many microservices at beta:

- The **governor** and the **evidence plane** run in process. Their
  handlers mount under this service's routes, so run reads and evidence
  ingest never disagree with the components.
- The **broker** stays a separate service. Every effect route is a
  transparent reverse proxy: identity headers, idempotency keys, and
  bodies pass through unchanged, and the broker's own decisions and
  problem envelopes come back as the reply. The broker remains the
  enforcement point; the proxy adds nothing.
- The **compiler** stays Python (spec 9.1: only the deterministic
  compiler authorizes execution). Validation shells out to
  `python3 -m acx_compiler` in `../control-plane`: one JSON request on
  standard input, one JSON reply on standard output. Compile failures
  are results (`ok=false`, exit 0); a nonzero exit is an outage and
  reports `compiler_unavailable`, never a silent pass.

## Surface

```text
POST /v1/experiments                    store a draft manifest
POST /v1/experiments/{id}/validation    compile without execution
POST /v1/experiments/{id}/runs          register the envelope, start a run
GET  /v1/runs/{id}                      run state (governor)
POST /v1/runs/{id}/stop                 fence the run, execute the stop
GET  /v1/runs/{id}/stop                 the broker's stop report
POST /v1/evidence/events                collector batches (evidence plane)
GET  /v1/evidence/*                     chain, verify, findings (evidence)
POST /v1/effects/authorizations         broker proxy
POST /v1/effects/{id}/commit            broker proxy
POST /v1/effects/{id}/review            broker proxy
POST /v1/delegations[...]               broker proxy
GET  /v1/quarantine                     broker proxy
POST /v1/assurance-claims               assess a fixed cohort
GET  /v1/assurance-claims/{id}          read a claim
POST /v1/safety-levers/{scope}/engage   fence tenant or experiment
GET  /healthz                           liveness
```

Callers authenticate through the identity headers `X-ACX-Actor`,
`X-ACX-Tenant`, and `X-ACX-Role`, set by the deployment's
authentication front end. A tenant in a request body never overrides
the authenticated tenant (spec 18.3). Every API-owned mutation requires
an `Idempotency-Key` matching `idk_[A-Za-z0-9_-]{8,128}`; reuse with
the same body replays the stored reply, and reuse with a different body
is a 409 conflict. Authentication and role checks run before the reply
ledger, so a replay from an unauthenticated or wrong-role caller never
surfaces a stored reply.

Roles:

- Service and operator identities create, validate, and run
  experiments, and assess claims.
- Service, operator, and customer identities stop runs and engage
  safety levers. The customer controls never depend on the main UI or
  on an operator being reachable (spec 13.3).
- Worker identities cannot alter experiments, assess claims, or engage
  levers. The evidence plane itself refuses a collector fact from a
  non-collector identity, and the broker refuses worker and collector
  callers on every mutation.

## Experiment lifecycle

1. `POST /v1/experiments` stores a draft. The route enforces the
   top-level Experiment contract: unknown fields fail closed, a
   smuggled `plan` is rejected (only the compiler attaches one), a new
   experiment starts as draft, and a body tenant claim cannot override
   the authenticated tenant.
2. `POST /v1/experiments/{id}/validation` compiles the stored manifest.
   The referenced records travel with the request: workloads,
   profiles, scenarios, targets, credentials. On success the plan block
   is attached and the experiment moves to `compiled`. On failure the
   reply is 422 `compile_failed` with every compiler problem, and
   nothing changes — compilation fails closed (spec 9.1).
3. `POST /v1/experiments/{id}/runs` requires a stored compilation. The
   first run registers the governor safety envelope, translated from
   the digest-covered plan document: selectors (the compiled snapshot),
   budgets, stop rules, and the session cap. Later runs reuse the
   immutable envelope. The run request names the allowed primitives
   because the Experiment contract carries no operation names; the
   governor validates them (one to 128, unique, operation pattern).

A run start refuses for the governor's reasons and passes them through
as problem envelopes: `tenant_fenced`, `experiment_fenced`,
`concurrency_exhausted`, and so on.

## Run stop and safety levers

`POST /v1/runs/{id}/stop` spans two components (spec 13.3):

1. The governor trips the run on `operator_request` — the routine stop,
   distinct from the emergency control — which ends experiment
   authority and emits the stop handoff.
2. The broker executes the ten-step stop protocol with the caller's
   order (sandbox disposition, compensations). The caller's identity
   and idempotency key travel with it, so the broker's own ledger sees
   one stop per key.

The reply reports both: the fenced governor run and the broker's stop
report with its terminal state. If the broker is unreachable the
request fails retryable (502 `broker_unreachable`) and says that the
governor fence stands.

`POST /v1/safety-levers/{scope}/engage` is the emergency control
(spec 13.2). The scope segment is `tenant` or an experiment id; it maps
to the governor's emergency stop, which terminates every active run in
scope, fences the scope against new runs, and emits a handoff per run.
Engaging a lever for an experiment with no registered envelope is a
404 — there is nothing to fence.

## Assurance claims

`POST /v1/assurance-claims` assesses a fixed cohort (spec 14) through
the exact one-sided binomial bounds of the control module, and stores
the emitted AssuranceClaim document. The request mirrors the claim
contract with strict keys at every nesting level — unknown fields fail
closed. The tenant never appears in the request. `GET
/v1/assurance-claims/{id}` returns the stored claim; a cross-tenant
read is indistinguishable from absence.

## Build and test

```bash
cd api && go test ./...
go run ./cmd/apid   # serve on 127.0.0.1:8080, broker at :8081
```

The suite wires a real governor, evidence recorder, and a live broker
upstream in process, and drives the fixture experiment through the
compiler subprocess end to end: create, validate, run, stop, and the
post-stop fence that denies new effects with `run_stopped`. Compiler
tests skip when python3 is unavailable.
