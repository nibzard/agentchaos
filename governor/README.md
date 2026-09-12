# Safety governor

Go service that implements the independent safety governor (spec
13.2). The governor is separate from the experiment runner and its
LLMs: the runner holds experiment authority only through short-lived
grants the governor issues, and every time bound is measured on the
governor's own clock. A runner or model outage can delay a heartbeat
but never extend a grant (spec 10.2, AC-006).

## Surface

```text
POST /v1/envelopes                    register an experiment safety envelope
GET  /v1/envelopes/{id}               read one envelope
POST /v1/runs                         start a run; issues the first grant
GET  /v1/runs/{id}                    read the run's governor record
POST /v1/runs/{id}/heartbeats         renew the grant lease
POST /v1/runs/{id}/incidents          report an observed trip condition
POST /v1/runs/{id}/cleanup-state      record the cleanup terminal state
GET  /v1/runs/{id}/stop-handoff       fetch the stop handoff
POST /v1/emergency-stop               revoke experiment authority
GET  /healthz                         liveness
```

Callers authenticate through the identity headers `X-ACX-Actor`,
`X-ACX-Tenant`, and `X-ACX-Role`, set by the deployment's
authentication front end. A tenant in a request body never overrides
the authenticated tenant (spec 18.3).

## Grants and heartbeats

The default grant lease is ten seconds with renewal
(`GrantLeaseTTL`). Starting a run mints the first lease; the runner
keeps authority only by heartbeating inside the window. Expiry equal
to now authorizes nothing. A beat that arrives after expiry trips
`grant_expiry` instead of renewing, and a daemon tick (`Sweep`, one
second by default in `cmd/governord`) trips lapsed runs without any
runner participation — enforcement immediately rejects new experiment
work after expiration.

Every renewal is checked, in one critical section, on the governor's
clock:

- the run is active, unfenced, and unexpired;
- the beat's generation is current (a retried beat naming the previous
  generation replays the current grant; anything older is refused as
  stale delivery);
- every observed target falls inside the envelope's eligible set;
- spend claims keep the per-session and aggregate ceilings;
- the renewal never extends past the duration deadline: the new expiry
  is the earlier of now plus the lease and the deadline.

Spend claims are lower bounds. The recorded total for a session only
rises; a runner cannot lower it by reporting a smaller number. A claim
in a currency the budget cannot denominate is incomparable, so it
trips rather than passes. Aggregate sums compare against the ceiling
in subtraction form, so extreme values saturate at the ceiling instead
of wrapping under it.

A run holds a concurrency slot while its lease is live: the budget
caps concurrently granted runs, so a lapsed lease frees its slot even
before the sweep trips it.

## Safety envelopes

`POST /v1/envelopes` records an experiment's safety envelope
(spec 13.1): explicit enrolled selectors with the recorded selection
seed and exclusion list, duration and concurrency budgets, per-session
and aggregate cost ceilings, allowed primitives, stop rules, and the
session bound. Registration is append-only, and an envelope whose
experiment has started runs is immutable — a template cannot widen its
own envelope. Eligibility is the union of every selector's targets
minus every exclusion; wildcard public destinations are not
representable.

## Trip conditions

The governor trips on the spec 13.2 conditions. Some it detects from
heartbeats (`unexpected_target_expansion`, `budget_exhaustion`,
`grant_expiry`); others arrive as incident reports from the broker,
collectors, and monitors (`unauthorized_effect`,
`containment_coverage_loss`, `evidence_persistence_failure`,
`service_health_threshold`), and every report trips fail-closed. A
service-health incident compares the observed value against the
matching stop rule's threshold; a threshold condition with no declared
threshold cannot be evaluated and trips.

The envelope's stop rules map a condition to an action:

- `stop_injection` stops fault injection but does not fence effects.
  The grant keeps renewing — flagged `injection_stopped` — so the run
  can observe and record evidence. Stopping injection and task
  termination are separate operations (spec 13.2).
- `fence_effects` fences the run: every later renewal is refused and a
  stop handoff is emitted.
- `terminate` stops the run outright with a stop handoff.

A condition with no matching rule fences — the fail-closed reading.
One condition trips a run once; later raises land in the decision log
only.

## Emergency stop

`POST /v1/emergency-stop` is the customer-accessible control
(spec 13.2): operator or customer role, never a worker or the runner's
service identity, and it depends on nothing but this service and the
caller's credentials — never the main UI or the model provider. The
stop terminates every active run in scope (one experiment or the whole
tenant), emits a stop handoff for each, and fences the scope so no new
run starts. Termination is forced: an envelope's stop rules cannot
weaken the emergency control. The stop is idempotent.

## Stop handoff

When a run is fenced or terminated, the governor emits a `StopHandoff`
document that lists the spec 13.3 protocol in order: revoke new effect
permits, disable injectors, fence the delegation group, cancel pending
effects, identify in-flight and unknown effects, reconcile receipts,
execute preapproved compensation, terminate or preserve the sandbox,
run the independent cleanup verifier, and record the terminal state.
Every step starts pending; nothing is marked done because a worker
exited. The stop controller (a later task) executes the protocol and
reports the terminal state back through
`POST /v1/runs/{id}/cleanup-state` — `CLEAN`, `DIRTY_QUARANTINED`, or
`UNKNOWN` — and the first report wins.

## Evidence and decisions

The evidence contract's event kinds come from spec 9.4 and carry no
governor-specific kind, so the governor journals within the closed
set: enforcement actions (trips, fences, emergency stops, stop
handoffs, cleanup states) are `recovery_action` events, and accepted
spend accounting is `budget_change` events. Both carry the governor as
their source with `collector_fact` trust, per-source sequences, and
minimized inline payloads (spec 19).

Grant issuance and renewal are recorded in the governor's own
append-only decision log rather than the evidence journal — capture is
minimized by default, and the grant is fully described by the run
record the API returns. A tenant-wide emergency stop with no active
runs journals nothing for the same reason; the decision log keeps it.

The EvidenceEvents this governor emits validate against the shared
contracts in `shared/schemas/`. A cross-language test
(`crosslang_test.go`) feeds every emitted shape through the
`acx-schemas` Python validator and skips when it is not installed.

## Idempotency

Mutations are idempotent by construction, not through a separate
idempotency ledger: the registries are append-only (a retried
envelope or run start surfaces the existing record as a conflict), a
retried heartbeat replays the current grant (the generation guard), a
condition trips a run once, the emergency stop is a no-op when the
scope is already fenced, and the first cleanup report wins.

## Declared limitations

- Registration, run, and grant state is in memory; durable state is
  the control plane's store (a later task). A restart drops envelopes
  and runs, and a run whose envelope vanished refuses every renewal —
  failing closed.
- There is no un-fence API: an emergency-stopped tenant or experiment
  stays fenced for the life of this process. Lifting a fence is a
  deliberate control-plane action in a later task.
- Heartbeats carry spend claims and observed targets only. Containment
  coverage and evidence persistence are observed by the collector and
  arrive as incident reports; the governor has no direct telemetry.
- The broker consumes `GrantExpiresAt` from its run context today. The
  wiring that refreshes that value from this governor's grant is part
  of the execution-plane integration (a later task).

## Build and test

```bash
cd governor && go test ./...
go run ./cmd/governord            # serve on 127.0.0.1:8082
go run ./cmd/governord -addr :8082 -sweep-every 1s
```
