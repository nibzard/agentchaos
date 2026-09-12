# Evidence plane

Go service that owns the authoritative evidence recorder (spec 9.4,
18.2). Worker claims, collector facts, and monitor interpretations
arrive as separate trust-labeled events (AC-012); the recorder
sequences them per source, chains them per tenant, signs checkpoints,
and turns delivery anomalies into explicit findings. Nothing here
takes a worker's word for what happened: the trust label says who is
speaking, and the role gate says who may say it.

## Surface

```text
POST /v1/evidence/events              ingest a batch of events
GET  /v1/evidence/events              list the tenant's events (run_id filter)
GET  /v1/evidence/chain               report the tenant's chain head
GET  /v1/evidence/verify              walk the chain and checkpoint signatures
GET  /v1/evidence/findings            list the tenant's derived findings
GET  /healthz                         liveness
```

Callers authenticate through the identity headers `X-ACX-Actor`,
`X-ACX-Tenant`, and `X-ACX-Role`, set by the deployment's
authentication front end. A tenant in a body never overrides the
authenticated tenant (spec 18.3). Ingest requires an
`Idempotency-Key` header matching `idk_[A-Za-z0-9_-]{8,128}`; reuse
with the same body replays the first reply, reuse with a different
body is a 409 conflict. Authentication runs before the ledger, so a
replay from an unauthenticated caller never surfaces a stored reply.

Reads serve `service`, `operator`, and `collector` roles. Workers see
evidence through the control plane, not the authoritative store.

## Trust labels and role authority

Every event carries one of three trust labels (spec 9.4, AC-012):

- `worker_claim` — the worker's own account. Lower trust by
  definition. Any authenticated role may submit one; the label itself
  marks it as a claim.
- `collector_fact` — an authoritative collector's observation.
  Only a `collector` identity may record one (spec 18.3: worker
  identities cannot ingest authoritative collector events).
- `monitor_interpretation` — a supervisor-side reading of behavior.
  Monitor, collector, service, and operator roles may record one.

Two consistency matrices back the labels up. The source component
must match the label: a worker never originates a collector fact, a
monitor never files a worker claim. And two event kinds are pinned:
`broker_decision` and `collector_heartbeat` are collector facts by
definition — a worker claiming either is exactly the confusion the
labels exist to prevent. Collector events must also declare coverage
(`observed` or `contained`), which feeds the containment
coverage-loss trip condition (spec 13.2).

## Batches are all-or-nothing

A batch refuses whole on any contract violation, and nothing is
stored. A stored half would turn an idempotent replay into a
different answer. Two exceptions are not violations:

- A duplicate event id is deduplicated; at-least-once delivery is the
  norm and the first copy stands (spec 18.3).
- Sequence reuse under a fresh event id refuses the batch: two events
  claiming one slot is a contract violation, not a delivery
  artifact.

Unknown fields fail closed at every nesting level. The decoder checks
the wire bytes, never a re-marshaled struct — re-encoding would
silently drop unknown keys (AC-001).

## Sequence policy

Each source numbers its events; no global total order is assumed
(spec 9.4). Correlation IDs, parent edges, and recorded clock
uncertainty travel on every event. The frontier logic:

- A sequence jump past `last + 1` is a gap. The recorder stores the
  event and opens an `evidence_gap` finding (severity H1) whose
  `coverage_gap` names the source, the stream's kind, and the missing
  range. A source whose first event is not sequence 0 is a gap.
- A late arrival below the frontier is stored as delivered — no
  silent repair — with its own finding.
- A clock more than ten minutes from the recorder's clock (tunable)
  opens a finding; the recorded uncertainty rides along in the
  description.

Findings are Finding documents (spec 18.1) with evidence references.
A gap finding says what is absent; it never invents content.

## Chain, checkpoints, retention

Storage is append-only, per tenant. Each event's canonical bytes —
every contract field, payload content included — hash onto the
tenant's chain with the previous digest. `verify` walks the chain and
re-checks every checkpoint signature; any modified or removed event
breaks it at the first divergence.

The chain's honesty limits: it detects later modification, not loss.
Truncating the tail leaves a valid chain over the remainder — gaps
find loss, and checkpoints bound it. A checkpoint signs one source's
contiguous sequence range (ed25519 over the digest basis, linked to
the previous checkpoint), and the frontier walk guarantees a
checkpoint never covers a gap.

Retention tombstones `object_ref` payloads older than the horizon.
Only the live copy changes; the chained original keeps the digest and
storage reference, so the evidence still names what existed and
`verify` still passes (spec 19). Inline and metadata-only payloads
have nothing to delete.

## Build and test

```sh
cd evidence-plane
go test ./...
go run ./cmd/evid   # serves on 127.0.0.1:8082
```

The cross-language test emits stored events and findings and
validates them against `shared/schemas` through the shared Python
validator (`shared/python/acx_schemas`).
