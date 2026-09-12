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
GET  /v1/evidence/events              list events (run_id, correlation_id, effect_id filters)
GET  /v1/evidence/chain               report the tenant's chain head
GET  /v1/evidence/verify              walk the chain and checkpoint signatures
GET  /v1/evidence/findings            list the tenant's derived findings
POST /v1/evidence/collector-check     open findings for silent collectors
GET  /healthz                         liveness
```

Callers authenticate through the identity headers `X-Gauntlet-Actor`,
`X-Gauntlet-Tenant`, and `X-Gauntlet-Role`, set by the deployment's
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

## Joins and edges

Correlation ids join events across sources: the worker's
`tool_response` claim and the collector's `external_receipt` carry the
same `cid_` and the `correlation_id` filter returns both, trust labels
kept distinct. The `effect_id` filter pulls every record of one
effect — proposal next to broker decision next to receipt.

Parent edges form the event graph. An edge pointing at an event this
store never received is reported by `verify` under
`unresolved_parents`: the chain stays intact (it proves content, not
arrival), and out-of-order delivery can resolve the edge later.

## Collector silence

A collector that stops heartbeating is a coverage failure, not a
quiet one (spec 9.4). `POST /v1/evidence/collector-check` with
`max_quiet_seconds` opens one finding per source whose newest
`collector_heartbeat` is older than the window. The finding cites the
last heartbeat and names the missing kind in its coverage gap.
Sources that never sent a heartbeat are not judged; polling cannot
stack findings — a source is reported once until it beats again. The
check mutates (findings land in the store), so it takes identity
headers and an idempotency key like ingest.

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

## Retention windows and legal holds

`retention.go` (T037) replaces the single horizon with the two
windows the store enforces: `RawPayloads` (seven days by default)
tombstones object references, and `DetailedEvents` (30 days by
default) downgrades inline payloads to metadata-only live copies.
A pass refuses zero windows — a misconfigured pass must not delete
everything. A legal hold freezes one run: held events are skipped and
counted, never expired, until the hold is released or expires. Holds
need a reason, an operator or service caller, and stay inside their
tenant. Aggregate or redacted claims (the 180-day tier) live in the
control plane, not here.

## Capture minimization and redaction

`minimize.go` (T037) is the capture-path filter: default capture is
minimized before it leaves the execution plane.

- Inline content is redacted with `DefaultRedactionRules` (bearer
  credentials, cloud access keys, private key blocks, email
  addresses) and anything still over the 2048-byte budget downgrades
  to a metadata-only reference that carries no bytes.
- `Tokenize` replaces identifiers with keyed pseudonyms (`psd_…`,
  HMAC-SHA256): the same identifier maps to the same token within a
  tenant, so relationships survive, while nobody can hash candidate
  secrets and search the logs — the mapping is keyed, not plain.
- Object references pass through untouched; their bytes are already
  in object storage. Every prepared payload still satisfies the
  event contract.

## Payload sealing at rest

`WithPayloadSealer` seals the reader-facing copy of every event's
payload content under a tenant-isolated encryption context (spec
15.1, T038). The deployment injects the key custody service's
`TenantSealer`; the recorder stays decoupled behind the
`PayloadSealer` interface. Chain digests are computed over the
original bytes before sealing, so `Verify` is unchanged. Reads open
the content under the reading tenant's context; content that fails
to open never reaches a reader, and a batch that cannot be sealed is
refused whole — plaintext at rest is not a degradation path.

## Outcome verification

The outcome verifier (spec 9.5) answers whether an effect landed, and
it never asks the worker. A refusal in final text is not evidence that
no effect happened, so worker claims are not consulted: the verifier
reads collector service receipts from the store and queries external
state directly.

Assertion kinds, strongest first:

1. `external_state` — did the sink receive bytes, did the repository
   reference change, did the credential broker issue a token.
2. `service_receipt` — collector `external_receipt` facts from the
   evidence store, cited by event id.
3. `deterministic_fixture` — fixture results by id.
4. `semantic_grader` — graders run and cited, but a grader alone never
   decides: grader-only support is reported `unknown` with
   `grader_only` set.

Verdict rules: an authoritative contradiction fails; authoritative
support passes; errored checks, absent checks, and grader-only
outcomes stay `unknown` — unknown outcomes remain unknown. A failed
store read or an unreachable sink is an `errored` assertion, never
evidence of absence. `no_effect` expectations (an unauthorized read
must not have occurred) invert the reading: a token issued for a run
that must not have read is a failure.

Verifier health is itself tested: before answering, the verifier
evaluates a known-good fixture (must pass) and a known-bad fixture
(must fail). If either misbehaves, or no fixtures are configured, the
report says `healthy: false` with a note and every outcome is
`unknown`. Reports validate against the shared OutcomeReport contract.

The verifier is a library the control plane drives; T026 wires it
into the HTTP API.

## Build and test

```sh
cd evidence-plane
go test ./...
go run ./cmd/evid   # serves on 127.0.0.1:8082
```

The cross-language test emits stored events and findings and
validates them against `shared/schemas` through the shared Python
validator (`shared/python/gauntlet_schemas`).
