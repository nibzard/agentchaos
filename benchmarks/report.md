# Beta target benchmark report

Generated 2026-09-12T15:31:54Z by `benchmarks/run.sh`.

In-process measurements from one development machine. They exercise the real code paths but do not reproduce the beta measurement conditions (reference deployments, network services, live models), and they certify nothing.

| Area | Beta target | Measured | Condition | Status |
|---|---|---|---|---|
| Local deterministic gate | p95 added latency <= 10 ms | p95 0.113 ms (p50 0.048 ms, p99 0.402 ms) | in-process authorize path, single machine, bounded policy set, no network | measured |
| Context reviewer deadline | default 3 s decision deadline; on expiry the profile fallback holds, never a silent allow | default deadline 3 s; every timed-out decision fell back to hold (zero silent allows in benchmark) | in-process DeadlineReviewer over a reviewer slower than the deadline; model latency itself not measured | measured (enforcement, not model latency) |
| End-to-end overhead | median added wall time <= 15% | median 3.5 ms added per 3-pair run (0.12% of simulated wall time) | simulated 0.5 s variants, local filesystem, no network; the beta condition is tasks >= 30 s, which this bench does not reach | measured at short durations |
| Monitoring inference cost | median <= 20% of worker inference cost | not measured: needs live model calls on both sides; deterministic review tier measured at 383730 decisions/second | requires a reference workload with real inference | not measured |
| Event ingest | 5,000 metadata events/second | 72411 events/second | in-process recorder ingest, 1 KB inline events, batches of 100, single stream, no HTTP, one machine | measured (library, not the service) |
| Broker throughput | 500 deterministic decisions/second | 15407 decisions/second | in-process authorize path, single machine, bounded policy set, no HTTP | measured (library, not the service) |
| Safety grant expiry | 10 s lease; nothing accepted after expiry | expired-grant denial path 34.7 us per decision, same order as the allow path; refusal enforcement covered by the broker test suite | in-process authorize against an expired grant | measured (enforcement) |
| Fencing acknowledgment | p99 <= 2 s for the enrolled broker | p99 0.02 ms (p50 0.02 ms) from trip to observable fenced state | in-process emergency stop over two live runs, state read included; no network | measured |
| Evidence durability | intent durable before dispatch | behavior, not latency: the evidence fence holds new external effects while capture is down; covered by the broker gate tests | broker test suite (gate behavior) | covered by tests |
| Hosted service availability | 99.9% monthly design objective | not measured: no hosted deployment exists | requires a running deployment and a month | not measured |
| First fixture result | under 30 minutes | automated environment lifecycle 0.2 ms | local filesystem only; tool installation and account provisioning are not measured | partial |
| Real workflow integration | under one engineer-day | not measured: no partner integration exists yet | requires a supported broker/harness path and an enrolled environment | not measured |

## Raw output

The unedited benchmark output lives in `benchmarks/raw/`.
