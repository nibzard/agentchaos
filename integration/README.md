# Integration tests

Cross-plane fault tests (T041). The harness composes the monolith the
way spec 8.1 draws it: the API front end verifies principal tokens
(T027), the broker sits behind it as an isolated HTTP upstream, and the
governor and evidence plane run in-process. Faults enter only through
the seams a deployment leaves open — the synthetic sink's responder
hooks, the supervisor's deadline reviewer, and the wire itself.

## What each test proves

| Test | Fault | Guarantee under fault |
| --- | --- | --- |
| Reviewer outage | Contextual reviewer exceeds its deadline | Effects that need review hold (F19, spec 10.2); local work and the deterministic gate continue (AC-021); recovery decides on the same record |
| Evidence capture failure | Evidence fence engaged on the broker | New proposals deny `evidence_capture_fenced`; authorized permits keep state and refuse to commit; release resumes without loss (F18) |
| Unknown dispatch | Sink times out | Effect lands `UNKNOWN_EFFECT`; resolution reads sink state — one dispatch, one state read, never a blind reissue (AC-010, spec 10.1) |
| Clock disagreement | Source clock 3 hours off | The event stores and the disagreement becomes a finding; the chain stays intact (spec 9.4) |
| Delivery faults | Replay, sequence gap, late arrival | Replays deduplicate by event id; gaps and reorders become explicit findings; the chain verifies (spec 18.3) |
| Dishonest transcript | A denied operation re-proposed | Layer 1 allows the retry; layer 2 routes it (`denied_retry`, high); layer 3 denies with a contract-valid verdict (spec 11) |
| Bypass attempts | Forged tokens, forged role headers, role abuse | Forged tokens 401; caller-set identity headers never survive the front end; workers and collectors cannot fence or stop |
| Stop protocol | Operator stop through the API | The governor trips, the broker executes the stop, and the next proposal denies `run_stopped` |

## Running

```bash
cd integration && go test ./...
```

The suite is pure Go: no Python compiler runs, because no test creates
an experiment. Per-plane fault detail stays in each module's own suite;
these tests assert what survives composition.
