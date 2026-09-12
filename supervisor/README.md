# Supervisor

The non-deterministic supervision layers of spec 11.1 (T018): a fast
detector that reads a bounded evidence window and routes review, and
a contextual reviewer that decides held proposals under a deadline.
The deterministic gate (layer 1) stays in the broker — nothing in
this module can widen what the gate allows, and every decision it
produces attaches through `AttachReview`, subject to the broker's
review decision contract.

## Layer 2: the fast detector

`FastDetector.Detect` scans the most recent events of one run — the
window is bounded by `WindowSize` (default 100) — and returns
suspicious patterns as `Suspicion` values. Each suspicion names its
rule, the policy it enforces, and the exact events that triggered it,
so a downstream decision inherits AC-014 references instead of
inventing them.

| Rule                | Fires when                                                     | Severity |
| ------------------- | -------------------------------------------------------------- | -------- |
| `denied_retry`      | a new proposal follows a broker deny in the same window        | high     |
| `corrected_claim`   | an event corrects an earlier event (`corrects_event_id`)       | high     |
| `proposal_burst`    | one worker source proposes more than `MaxProposals` effects    | low      |
| `collector_silent`  | worker tool traffic exists but no collector heartbeat does     | low      |

Any suspicion sets `RouteReview`. The detector never calls a model
and never decides an effect.

## Layer 3: the contextual reviewer

`ContextualReviewer` is the interface; `ReferenceReviewer` is the
deterministic reference implementation of the decision contract, not
a claim of judgment quality (spec 11.3 evaluation compares against
it):

- any high-severity suspicion → `DENY`
- only low-severity suspicions → `WATCH` (the broker keeps the hold)
- no suspicions plus independent evidence → `ALLOW`
- no suspicions plus worker claims only → `ABSTAIN`

`ABSTAIN` is not benign: the broker keeps the hold. Reviews carry
verdict, reviewer, policy references, event references, rationale,
limitations, model and prompt version, and latency (spec 11.2).

## Deadline and fallback

`DeadlineReviewer` wraps any reviewer with the profile's
`ReviewPolicy` — a deadline (default three seconds, spec 11.2) and a
failure mode (F19). When the reviewer times out, errors, panics, or
returns a decision that violates the contract, the wrapper produces
the profile's fallback:

- `FailHold` — return an error; the effect stays `PROPOSED`.
- `FailDeny` — a contract-valid `DENY`.
- `FailAbstain` — a contract-valid `ABSTAIN`.

No failure path ever returns `ALLOW`. A fallback that could not cite
source events becomes a hold instead of an uncheckable decision. The
wrapper stamps the measured latency on every decision.

## Usage

```go
reviewer := supervisor.NewDeadlineReviewer(
    supervisor.NewReferenceReviewer(),
    supervisor.DefaultReviewPolicy(),
)
sup := supervisor.New(reviewer)

review, detection, err := sup.Consider(ctx, proposal, purpose, recentEvents)
if err != nil {
    // FailHold: attach nothing; the broker keeps the hold.
}
if detection.RouteReview {
    effect, decision, err := broker.AttachReview(principal, effect.ID, review)
}
```

The broker (T017) holds the effect `PROPOSED` while the review runs:
`ALLOW` authorizes, `DENY` denies permanently, and `WATCH` and
`ABSTAIN` keep the hold.

## Safe degradation

`DegradationTracker` records the health of the three dependencies
whose failure changes what the system may do (spec 10.2, AC-021):

| Dependency        | Failure effect                                            |
| ----------------- | --------------------------------------------------------- |
| `reviewer`        | review-routed effects hold; local work continues          |
| `evidence_capture`| new external effects fence (broker evidence fence)        |
| `governor_lease`  | new injection stops; experiment effects fence             |

The rules: permitted local work continues in every degraded state
(`LocalWorkAllowed` is always true — local work needs no external
effect and no reviewer); effects whose profile requires review hold
while the reviewer is degraded; and new external effects fence while
evidence capture or the governor lease is degraded, because an effect
without an evidence trail never executes silently. The tracker only
observes and reports — the broker holds, and the governor fences.

The broker side of the same rule is the evidence fence (spec 10.2):
`POST /v1/evidence-fence/engage` denies every new proposal with
`evidence_capture_fenced`, refuses to dispatch existing permits, and
blocks review releases until an authority releases it. The governor's
lease expiry and sweep fence runs on its side (T009).

## Tests

```bash
cd supervisor && go test ./...
```
