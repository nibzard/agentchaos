# Gauntlet UI

The operator web application (ADR-0001, spec 17, T031): TypeScript,
no runtime dependencies, read-oriented. It consumes documents the
control plane renders, never holds worker authority, and renders
every value as inert text.

## Structure

```text
ui/src/overview.ts       workload overview: strict parser + renderer
ui/src/overview.test.ts  overview suite
ui/src/builder.ts        experiment builder: catalog parser, selection
                         state, blockers, manifest draft, renderer
ui/src/builder.test.ts   builder suite
ui/src/timeline.ts       run timeline: strict parser, lane assignment,
                         effect pairing, renderer
ui/src/timeline.test.ts  timeline suite
ui/src/compare.ts        comparison and assurance view: frontier
                         columns, paired-difference classification,
                         scoped claim cards
ui/src/compare.test.ts   comparison suite
ui/src/recovery.ts       recovery and governance view: fenced groups,
                         unknown effects, dirty environments, lever
ui/src/recovery.test.ts  recovery suite
ui/src/main.ts           overview page entry: data island -> page
ui/src/builder-page.ts   builder page entry: islands -> builder panel
ui/src/timeline-page.ts  timeline page entry: island -> lanes
ui/src/compare-page.ts   comparison page entry: islands -> frontier
ui/src/recovery-page.ts  recovery page entry: island -> board
ui/index.html            overview shell with a synthetic example island
ui/builder.html          builder shell with example islands
ui/timeline.html         timeline shell with a synthetic example island
ui/compare.html          comparison shell with synthetic example islands
ui/recovery.html         recovery shell with a synthetic example island
```

## Data flow

The control plane renders a `WorkloadOverview` document into the
page's JSON data island. `main.ts` reads the island, parses it with
`parseOverview`, and mounts `renderOverview`'s output into `#app`.
A malformed island prints the parse error as text — never a partial
page — because the parser refuses unknown fields at every nesting
level (ADR-0002) and every value the renderer emits passes through
`escapeHtml`.

## What the overview shows

Per spec 17.1, each workload row states its version id, supported
modes, current autonomy profile, coverage gaps, useful throughput
(authorized completions over eligible tasks, not raw completion),
recent failures, evidence freshness, and cost. Two rules shape the
layout:

- **Test and production results never share a section.** The
  synthetic and production environments render under separate
  headings; an environment with nothing enrolled says so instead of
  hiding.
- **A missing enforcement path is more prominent than a high
  detector score.** `sortForDisplay` orders rows by coverage-gap
  severity, then failures, then id — a clean, perfect-throughput row
  never outranks a gapped one, and the gap block renders above every
  metric inside the row.

There is no aggregate safety badge: no "99.99% free of malicious
effort" appears anywhere, and unknown freshness renders as unknown,
not fresh.

## Commands

```bash
cd ui
bun test            # run the suite
bun run build       # bundle the page entries into dist/
```

Bun is development tooling only (see THIRD_PARTY.md); the shipped
page is one standard-library bundle with no dependencies.

## Experiment builder

`builder.ts` (spec 17.2, T032) keeps the operator's selection in an
immutable state record and answers one question honestly: *why can't
this advance?*

- `parseCatalog` reads the control plane's catalog — workloads with
  supported modes and enrolled targets, scenarios, autonomy profiles —
  and rejects unknown fields at every level (ADR-0002).
- Defaults follow spec 17.2: synthetic dedicated identities and an
  isolated mode; recording is mandatory with no manifest opt-out.
- `blockers` lists every contract reason the configuration cannot
  advance — unsupported modes, scenario-mode mismatches, a missing
  profile pair, unenrolled targets, invalid budgets. There is no
  ignore-safety control; the panel says so.
- `toManifest` emits an Experiment manifest draft valid by
  construction and refuses to emit while a blocker stands.
- `canSchedule` stays false until the deterministic compiler produced
  a plan digest (`withPlanDigest`); the builder never claims a plan.
- A customer-canary selection switches identities to enrolled opt-in
  and sinks to enrolled services, and keeps scheduling off until
  enrollment is confirmed in the control plane.

Selection updates (`selectWorkload`, `toggleScenario`, `toggleTarget`,
`setProfiles`, `setMode`, `setBudgets`) return new states; switching
workloads drops targets chosen for the old one.

## Run timeline

`timeline.ts` (spec 17.3, T033) renders one run's events on six
trust-labeled lanes: agent, tool, broker, injection, monitor,
infrastructure.

- `parseTimeline` accepts the timeline document strictly — ids match
  the `evt_`/`run_`/`src_`/`cid_` patterns, kinds and trust labels
  come from the contract enums, and unknown fields fail closed at
  every level (ADR-0002). A finding that names an event the document
  does not carry is a parse error, not a silent drop.
- Every event shows its trust label: worker claim, collector fact, or
  monitor interpretation. Monitor interpretations always take the
  monitor lane, whatever their kind.
- `pairEffects` joins each broker decision to its external receipt
  through a shared correlation id. A decision with no receipt — or a
  receipt with no decision — renders as a visible missing half.
- Findings list the event ids they rest on, so a claim can be walked
  back to raw evidence.
- Object references render as digests only; the page never fetches
  the referenced content. Redaction, truncation, limited source
  coverage, and clock uncertainty are stated, not hidden.

## Comparison and assurance view

`compare.ts` (spec 17.4 and 17.5, T034) renders the
utility/safety/latency/cost frontier and scoped assurance cards.

- The frontier is a table of separate columns. There is no combined
  score, no ranking, and no recommended profile; rows stay in the
  document's order.
- Every rate carries its denominator. A zero denominator reads "not
  measured", never zero. Unknown outcomes stay visible outside every
  verified rate.
- A profile that completed no eligible task is called out: refusing
  everything is not an improvement and cannot be recommended.
- `classifyDiff` labels each paired difference as an improvement, a
  regression, or uncertain from its interval; an unknown metric is
  never classified.
- Claim cards are scoped by construction: hazard, eligible
  population, all seven fingerprints, observed failures, unresolved
  cases with the all-unresolved sensitivity bound, confidence bound,
  target, dependence assumptions, and expiration. Status text says
  "supported within scope only"; nothing on the page claims
  universal safety.

## Recovery and governance

`recovery.ts` (spec 17.6, T035) renders the recovery board.

- The emergency safety lever section renders first and always. When
  reachable it names its authorized operators and same-origin path;
  when not, it states that as a defect with the same prominence.
- Dirty and quarantined environments stay visible, and an unknown
  cleanup state reads "unknown — treated as dirty", never clean. A
  clean environment on the dirty list is a parse error.
- Unknown effects state that resolution requires verified evidence,
  not the passage of time. Compensation attempts without a receipt
  say "no receipt"; failed attempts call for follow-up.
- Policy changes and exceptional incident closures render in their
  own audit trail, separate from run operations. There is no human
  approval inbox anywhere: routine operation never queues a human
  approval, so the page has none to show.
