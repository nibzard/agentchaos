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
ui/src/main.ts           overview page entry: data island -> page
ui/src/builder-page.ts   builder page entry: islands -> builder panel
ui/index.html            overview shell with a synthetic example island
ui/builder.html          builder shell with example islands
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
