# Gauntlet UI

The operator web application (ADR-0001, spec 17, T031): TypeScript,
no runtime dependencies, read-oriented. It consumes documents the
control plane renders, never holds worker authority, and renders
every value as inert text.

## Structure

```text
ui/src/overview.ts      snapshot contract: strict parser + renderer
ui/src/overview.test.ts the suite (bun test)
ui/src/main.ts          browser entry: data island -> inert page
ui/index.html           page shell with a synthetic example island
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
bun run build       # bundle src/main.ts to dist/main.js
```

Bun is development tooling only (see THIRD_PARTY.md); the shipped
page is one standard-library bundle with no dependencies.
