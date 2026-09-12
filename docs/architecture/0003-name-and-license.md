# 0003: Product name and license readiness

## Status

Accepted

Amended 2026-09-12: the deferred `acx` prefix retirement landed as
ADR-0004. This decision's "keep for now" list is resolved; the rest
stands unchanged.

## Context

The product specification was drafted under the working name
AgentChaos. That name is not clear: a public repository of the same
name already exists, and the specification itself warns against
implying any right to it ("Do not assume the existing same-name
repository permits reuse merely because it is public", release gates).
The name appears in several places with different blast radii:

- The product name in prose documents.
- Go module paths (`agentchaos/...`) in five modules.
- Contract schema URIs (`https://agentchaos.invalid/schemas/v1/...`).
- The `acx` short prefix: identity headers, the principal token
  version string, Python package names (`acx_compiler`, `acx_runner`,
  `acx_schemas`), and the CLI name reserved by ADR-0001.

The specification also proposes a code license: Apache-2.0 for original
code, with separate review for third-party code.

## Decision

### Name

The working name is **Gauntlet**. The name describes what the product
does — autonomous agents run a gauntlet of enrolled targets, injected
faults, and hard controls, with every step evidenced — and a search
shows no product in this category holding it.

Rename now, before any release:

- Product name in every document: Gauntlet.
- Go module paths: `gauntlet/api`, `gauntlet/broker`, `gauntlet/control`,
  `gauntlet/evidence`, `gauntlet/governor`.
- Contract schema URIs: `https://gauntlet.invalid/schemas/v1/...`. The
  v1 schemas are unreleased, so this is not a breaking contract change.

Keep for now, rename under a tracked follow-up task:

- The `acx` prefix (headers `X-ACX-*`, token version `acx1`, Python
  package names, the reserved CLI name). It derives from the retired
  name, but it is an opaque wire and package namespace, not a product
  identity. Renaming it touches every contract example in the
  specification and every component at once; it is cheap before a
  public contract freeze and disruptive after. The follow-up task must
  land before any public API compatibility promise.

Non-affiliation: Gauntlet is not associated with, derived from, or
endorsed by the public AgentChaos repository. The repository README
states this. Nothing in this tree originates there (see
`THIRD_PARTY.md`).

The v0.1 product brief keeps its original file name and text unchanged
under `docs/`; it is the historical input document that section
citations elsewhere refer to.

### License

Apache-2.0 for original code, per the specification's release gate.
`THIRD_PARTY.md` records the dependency review: runtime code depends on
standard libraries only, and the one development dependency is MIT
licensed. Each new dependency requires a `THIRD_PARTY.md` update.

## Consequences

- Imports and module paths change across the tree; no behavior changes.
- Schema `$id` values and the registry `contract_base` change; the
  loader validates the new URIs and every suite that pins them is
  updated in the same change.
- The follow-up `acx` rename stays visible in the task tracker until
  it lands, so it cannot be silently forgotten before a public release.
