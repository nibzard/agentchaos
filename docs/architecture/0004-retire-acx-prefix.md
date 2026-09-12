# 0004: Retire the acx wire namespace prefix

## Status

Accepted

## Context

ADR-0003 renamed the product to Gauntlet and kept the `acx` short
prefix as an opaque namespace under a tracked follow-up task, because
the rename touches every component at once and is only cheap before a
public contract freeze. The follow-up must land before any public API
compatibility promise. No contract is released yet, so nothing depends
on the old names outside this repository.

The prefix appears in the identity headers, the principal token
version, five Python package names, the reserved CLI command name, the
sealed-blob mark in key custody, and one fixture workload name.

## Decision

Retire the `acx` prefix now, atomically, in favor of the `gauntlet`
namespace:

| Surface | Old | New |
| --- | --- | --- |
| Identity headers | `X-ACX-Actor`, `X-ACX-Tenant`, `X-ACX-Role` | `X-Gauntlet-Actor`, `X-Gauntlet-Tenant`, `X-Gauntlet-Role` |
| Principal token version | `acx1` | `gauntlet1` |
| Python packages | `acx_compiler`, `acx_runner`, `acx_schemas`, `acx_adapters`, `acx_scenarios` | `gauntlet_compiler`, `gauntlet_runner`, `gauntlet_schemas`, `gauntlet_adapters`, `gauntlet_scenarios` |
| CLI command | `acx` | `gauntlet` |
| Sealed-blob mark | `acxseal` | `gauntletseal` |
| Fixture workload name | `acx-harness` | `gauntlet-harness` |

The whole change lands in one commit: module directories, imports,
wire constants, pyproject package lists, the packaging manifest, the
exit gate checker, and every test that pins a name. The v0.1 product
brief under `docs/` stays verbatim and still says `acx`; it is the
historical input document, and section citations elsewhere refer to
it. ADR-0001 and ADR-0002 keep their original text for the same
reason; this decision supersedes the CLI name they reserve.

The digest test vector `sha256("acx")` in `analysis` is arbitrary test
input, not a namespace use, and keeps its precomputed digest.

## Consequences

- No behavior changes; every suite must pass unchanged in the same
  commit that renames.
- The `gauntlet` CLI name and the `X-Gauntlet-*` headers are the
  names a public compatibility promise would freeze.
- Any external material that still says `acx` (none exists today)
  would break loudly, which is the point of renaming before release.
