# Packaging

The open-core distribution defined by spec 23.1.

## Build

```sh
python3 packaging/build_open_core.py
```

The script validates `packaging/manifest.json` against
`packaging/manifest.schema.json`, checks every path, and assembles the
tree under `dist/gauntlet-open-core/` with a `VERSION` file naming the
commit. The build fails if an exclusion covers a promised path, if a
promise copies nothing, or if excluded material leaks into the tree.

## The boundary

The manifest carries one component per promise in spec 23.1:

- scenario specification, schemas, CLI, local runner, reference
  fixture environments, synthetic scenario pack, adapter interface,
  core evidence format, comparison and statistics code, basic local
  UI, and the essential safety controls.

Everything else stays out, with the reason stated in the manifest:

- `api/` — the hosted beta HTTP surface, a commercial tier per spec
  23.2.
- `keycustody/` — platform signing-key infrastructure of the hosted
  trust base.
- `integration/`, `release/`, `benchmarks/`, `to-do*.json` — internal
  engineering, not product code.
- `ui/dist`, `ui/node_modules` — build output and dependency caches.

Spec 23.3 constrains the split: local users keep the stop controls,
honest unknown states, redaction, export, and containment without
paying. The broker, governor, and supervisor ship in the open tree,
and `test_local_users_keep_the_safety_controls` pins that.

## Name and license

Original code ships under Apache-2.0 with no runtime dependencies
(see `THIRD_PARTY.md`). Gauntlet is a working name; naming clearance
is pending and the caveat travels with the distribution in `VERSION`
(see `docs/architecture/0003-name-and-license.md`).

## Tests

```sh
python3 -m pytest packaging/test_packaging.py -q
```
