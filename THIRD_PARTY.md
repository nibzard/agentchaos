# Third-party license review

Review date: 2026-09-12. Scope: everything in this repository.

## Runtime dependencies

None. Every component ships against a standard library only:

- The Go modules (`gauntlet/api`, `gauntlet/broker`, `gauntlet/control`,
  `gauntlet/evidence`, `gauntlet/governor`) import the Go standard
  library and each other. `go.mod` carries no third-party requires.
- The Python packages (`acx_compiler`, `acx_runner`, `acx_schemas`)
  import the Python standard library only.

## Development dependencies

- `jsonschema` (MIT license, package
  `jsonschema` on PyPI) validates this repository's own contract
  schemas and the task tracker during development and review. It is not
  imported by any shipped component.

## Same-name repository

A public repository named AgentChaos exists outside this project. This
repository contains no code, configuration, or documentation from it.
The working name collision is resolved by ADR-0003: this product is
named Gauntlet and states its non-affiliation in its README.

## Conclusion

Apache-2.0 (see `LICENSE`) covers original code with no third-party
obligations beyond the MIT-licensed development tooling noted above.
Re-run this review whenever a dependency is added.
