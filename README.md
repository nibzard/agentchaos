# Gauntlet

Gauntlet is a developer and security testing product for autonomous
agent systems. It runs agent workloads against enrolled targets under
injected faults, hard controls, and mandatory evidence, and it computes
assurance claims from what actually happened.

Gauntlet is a working name; the naming decision and its limits are
recorded in `docs/architecture/0003-name-and-license.md`.

## Non-affiliation

Gauntlet is not associated with, derived from, or endorsed by any
public repository named AgentChaos or any similarly named project. No
code in this tree originates there. The v0.1 product brief in `docs/`
predates the rename and is kept verbatim as the historical input
document.

## Repository layout

| Path | Contents |
| --- | --- |
| `governor/` | Safety governor: envelopes, grants, fences, stop protocol handoffs |
| `broker/` | Effect broker: every external action passes through here |
| `control-plane/` | Deterministic compiler and fixed-cohort assurance statistics |
| `evidence-plane/` | Append-only event chain with source trust labels |
| `execution-plane/` | Local fixture runner for experiments |
| `api/` | The beta HTTP API monolith that composes the planes |
| `shared/` | Contract schemas, the Python validator, and reference fixtures |
| `docs/` | Architecture decisions and the product brief |

## Guarantees

- No external effect without an authorized, broker-mediated path.
- No run without a compiled plan and a registered safety envelope.
- Every claim rests on named evidence with exact, deterministic bounds.
- Safety levers engage from the customer side and never disengage
  through the API.
- Unknown fields fail closed everywhere a contract is read.

## Development

Each component documents its own build and test steps in its README.
Go modules test with `go test ./...`; Python suites run with `pytest`.
The task tracker `to-do.json` lists outstanding work.

## License

Apache-2.0 (see `LICENSE`). Third-party review lives in
`THIRD_PARTY.md`.
