# 0001: Initial stack and repository layout

## Status

Accepted

## Context

Gauntlet starts as a developer and security testing product for autonomous
agent systems. The product specification requires these major parts:

- A control plane for definitions, scheduling, result comparison, and claims.
- An execution plane for disposable runs, fixtures, adapters, and cleanup.
- An evidence plane for authoritative events and result records.
- A mandatory effect broker for mediated external actions.
- An independent safety governor for leases, budgets, stops, and fencing.
- A CLI named `acx`, subject to naming clearance.
- A TypeScript web UI for workload, run, comparison, assurance, and recovery
  views.

The specification also gives the preferred first implementation stack:

- Python for scenario authoring, the reference harness, SDK integration, and
  developer tooling.
- Go for the broker and governor on the enforcement path.
- PostgreSQL for durable control state and result state.
- Object storage for evidence payloads and artifacts.
- TypeScript for the web interface.
- OpenTelemetry-compatible export for observation interoperability.

## Decision

Use a modular monorepo. Keep the beta system as a modular monolith plus
separate enforcement services.

Use Python for the control-plane application, the execution runner, evidence
processing, SDK bindings, fixture tools, and the `acx` CLI. Use Go for the
effect broker and safety governor because these components must stay small,
deterministic, and easy to deploy outside the worker environment.

Use PostgreSQL as the first durable relational store for tenants, workload
versions, autonomy profiles, experiments, runs, effects, findings, and
assurance claims. Use object storage for large evidence payloads, artifacts,
reports, and retained raw content. The database stores references, digests,
metadata, and retention state for those objects.

Use a TypeScript UI under `ui/`. The UI consumes the HTTP API from the control
plane. It does not receive worker authority.

## Repository layout

```text
.
├── broker/                 # Go effect broker and adapter-facing HTTP surface
├── cli/acx/                # Python CLI package
├── control-plane/          # Python API, compiler, scheduler, and result logic
├── docs/architecture/      # Architecture decisions and implementation notes
├── evidence-plane/         # Event ingest, evidence processing, and exports
├── execution-plane/        # Python runner, fixtures, adapters, and cleanup
├── governor/               # Go safety governor and emergency controls
├── shared/                 # Shared contracts, test fixtures, and utilities
└── ui/                     # TypeScript web application
```

## Boundaries

- The control plane can schedule work and read results. It must not be the only
  source of local safety limits.
- The execution plane can run disposable workloads. It must not hold downstream
  credentials for mediated effects.
- The broker owns effect authorization, decision durability before dispatch,
  receipt reconciliation, and idempotency behavior for supported actions.
- The governor owns experiment leases, heartbeats, budgets, stop conditions,
  fencing, and cleanup handoff.
- The evidence plane owns authoritative event capture and export. Worker claims
  remain separate from collector facts and monitor interpretations.
- The UI is read-oriented for operations and can call approved control-plane
  APIs. It must render evidence as inert data.

## Consequences

This layout lets early tasks add strict contracts, the compiler, the runner,
and the broker without first splitting the product into many services. It also
keeps the components with direct authority over external effects separate from
the worker environment from the start.

Future tasks may add package manifests, generated clients, migrations, tests,
and deployment assets inside these directories. They should keep the boundaries
above unless a later architecture decision changes them.
