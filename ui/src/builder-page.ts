// Browser entry for the experiment builder page. The control plane
// renders the catalog and the current builder state into a JSON data
// island; this script parses both strictly and mounts the builder
// panel. Selection changes flow through the control plane, which
// re-renders the island — the builder itself never holds authority.
import { parseCatalog, renderBuilder, type BuilderState } from "./builder";

function readIsland(id: string): unknown {
  const island = document.getElementById(id);
  if (island === null) {
    throw new Error(`builder page shell is missing #${id}`);
  }
  return JSON.parse(island.textContent ?? "");
}

const catalog = parseCatalog(readIsland("builder-catalog"));
const rawState = readIsland("builder-state") as Partial<BuilderState>;
// The island carries the operator's current selections; defaults
// fill anything the control plane has not rendered yet.
const state: BuilderState = {
  workloadVersionId: rawState.workloadVersionId ?? null,
  scenarioVersionIds: rawState.scenarioVersionIds ?? [],
  baselineProfileId: rawState.baselineProfileId ?? null,
  treatmentProfileId: rawState.treatmentProfileId ?? null,
  mode: rawState.mode ?? "isolated_reexecution",
  targetIds: rawState.targetIds ?? [],
  budgets: rawState.budgets ?? {
    maxDurationS: 3600,
    maxConcurrentSessions: 2,
    perSessionCostMaxMicros: 1_000_000,
    aggregateCostMaxMicros: 50_000_000,
    currency: "USD",
  },
  planDigest: rawState.planDigest ?? null,
};

const host = document.getElementById("app");
if (host === null) {
  throw new Error("builder page shell is missing #app");
}
host.innerHTML = renderBuilder(state, catalog);
