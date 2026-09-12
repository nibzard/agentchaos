// Experiment builder (spec 17.2, T032): select a workload, a scenario
// pack, baseline and treatment profiles, selectors, and budgets;
// preview the compiled plan; then schedule. Defaults use synthetic
// identities and an isolated mode. The builder explains why a
// configuration cannot advance; it never offers an "ignore safety"
// checkbox. The compiler stays the only authority on plans: this
// module produces a manifest draft and lists blockers, nothing more.

import { escapeHtml } from "./overview";

export type Mode = "observe" | "replay" | "isolated_reexecution" |
  "production_synthetic" | "customer_canary" | "govern";

export const modes: readonly Mode[] = ["observe", "replay",
  "isolated_reexecution", "production_synthetic", "customer_canary",
  "govern"];

export interface CatalogWorkload {
  readonly workloadVersionId: string;
  readonly modes: readonly Mode[];
  readonly enrolledTargets: readonly string[];
}

export interface CatalogScenario {
  readonly scenarioVersionId: string;
  readonly modes: readonly Mode[];
}

export interface CatalogProfile {
  readonly profileId: string;
  readonly description: string;
}

export interface BuilderCatalog {
  readonly kind: "BuilderCatalog";
  readonly apiVersion: "v1";
  readonly workloads: readonly CatalogWorkload[];
  readonly scenarios: readonly CatalogScenario[];
  readonly profiles: readonly CatalogProfile[];
}

// BuilderError names the catalog field that failed.
export class BuilderError extends Error {
  constructor(readonly path: string, reason: string) {
    super(`builder catalog: ${path}: ${reason}`);
    this.name = "BuilderError";
  }
}

const reWorkload = /^wlv_[a-z0-9]{8,64}$/;
const reScenario = /^scn_[a-z0-9]{8,64}$/;
const reProfile = /^aup_[a-z0-9]{8,64}$/;
const reTarget = /^tgt_[a-z0-9]{8,64}$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function expect(value: unknown, path: string): Record<string, unknown> {
  if (!isObject(value)) {
    throw new BuilderError(path, "expected an object");
  }
  return value;
}

function noUnknown(document: Record<string, unknown>,
  allowed: readonly string[], path: string): void {
  for (const key of Object.keys(document)) {
    if (!allowed.includes(key)) {
      throw new BuilderError(`${path}.${key}`, "unknown field");
    }
  }
}

function str(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new BuilderError(path, "expected a non-empty string");
  }
  return value;
}

function pattern(value: string, regex: RegExp, path: string,
  shape: string): string {
  if (!regex.test(value)) {
    throw new BuilderError(path, `expected ${shape}`);
  }
  return value;
}

function arr(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new BuilderError(path, "expected an array");
  }
  return value;
}

function enumerated<T extends string>(value: unknown, path: string,
  allowed: readonly T[]): T {
  const text = str(value, path);
  if (!(allowed as readonly string[]).includes(text)) {
    throw new BuilderError(path, `expected one of ${allowed.join(", ")}`);
  }
  return text as T;
}

/** Parse the catalog strictly: unknown fields fail closed. */
export function parseCatalog(input: unknown): BuilderCatalog {
  const root = expect(input, "$");
  noUnknown(root, ["kind", "api_version", "workloads", "scenarios",
    "profiles"], "$");
  if (root.kind !== "BuilderCatalog") {
    throw new BuilderError("$.kind", "expected BuilderCatalog");
  }
  if (root.api_version !== "v1") {
    throw new BuilderError("$.api_version", "expected v1");
  }
  const workloads = arr(root.workloads, "$.workloads")
    .map((raw, index) => {
      const path = `$.workloads[${index}]`;
      const workload = expect(raw, path);
      noUnknown(workload, ["workload_version_id", "modes",
        "enrolled_targets"], path);
      const modesList = arr(workload.modes, `${path}.modes`)
        .map((mode, modeIndex) =>
          enumerated(mode, `${path}.modes[${modeIndex}]`, modes));
      return {
        workloadVersionId: pattern(
          str(workload.workload_version_id, `${path}.workload_version_id`),
          reWorkload, `${path}.workload_version_id`, "wlv_ plus id"),
        modes: modesList,
        enrolledTargets: arr(workload.enrolled_targets,
          `${path}.enrolled_targets`)
          .map((target, targetIndex) => pattern(
            str(target, `${path}.enrolled_targets[${targetIndex}]`),
            reTarget, `${path}.enrolled_targets[${targetIndex}]`,
            "tgt_ plus id")),
      };
    });
  const scenarios = arr(root.scenarios, "$.scenarios")
    .map((raw, index) => {
      const path = `$.scenarios[${index}]`;
      const scenario = expect(raw, path);
      noUnknown(scenario, ["scenario_version_id", "modes"], path);
      return {
        scenarioVersionId: pattern(
          str(scenario.scenario_version_id, `${path}.scenario_version_id`),
          reScenario, `${path}.scenario_version_id`, "scn_ plus id"),
        modes: arr(scenario.modes, `${path}.modes`)
          .map((mode, modeIndex) =>
            enumerated(mode, `${path}.modes[${modeIndex}]`, modes)),
      };
    });
  const profiles = arr(root.profiles, "$.profiles")
    .map((raw, index) => {
      const path = `$.profiles[${index}]`;
      const profile = expect(raw, path);
      noUnknown(profile, ["profile_id", "description"], path);
      return {
        profileId: pattern(str(profile.profile_id, `${path}.profile_id`),
          reProfile, `${path}.profile_id`, "aup_ plus id"),
        description: str(profile.description, `${path}.description`),
      };
    });
  return { kind: "BuilderCatalog", apiVersion: "v1", workloads,
    scenarios, profiles };
}

// Builder state. Defaults follow spec 17.2: synthetic identities and
// an isolated mode; recording is mandatory and has no off switch.

export interface Budgets {
  maxDurationS: number;
  maxConcurrentSessions: number;
  perSessionCostMaxMicros: number;
  aggregateCostMaxMicros: number;
  currency: string;
}

export interface BuilderState {
  readonly workloadVersionId: string | null;
  readonly scenarioVersionIds: readonly string[];
  readonly baselineProfileId: string | null;
  readonly treatmentProfileId: string | null;
  readonly mode: Mode;
  readonly targetIds: readonly string[];
  readonly budgets: Budgets;
  /** Present only after the control plane compiled the draft; the
   * builder itself never claims a plan. */
  readonly planDigest: string | null;
}

export function newBuilderState(): BuilderState {
  return {
    workloadVersionId: null,
    scenarioVersionIds: [],
    baselineProfileId: null,
    treatmentProfileId: null,
    mode: "isolated_reexecution",
    targetIds: [],
    budgets: {
      maxDurationS: 3600,
      maxConcurrentSessions: 2,
      perSessionCostMaxMicros: 1_000_000,
      aggregateCostMaxMicros: 50_000_000,
      currency: "USD",
    },
    planDigest: null,
  };
}

export function selectWorkload(state: BuilderState,
  workloadVersionId: string | null): BuilderState {
  // A new workload invalidates targets chosen for the old one.
  return { ...state, workloadVersionId,
    targetIds: state.workloadVersionId === workloadVersionId
      ? state.targetIds : [] };
}

export function toggleScenario(state: BuilderState,
  scenarioVersionId: string): BuilderState {
  const has = state.scenarioVersionIds.includes(scenarioVersionId);
  return { ...state,
    scenarioVersionIds: has
      ? state.scenarioVersionIds.filter((id) => id !== scenarioVersionId)
      : [...state.scenarioVersionIds, scenarioVersionId] };
}

export function toggleTarget(state: BuilderState,
  targetId: string): BuilderState {
  const has = state.targetIds.includes(targetId);
  return { ...state,
    targetIds: has
      ? state.targetIds.filter((id) => id !== targetId)
      : [...state.targetIds, targetId] };
}

export function setProfiles(state: BuilderState,
  baseline: string | null, treatment: string | null): BuilderState {
  return { ...state, baselineProfileId: baseline,
    treatmentProfileId: treatment };
}

export function setMode(state: BuilderState, mode: Mode): BuilderState {
  return { ...state, mode };
}

export function setBudgets(state: BuilderState,
  budgets: Budgets): BuilderState {
  return { ...state, budgets };
}

export function withPlanDigest(state: BuilderState,
  digest: string | null): BuilderState {
  return { ...state, planDigest: digest };
}

/** Every reason the configuration cannot advance. Empty means the
 * manifest is complete enough to compile — not that it is safe. */
export function blockers(state: BuilderState,
  catalog: BuilderCatalog): string[] {
  const reasons: string[] = [];
  const workload = catalog.workloads.find((candidate) =>
    candidate.workloadVersionId === state.workloadVersionId);
  if (workload === undefined) {
    reasons.push("select a workload");
    return reasons;
  }
  if (!workload.modes.includes(state.mode)) {
    reasons.push(`mode ${state.mode} is not supported by this workload; ` +
      `supported: ${workload.modes.join(", ")}`);
  }
  const unsupportedScenarios = state.scenarioVersionIds.filter((id) => {
    const scenario = catalog.scenarios.find((candidate) =>
      candidate.scenarioVersionId === id);
    return scenario === undefined || !scenario.modes.includes(state.mode);
  });
  if (state.scenarioVersionIds.length === 0) {
    reasons.push("select at least one scenario");
  } else if (unsupportedScenarios.length > 0) {
    reasons.push(`scenarios do not support mode ${state.mode}: ` +
      unsupportedScenarios.join(", "));
  }
  if (state.baselineProfileId === null) {
    reasons.push("select a baseline profile");
  }
  if (state.treatmentProfileId === null) {
    reasons.push("select a treatment profile");
  } else if (state.baselineProfileId === state.treatmentProfileId) {
    reasons.push("the baseline and treatment profiles are the same; " +
      "a comparison needs a pair");
  }
  if (state.targetIds.length === 0) {
    reasons.push("select at least one enrolled target");
  } else {
    const unenrolled = state.targetIds.filter((id) =>
      !workload.enrolledTargets.includes(id));
    if (unenrolled.length > 0) {
      reasons.push(`targets not enrolled for this workload: ` +
        unenrolled.join(", "));
    }
  }
  if (state.budgets.maxDurationS < 1 ||
    state.budgets.maxDurationS > 86400) {
    reasons.push("max duration must be between 1 s and 86400 s");
  }
  if (state.budgets.maxConcurrentSessions < 1 ||
    state.budgets.maxConcurrentSessions > 64) {
    reasons.push("concurrent sessions must be between 1 and 64");
  }
  if (state.budgets.perSessionCostMaxMicros < 1) {
    reasons.push("per-session cost maximum must be positive");
  }
  if (state.budgets.aggregateCostMaxMicros <
    state.budgets.perSessionCostMaxMicros) {
    reasons.push("aggregate cost maximum is below the per-session maximum");
  }
  // Mode and identity class are linked (spec 13.1): a customer canary
  // runs under enrolled real identities; the builder refuses the
  // mismatch instead of letting the compiler reject it later.
  if (state.mode === "customer_canary") {
    reasons.push("customer canary mode requires enrolled identities; " +
      "confirm enrollment in the control plane before scheduling");
  }
  return reasons;
}

/** True when the compiled plan exists and no blocker stands: the
 * schedule control may advance. */
export function canSchedule(state: BuilderState,
  catalog: BuilderCatalog): boolean {
  return state.planDigest !== null &&
    blockers(state, catalog).length === 0;
}

/** The manifest draft, valid against the Experiment contract by
 * construction. Defaults follow spec 17.2 and 13.1: synthetic
 * dedicated identities, isolated mode, synthetic sinks, mandatory
 * recording. Calling this with standing blockers throws: the builder
 * does not emit half a manifest. */
export function toManifest(state: BuilderState,
  catalog: BuilderCatalog): Record<string, unknown> {
  const standing = blockers(state, catalog);
  const hard = standing.filter((reason) =>
    !reason.startsWith("customer canary"));
  if (hard.length > 0) {
    throw new Error(`the configuration cannot advance: ${hard[0]}`);
  }
  return {
    mode: state.mode,
    workload_version_id: state.workloadVersionId,
    scenario_version_ids: [...state.scenarioVersionIds],
    baseline_profile_id: state.baselineProfileId,
    treatment_profile_id: state.treatmentProfileId,
    selectors: [{
      kind: "enrolled_targets",
      target_ids: [...state.targetIds],
      recorded_seed: 0,
      exclusions: [],
    }],
    budgets: {
      max_duration_s: state.budgets.maxDurationS,
      max_concurrent_sessions: state.budgets.maxConcurrentSessions,
      per_session_cost_max: {
        currency: state.budgets.currency,
        micros: state.budgets.perSessionCostMaxMicros,
      },
      aggregate_cost_max: {
        currency: state.budgets.currency,
        micros: state.budgets.aggregateCostMaxMicros,
      },
    },
    identities: {
      kind: state.mode === "customer_canary"
        ? "enrolled_opt_in" : "synthetic_dedicated",
      max_sessions: state.budgets.maxConcurrentSessions,
    },
    recording: {
      required_event_kinds: ["proposed_action", "broker_decision",
        "tool_request", "tool_response", "external_receipt",
        "injection_receipt", "recovery_action"],
      mandatory: true,
      retention_days: 30,
    },
    stop_rules: [
      { condition: "unauthorized_effect", action: "fence_effects" },
      { condition: "grant_expiry", action: "terminate" },
      { condition: "budget_exhaustion", action: "terminate" },
    ],
    rollback: { strategy: "none" },
    credentials: { required_kinds: [], freshness_max_age_s: 3600 },
    effect_sinks: [{
      kind: state.mode === "customer_canary"
        ? "enrolled_service" : "synthetic",
      destination: "sink:gauntlet-default",
    }],
  };
}

/** Render the builder as inert HTML: the current configuration, why
 * it cannot advance, and the preview/schedule states. */
export function renderBuilder(state: BuilderState,
  catalog: BuilderCatalog): string {
  const standing = blockers(state, catalog);
  const workload = catalog.workloads.find((candidate) =>
    candidate.workloadVersionId === state.workloadVersionId);

  const blockersBlock = standing.length === 0
    ? `<p class="blockers none">no blockers: the configuration can go ` +
      `to the compiler</p>`
    : `<div class="blockers" role="alert"><h3>Cannot advance</h3><ul>` +
      standing.map((reason) =>
        `<li>${escapeHtml(reason)}</li>`).join("") +
      `</ul><p class="no-override">these are contract limits; there ` +
      `is no override</p></div>`;

  const preview = state.planDigest === null
    ? `<p class="preview pending">plan preview: not compiled yet — the ` +
      `deterministic compiler is the only plan authority</p>`
    : `<p class="preview ready">plan preview: digest ` +
      `${escapeHtml(state.planDigest)}</p>`;

  const schedule = canSchedule(state, catalog)
    ? `<p class="schedule ready">schedule control available</p>`
    : `<p class="schedule blocked">schedule control disabled until a ` +
      `compiled plan exists and no blocker stands</p>`;

  const targets = workload === undefined ? "" :
    `<p class="targets">enrolled targets: ` +
    (workload.enrolledTargets.length === 0 ? "none"
      : workload.enrolledTargets.map(escapeHtml).join(", ")) + `</p>`;

  return `<section class="builder">` +
    `<h1>Experiment builder</h1>` +
    `<p class="selection">workload ` +
    `${workload === undefined ? "—" : escapeHtml(workload.workloadVersionId)}` +
    ` · mode ${state.mode} · scenarios ` +
    (state.scenarioVersionIds.length === 0 ? "—"
      : state.scenarioVersionIds.map(escapeHtml).join(", ")) +
    `</p>` +
    `<p class="profiles">baseline ` +
    `${state.baselineProfileId === null ? "—"
      : escapeHtml(state.baselineProfileId)} · treatment ` +
    `${state.treatmentProfileId === null ? "—"
      : escapeHtml(state.treatmentProfileId)}</p>` +
    `<p class="targets-selected">targets ` +
    (state.targetIds.length === 0 ? "—"
      : state.targetIds.map(escapeHtml).join(", ")) + `</p>` +
    targets +
    `<p class="budgets">budgets ${state.budgets.maxDurationS} s · ` +
    `${state.budgets.maxConcurrentSessions} sessions · ` +
    `${state.budgets.perSessionCostMaxMicros / 1_000_000} ` +
    `${escapeHtml(state.budgets.currency)} per session</p>` +
    `<p class="recording">recording is mandatory; the manifest has no ` +
    `recording-off option</p>` +
    blockersBlock + preview + schedule +
    `</section>`;
}
