// Comparison and assurance view (spec 17.4 and 17.5, T034): the
// utility/safety/latency/cost frontier as separate columns — never
// one score, never a leaderboard — plus scoped evidence cards. The
// documents mirror the analysis package's ProfileComparison and the
// control plane's AssuranceClaim; unknown fields fail closed at
// every level (ADR-0002), unknown outcomes stay visible, and no
// control that wins by refusing all tasks is recommended.

import { escapeHtml } from "./overview";

export interface Fraction {
  readonly numerator: number;
  readonly denominator: number;
}

export interface ProfileRow {
  readonly profile: string;
  readonly attempts: number;
  readonly unknownOutcomes: number;
  readonly clusters: number;
  readonly clustersWithUnauthorized: number;
  readonly authorizedCompletion: Fraction;
  readonly safeRefusals: number;
  readonly unauthorizedEffects: Fraction;
  readonly detectionBeforeEffect: Fraction;
  readonly postHocDetections: number;
  readonly responseOnlyChanges: number;
  readonly falseInterventions: Fraction;
  readonly medianLatencyMs: number;
  readonly meanCostMicros: number;
}

export type DiffVerdict = "improvement" | "regression" | "uncertain" |
  "unknown direction";

export interface PairedDiff {
  readonly profile: string;
  readonly metric: string;
  readonly baseline: number;
  readonly value: number;
  readonly difference: number;
  readonly lower: number;
  readonly upper: number;
  readonly unit: string;
}

export interface ComparisonDocument {
  readonly kind: "ProfileComparison";
  readonly apiVersion: "v1";
  readonly model: string;
  readonly baseline: string;
  readonly tasks: number;
  readonly profiles: readonly ProfileRow[];
  readonly pairedDifferences: readonly PairedDiff[];
  readonly limitations: readonly string[];
}

export type ClaimStatus = "SUPPORTED_WITHIN_SCOPE" |
  "TARGET_NOT_DEMONSTRATED" | "VIOLATED" | "INSUFFICIENT_EVIDENCE" |
  "STALE";

export type Severity = "H0" | "H1" | "H2" | "H3";

export type UnitOfObservation = "action" | "session" | "task" |
  "cluster" | "experiment";

export type EvidenceCategory = "production_incidence" |
  "challenge_set_failure" | "boundary_conformance" |
  "detector_performance";

export interface ClaimCard {
  readonly id: string;
  readonly status: ClaimStatus;
  readonly hazardDescription: string;
  readonly severity: Severity;
  readonly failureEvent: string;
  readonly unitOfObservation: UnitOfObservation;
  readonly workloadVersionId: string;
  readonly autonomyProfileId: string | null;
  readonly fingerprints: Readonly<Record<string, string>>;
  readonly evidenceCategory: EvidenceCategory;
  readonly windowFrom: string;
  readonly windowTo: string;
  readonly coverageGaps: readonly string[];
  readonly failures: number;
  readonly eligibleObservations: number;
  readonly unresolved: number;
  readonly confidenceLevel: number;
  readonly upperBound: number;
  readonly sensitivityAllUnresolvedFail: number;
  readonly acceptanceThreshold: number;
  readonly dependenceDescription: string;
  readonly populationApplicability: string;
  readonly exclusions: readonly string[];
  readonly validUntil: string;
  readonly invalidationTriggers: readonly string[];
}

export class CompareError extends Error {
  constructor(readonly path: string, reason: string) {
    super(`comparison document: ${path}: ${reason}`);
    this.name = "CompareError";
  }
}

const claimStatuses: readonly ClaimStatus[] = ["SUPPORTED_WITHIN_SCOPE",
  "TARGET_NOT_DEMONSTRATED", "VIOLATED", "INSUFFICIENT_EVIDENCE",
  "STALE"];
const severities: readonly Severity[] = ["H0", "H1", "H2", "H3"];
const units: readonly UnitOfObservation[] = ["action", "session",
  "task", "cluster", "experiment"];
const evidenceCategories: readonly EvidenceCategory[] =
  ["production_incidence", "challenge_set_failure",
    "boundary_conformance", "detector_performance"];
const fingerprintKeys = ["model", "harness", "tools", "policy",
  "monitor", "scenario_distribution", "environment"] as const;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function objectAt(value: unknown, path: string): Record<string, unknown> {
  if (!isObject(value)) {
    throw new CompareError(path, "expected an object");
  }
  return value;
}

function noUnknown(document: Record<string, unknown>,
  allowed: readonly string[], path: string): void {
  for (const key of Object.keys(document)) {
    if (!allowed.includes(key)) {
      throw new CompareError(`${path}.${key}`, "unknown field");
    }
  }
}

function required(document: Record<string, unknown>, key: string,
  path: string): unknown {
  if (!(key in document)) {
    throw new CompareError(`${path}.${key}`, "missing required field");
  }
  return document[key];
}

function str(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new CompareError(path, "expected a non-empty string");
  }
  return value;
}

function enumerated<T extends string>(value: unknown, path: string,
  allowed: readonly T[]): T {
  const text = str(value, path);
  if (!(allowed as readonly string[]).includes(text)) {
    throw new CompareError(path, `expected one of ${allowed.join(", ")}`);
  }
  return text as T;
}

function strList(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) {
    throw new CompareError(path, "expected an array");
  }
  return value.map((item, index) =>
    str(item, `${path}[${index}]`));
}

function num(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new CompareError(path, "expected a finite number");
  }
  return value;
}

function int(value: unknown, path: string,
  minimum: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) ||
    value < minimum) {
    throw new CompareError(path,
      `expected an integer of at least ${minimum}`);
  }
  return value;
}

function fraction(value: unknown, path: string): Fraction {
  const object = objectAt(value, path);
  noUnknown(object, ["numerator", "denominator"], path);
  const numerator = int(required(object, "numerator",
    `${path}.numerator`), `${path}.numerator`, 0);
  const denominator = int(required(object, "denominator",
    `${path}.denominator`), `${path}.denominator`, 0);
  if (numerator > denominator) {
    throw new CompareError(path,
      "the numerator exceeds the denominator");
  }
  return { numerator, denominator };
}

/** Parse the ProfileComparison document strictly. */
export function parseComparison(input: unknown): ComparisonDocument {
  const root = objectAt(input, "$");
  noUnknown(root, ["kind", "api_version", "model", "baseline", "tasks",
    "profiles", "paired_differences", "limitations"], "$");
  if (required(root, "kind", "$") !== "ProfileComparison") {
    throw new CompareError("$.kind", "expected ProfileComparison");
  }
  if (required(root, "api_version", "$") !== "v1") {
    throw new CompareError("$.api_version", "expected v1");
  }
  const model = str(required(root, "model", "$.model"), "$.model");
  const baseline = str(required(root, "baseline", "$.baseline"),
    "$.baseline");
  const tasks = int(required(root, "tasks", "$.tasks"), "$.tasks", 0);

  const profilesPath = "$.profiles";
  const rawProfiles = required(root, "profiles", profilesPath);
  if (!Array.isArray(rawProfiles) || rawProfiles.length === 0) {
    throw new CompareError(profilesPath,
      "expected at least one profile row");
  }
  const profiles = rawProfiles.map((raw, index) => {
    const path = `${profilesPath}[${index}]`;
    const row = objectAt(raw, path);
    noUnknown(row, ["profile", "attempts", "unknown_outcomes",
      "clusters", "clusters_with_unauthorized", "authorized_completion",
      "safe_refusals", "unauthorized_effects", "detection_before_effect",
      "post_hoc_detections", "response_only_changes",
      "false_interventions", "median_latency_ms", "mean_cost_micros"],
      path);
    return {
      profile: str(required(row, "profile", `${path}.profile`),
        `${path}.profile`),
      attempts: int(required(row, "attempts", `${path}.attempts`),
        `${path}.attempts`, 0),
      unknownOutcomes: int(
        required(row, "unknown_outcomes", `${path}.unknown_outcomes`),
        `${path}.unknown_outcomes`, 0),
      clusters: int(required(row, "clusters", `${path}.clusters`),
        `${path}.clusters`, 0),
      clustersWithUnauthorized: int(
        required(row, "clusters_with_unauthorized",
          `${path}.clusters_with_unauthorized`),
        `${path}.clusters_with_unauthorized`, 0),
      authorizedCompletion: fraction(
        required(row, "authorized_completion",
          `${path}.authorized_completion`),
        `${path}.authorized_completion`),
      safeRefusals: int(
        required(row, "safe_refusals", `${path}.safe_refusals`),
        `${path}.safe_refusals`, 0),
      unauthorizedEffects: fraction(
        required(row, "unauthorized_effects",
          `${path}.unauthorized_effects`),
        `${path}.unauthorized_effects`),
      detectionBeforeEffect: fraction(
        required(row, "detection_before_effect",
          `${path}.detection_before_effect`),
        `${path}.detection_before_effect`),
      postHocDetections: int(
        required(row, "post_hoc_detections", `${path}.post_hoc_detections`),
        `${path}.post_hoc_detections`, 0),
      responseOnlyChanges: int(
        required(row, "response_only_changes",
          `${path}.response_only_changes`),
        `${path}.response_only_changes`, 0),
      falseInterventions: fraction(
        required(row, "false_interventions",
          `${path}.false_interventions`),
        `${path}.false_interventions`),
      medianLatencyMs: int(
        required(row, "median_latency_ms", `${path}.median_latency_ms`),
        `${path}.median_latency_ms`, 0),
      meanCostMicros: num(
        required(row, "mean_cost_micros", `${path}.mean_cost_micros`),
        `${path}.mean_cost_micros`),
    };
  });

  const diffsPath = "$.paired_differences";
  const rawDiffs = required(root, "paired_differences", diffsPath);
  if (!Array.isArray(rawDiffs)) {
    throw new CompareError(diffsPath, "expected an array");
  }
  const pairedDifferences = rawDiffs.map((raw, index) => {
    const path = `${diffsPath}[${index}]`;
    const diff = objectAt(raw, path);
    noUnknown(diff, ["profile", "metric", "baseline", "profile_value",
      "difference", "lower", "upper", "unit"], path);
    const lower = num(required(diff, "lower", `${path}.lower`),
      `${path}.lower`);
    const upper = num(required(diff, "upper", `${path}.upper`),
      `${path}.upper`);
    if (lower > upper) {
      throw new CompareError(path, "the interval is inverted");
    }
    const metric = str(required(diff, "metric", `${path}.metric`),
      `${path}.metric`);
    return {
      profile: str(required(diff, "profile", `${path}.profile`),
        `${path}.profile`),
      metric,
      baseline: num(required(diff, "baseline", `${path}.baseline`),
        `${path}.baseline`),
      value: num(required(diff, "profile_value",
        `${path}.profile_value`), `${path}.profile_value`),
      difference: num(required(diff, "difference",
        `${path}.difference`), `${path}.difference`),
      lower,
      upper,
      unit: str(required(diff, "unit", `${path}.unit`), `${path}.unit`),
    };
  });

  const limitations = root.limitations === undefined ? []
    : strList(root.limitations, "$.limitations");
  return { kind: "ProfileComparison", apiVersion: "v1", model, baseline,
    tasks, profiles, pairedDifferences, limitations };
}

/** Which direction is good for each metric the frontier classifies. */
const metricDirections = new Map<string, { up: boolean }>([
  ["authorized_completion", { up: true }],
  ["unauthorized_effects", { up: false }],
  ["detection_before_effect", { up: true }],
  ["false_interventions", { up: false }],
  ["median_latency_ms", { up: false }],
  ["mean_cost_micros", { up: false }],
]);

/** Classify one paired difference. An interval that crosses zero is
 * uncertain; an unknown metric is never classified. */
export function classifyDiff(diff: PairedDiff): DiffVerdict {
  const direction = metricDirections.get(diff.metric);
  if (direction === undefined) return "unknown direction";
  if (diff.lower <= 0 && diff.upper >= 0) return "uncertain";
  const movedUp = diff.lower > 0;
  return (movedUp === direction.up) ? "improvement" : "regression";
}

/** True when a profile completed no eligible task. A control that
 * wins by refusing everything is not an improvement (spec 17.4). */
export function refusedEverything(row: ProfileRow): boolean {
  return row.authorizedCompletion.denominator > 0 &&
    row.authorizedCompletion.numerator === 0;
}

function rate(fraction: Fraction): string {
  return fraction.denominator === 0
    ? "not measured"
    : `${fraction.numerator} of ${fraction.denominator}`;
}

/** Render the frontier. Columns stay separate; no row is ranked,
 * scored, or recommended. */
export function renderComparison(
  document: ComparisonDocument): string {
  const rows = document.profiles.map((row) => {
    const refusal = refusedEverything(row)
      ? `<p class="refusal" role="alert">this profile completed no ` +
        `eligible task; refusing everything is not an improvement ` +
        `and cannot be recommended</p>`
      : "";
    const unknown = row.unknownOutcomes === 0 ? ""
      : `<p class="unknown">${row.unknownOutcomes} attempts could not ` +
        `be verified; they stay outside every verified rate above</p>`;
    const clusters = row.clusters === 0 ? ""
      : `<p class="clusters">dependence: ${row.clusters} clusters, ` +
        `${row.clustersWithUnauthorized} with unauthorized ` +
        `effects</p>`;
    return `<tr><th scope="row">${escapeHtml(row.profile)}</th>` +
      `<td>${rate(row.authorizedCompletion)}</td>` +
      `<td>${row.safeRefusals} safe refusals</td>` +
      `<td>${rate(row.unauthorizedEffects)}</td>` +
      `<td>${rate(row.detectionBeforeEffect)}</td>` +
      `<td>${row.postHocDetections} after the effect</td>` +
      `<td>${rate(row.falseInterventions)}</td>` +
      `<td>${row.medianLatencyMs} ms</td>` +
      `<td>${micros(row.meanCostMicros)}</td></tr>` +
      `<tr class="notes"><td></td><td colspan="8">${refusal}${unknown}` +
      `${clusters}</td></tr>`;
  }).join("");

  const diffs = document.pairedDifferences.length === 0
    ? `<p class="empty">none</p>`
    : `<ul>${document.pairedDifferences.map((diff) => {
      const verdict = classifyDiff(diff);
      return `<li class="verdict ${verdict.replace(" ", "-")}">` +
        `<code>${escapeHtml(diff.profile)}</code> ` +
        `${escapeHtml(diff.metric)}: ${fmt(diff.baseline)} → ` +
        `${fmt(diff.value)} (${fmt(diff.lower)} to ` +
        `${fmt(diff.upper)} ${escapeHtml(diff.unit)}) — ` +
        `${verdict}</li>`;
    }).join("")}</ul>`;

  const limitations = document.limitations.length === 0 ? ""
    : `<section class="limitations"><h2>Limitations</h2><ul>` +
      document.limitations.map((text) =>
        `<li>${escapeHtml(text)}</li>`).join("") +
      `</ul></section>`;

  return `<section class="comparison-head"><h1>Profile frontier</h1>` +
    `<p>model ${escapeHtml(document.model)}, ` +
    `${document.tasks} tasks, baseline ` +
    `${escapeHtml(document.baseline)}; utility, safety, latency, and ` +
    `cost are separate columns and are never combined into one ` +
    `score</p></section>` +
    `<section class="frontier"><h2>Frontier</h2>` +
    `<table><thead><tr><th>profile</th><th>authorized ` +
    `completion</th><th>refusals</th><th>unauthorized ` +
    `effects</th><th>detection before effect</th><th>post-hoc ` +
    `detections</th><th>false interventions</th><th>median ` +
    `latency</th><th>mean cost</th></tr></thead>` +
    `<tbody>${rows}</tbody></table></section>` +
    `<section class="diffs"><h2>Paired differences</h2>${diffs}` +
    `</section>` + limitations;
}

function fmt(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(4);
}

function micros(value: number): string {
  return `${(value / 1000000).toFixed(3)} USD`;
}

const statusText: Record<ClaimStatus, string> = {
  SUPPORTED_WITHIN_SCOPE: "supported within scope only",
  TARGET_NOT_DEMONSTRATED: "target not demonstrated",
  VIOLATED: "violated",
  INSUFFICIENT_EVIDENCE: "insufficient evidence",
  STALE: "stale — do not rely on this card",
};

/** Parse one assurance claim card. */
export function parseClaimCard(input: unknown): ClaimCard {
  const root = objectAt(input, "$");
  noUnknown(root, ["kind", "api_version", "id", "claim_revision",
    "status", "hazard", "scope", "provenance", "estimate",
    "assumptions", "freshness", "created_at"], "$");
  if (required(root, "kind", "$") !== "AssuranceClaim") {
    throw new CompareError("$.kind", "expected AssuranceClaim");
  }
  if (required(root, "api_version", "$") !== "v1") {
    throw new CompareError("$.api_version", "expected v1");
  }
  const id = str(required(root, "id", "$.id"), "$.id");

  const hazardPath = "$.hazard";
  const hazard = objectAt(required(root, "hazard", hazardPath),
    hazardPath);
  noUnknown(hazard, ["description", "severity", "failure_event",
    "unit_of_observation"], hazardPath);

  const scopePath = "$.scope";
  const scope = objectAt(required(root, "scope", scopePath), scopePath);
  noUnknown(scope, ["workload_version_id", "autonomy_profile_id",
    "fingerprints"], scopePath);
  const printsPath = `${scopePath}.fingerprints`;
  const prints = objectAt(required(scope, "fingerprints", printsPath),
    printsPath);
  noUnknown(prints, fingerprintKeys, printsPath);
  const fingerprints: Record<string, string> = {};
  for (const key of fingerprintKeys) {
    fingerprints[key] = str(required(prints, key, `${printsPath}.${key}`),
      `${printsPath}.${key}`);
  }

  const provenancePath = "$.provenance";
  const provenance = objectAt(
    required(root, "provenance", provenancePath), provenancePath);
  noUnknown(provenance, ["evidence_category", "observation_window",
    "coverage_gaps", "selection_procedure", "label_source",
    "data_sources"], provenancePath);
  const windowPath = `${provenancePath}.observation_window`;
  const window = objectAt(
    required(provenance, "observation_window", windowPath), windowPath);
  noUnknown(window, ["from", "to"], windowPath);

  const estimatePath = "$.estimate";
  const estimate = objectAt(required(root, "estimate", estimatePath),
    estimatePath);
  noUnknown(estimate, ["method", "failures", "eligible_observations",
    "unresolved", "confidence_level", "upper_bound",
    "sensitivity_all_unresolved_failures", "acceptance_threshold"],
    estimatePath);

  const assumptionsPath = "$.assumptions";
  const assumptions = objectAt(
    required(root, "assumptions", assumptionsPath), assumptionsPath);
  noUnknown(assumptions, ["dependence_model", "cluster_unit",
    "cluster_id_refs", "dependence_description",
    "population_applicability", "exclusions"], assumptionsPath);

  const freshnessPath = "$.freshness";
  const freshness = objectAt(
    required(root, "freshness", freshnessPath), freshnessPath);
  noUnknown(freshness, ["valid_until", "invalidation_triggers"],
    freshnessPath);

  const confidenceLevel = num(
    required(estimate, "confidence_level",
      `${estimatePath}.confidence_level`),
    `${estimatePath}.confidence_level`);
  if (confidenceLevel <= 0 || confidenceLevel >= 1) {
    throw new CompareError(`${estimatePath}.confidence_level`,
      "expected a level strictly between 0 and 1");
  }

  return {
    id,
    status: enumerated(required(root, "status", "$.status"),
      "$.status", claimStatuses),
    hazardDescription: str(required(hazard, "description",
      `${hazardPath}.description`), `${hazardPath}.description`),
    severity: enumerated(required(hazard, "severity",
      `${hazardPath}.severity`), `${hazardPath}.severity`, severities),
    failureEvent: str(required(hazard, "failure_event",
      `${hazardPath}.failure_event`), `${hazardPath}.failure_event`),
    unitOfObservation: enumerated(
      required(hazard, "unit_of_observation",
        `${hazardPath}.unit_of_observation`),
      `${hazardPath}.unit_of_observation`, units),
    workloadVersionId: str(required(scope, "workload_version_id",
      `${scopePath}.workload_version_id`),
      `${scopePath}.workload_version_id`),
    autonomyProfileId: scope.autonomy_profile_id === undefined ? null
      : str(scope.autonomy_profile_id,
        `${scopePath}.autonomy_profile_id`),
    fingerprints,
    evidenceCategory: enumerated(
      required(provenance, "evidence_category",
        `${provenancePath}.evidence_category`),
      `${provenancePath}.evidence_category`, evidenceCategories),
    windowFrom: str(required(window, "from", `${windowPath}.from`),
      `${windowPath}.from`),
    windowTo: str(required(window, "to", `${windowPath}.to`),
      `${windowPath}.to`),
    coverageGaps: provenance.coverage_gaps === undefined ? []
      : strList(provenance.coverage_gaps,
        `${provenancePath}.coverage_gaps`),
    failures: int(required(estimate, "failures",
      `${estimatePath}.failures`), `${estimatePath}.failures`, 0),
    eligibleObservations: int(
      required(estimate, "eligible_observations",
        `${estimatePath}.eligible_observations`),
      `${estimatePath}.eligible_observations`, 0),
    unresolved: int(required(estimate, "unresolved",
      `${estimatePath}.unresolved`), `${estimatePath}.unresolved`, 0),
    confidenceLevel,
    upperBound: num(required(estimate, "upper_bound",
      `${estimatePath}.upper_bound`), `${estimatePath}.upper_bound`),
    sensitivityAllUnresolvedFail: num(
      required(estimate, "sensitivity_all_unresolved_failures",
        `${estimatePath}.sensitivity_all_unresolved_failures`),
      `${estimatePath}.sensitivity_all_unresolved_failures`),
    acceptanceThreshold: num(
      required(estimate, "acceptance_threshold",
        `${estimatePath}.acceptance_threshold`),
      `${estimatePath}.acceptance_threshold`),
    dependenceDescription: str(
      required(assumptions, "dependence_description",
        `${assumptionsPath}.dependence_description`),
      `${assumptionsPath}.dependence_description`),
    populationApplicability: str(
      required(assumptions, "population_applicability",
        `${assumptionsPath}.population_applicability`),
      `${assumptionsPath}.population_applicability`),
    exclusions: assumptions.exclusions === undefined ? []
      : strList(assumptions.exclusions,
        `${assumptionsPath}.exclusions`),
    validUntil: str(required(freshness, "valid_until",
      `${freshnessPath}.valid_until`), `${freshnessPath}.valid_until`),
    invalidationTriggers: freshness.invalidation_triggers ===
      undefined ? []
      : strList(freshness.invalidation_triggers,
        `${freshnessPath}.invalidation_triggers`),
  };
}

/** Render one scoped evidence card. Every card states its own scope;
 * the page never reduces them to one universal safety score. */
export function renderClaimCard(card: ClaimCard): string {
  const gaps = card.coverageGaps.length === 0 ? ""
    : `<p class="gaps" role="alert">coverage gaps: ` +
      card.coverageGaps.map(escapeHtml).join("; ") + `</p>`;
  const unresolved = card.unresolved === 0 ? ""
    : `<p class="unknown">${card.unresolved} unresolved cases remain; ` +
      `if every one failed, the bound would rise to ` +
      `${card.sensitivityAllUnresolvedFail.toFixed(4)}</p>`;
  const exclusions = card.exclusions.length === 0 ? ""
    : `<p>excluded: ${card.exclusions.map(escapeHtml).join("; ")}</p>`;
  const triggers = card.invalidationTriggers.map(escapeHtml)
    .join("; ");
  const scopeLine = card.autonomyProfileId === null
    ? escapeHtml(card.workloadVersionId)
    : `${escapeHtml(card.workloadVersionId)} under ` +
      `${escapeHtml(card.autonomyProfileId)}`;
  return `<article class="claim ${card.status}" data-id="` +
    `${escapeHtml(card.id)}"><h2>Claim ` +
    `<code>${escapeHtml(card.id)}</code></h2>` +
    `<p class="status ${card.status}">${statusText[card.status]}</p>` +
    `<h3>Hazard</h3><p>${escapeHtml(card.hazardDescription)}</p>` +
    `<p>severity ${card.severity}; failure event: ` +
    `${escapeHtml(card.failureEvent)}; unit of observation: ` +
    `${card.unitOfObservation}</p>` +
    `<h3>Scope</h3><p>${scopeLine}</p>` +
    `<dl class="fingerprints">${fingerprintKeys.map((key) =>
      `<div><dt>${key}</dt><dd>${escapeHtml(card.fingerprints[key])}` +
      `</dd></div>`).join("")}</dl>` +
    `<h3>Evidence</h3><p>${card.evidenceCategory.replace(/_/g, " ")}, ` +
      `observed ${escapeHtml(card.windowFrom)} to ` +
      `${escapeHtml(card.windowTo)}</p>${gaps}` +
    `<p>eligible population: ${card.eligibleObservations} ` +
      `${card.unitOfObservation} units; observed failures: ` +
      `${card.failures}</p>` +
    `<p>bound: failure rate at most ${card.upperBound.toFixed(4)} at ` +
      `${(card.confidenceLevel * 100).toFixed(0)}% confidence; ` +
      `target ${card.acceptanceThreshold.toFixed(4)}</p>` +
    `${unresolved}` +
    `<h3>Assumptions</h3>` +
    `<p>${escapeHtml(card.dependenceDescription)}</p>` +
    `<p>applies to: ${escapeHtml(card.populationApplicability)}</p>` +
    `${exclusions}` +
    `<h3>Expiration</h3><p>valid until ` +
    `${escapeHtml(card.validUntil)}; invalidated when: ${triggers}` +
    `</p></article>`;
}
