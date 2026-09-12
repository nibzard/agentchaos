// Workload overview (spec 17.1, T031): enrolled workload versions,
// supported modes, coverage gaps, current autonomy profile, useful
// throughput, recent failures, evidence freshness, and cost — with
// test results separated from production results, and a missing
// enforcement path more prominent than any score.

// A coverage gap outranks every positive metric. The order of the
// severity list is the sort order.
export const severityOrder = ["high", "medium", "low"] as const;
export type Severity = (typeof severityOrder)[number];

export type Environment = "synthetic" | "production";
export type FreshnessStatus = "fresh" | "stale" | "unknown";

export interface CoverageGap {
  readonly path: string;
  readonly severity: Severity;
  readonly detail?: string;
}

export interface RecentFailure {
  readonly runId: string;
  readonly label: string;
  readonly at: string;
}

export interface Throughput {
  readonly authorizedCompletions: number;
  readonly eligibleTasks: number;
  readonly windowHours: number;
}

export interface EvidenceFreshness {
  readonly status: FreshnessStatus;
  readonly validUntil?: string;
  readonly staleReason?: string;
}

export interface WorkloadCost {
  readonly currency: string;
  readonly totalMicros: number;
}

export interface WorkloadEntry {
  readonly workloadVersionId: string;
  readonly environment: Environment;
  readonly modes: readonly string[];
  readonly autonomyProfile: string;
  readonly coverageGaps: readonly CoverageGap[];
  readonly throughput: Throughput;
  readonly recentFailures: readonly RecentFailure[];
  readonly freshness: EvidenceFreshness;
  readonly cost: WorkloadCost;
}

export interface OverviewSnapshot {
  readonly kind: "WorkloadOverview";
  readonly apiVersion: "v1";
  readonly generatedAt: string;
  readonly workloads: readonly WorkloadEntry[];
}

// parseError names the field path that failed, so a bad document is
// debuggable instead of mysterious.
export class ParseError extends Error {
  constructor(readonly path: string, reason: string) {
    super(`overview document: ${path}: ${reason}`);
    this.name = "ParseError";
  }
}

const idPattern = /^wlv_[0-9a-f]{16}$/;
const runPattern = /^run_[0-9a-f]{16}$/;
const stampPattern = /^\d{4}-\d{2}-\d{2}T/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function field(document: Record<string, unknown>, key: string,
  path: string): unknown {
  if (!(key in document)) {
    throw new ParseError(path, "missing required field");
  }
  return document[key];
}

function expectString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ParseError(path, "expected a non-empty string");
  }
  return value;
}

function expectNumber(value: unknown, path: string,
  minimum: number): number {
  if (typeof value !== "number" || !Number.isFinite(value) ||
    value < minimum) {
    throw new ParseError(path, `expected a number >= ${minimum}`);
  }
  return value;
}

function expectEnum<T extends string>(value: unknown, path: string,
  allowed: readonly T[]): T {
  const text = expectString(value, path);
  if (!(allowed as readonly string[]).includes(text)) {
    throw new ParseError(path,
      `expected one of ${allowed.join(", ")}, got ${text}`);
  }
  return text as T;
}

function expectArray(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new ParseError(path, "expected an array");
  }
  return value;
}

// Strict key set per nesting level, matching the repo's contract
// convention (ADR-0002): unknown fields fail closed.
const snapshotKeys = ["kind", "api_version", "generated_at", "workloads"];
const entryKeys = ["workload_version_id", "environment", "modes",
  "autonomy_profile", "coverage_gaps", "throughput", "recent_failures",
  "freshness", "cost"];
const gapKeys = ["path", "severity", "detail"];
const throughputKeys = ["authorized_completions", "eligible_tasks",
  "window_hours"];
const failureKeys = ["run_id", "label", "at"];
const freshnessKeys = ["status", "valid_until", "stale_reason"];
const costKeys = ["currency", "total_micros"];

function checkKeys(document: Record<string, unknown>,
  allowed: readonly string[], path: string): void {
  for (const key of Object.keys(document)) {
    if (!allowed.includes(key)) {
      throw new ParseError(`${path}.${key}`, "unknown field");
    }
  }
}

/** Parse the overview document strictly. Anything unannounced or
 * malformed throws; the UI never renders a half-understood document. */
export function parseOverview(input: unknown): OverviewSnapshot {
  const root = requireObject(input, "$");
  checkKeys(root, snapshotKeys, "$");
  if (field(root, "kind", "$.kind") !== "WorkloadOverview") {
    throw new ParseError("$.kind", "expected WorkloadOverview");
  }
  if (field(root, "api_version", "$.api_version") !== "v1") {
    throw new ParseError("$.api_version", "expected v1");
  }
  const generatedAt =
    expectString(field(root, "generated_at", "$.generated_at"),
      "$.generated_at");
  if (!stampPattern.test(generatedAt)) {
    throw new ParseError("$.generated_at", "expected a timestamp");
  }

  const rawWorkloads = expectArray(field(root, "workloads", "$.workloads"),
    "$.workloads");
  const workloads = rawWorkloads.map((raw, index) =>
    parseEntry(raw, `$.workloads[${index}]`));

  return { kind: "WorkloadOverview", apiVersion: "v1", generatedAt,
    workloads };
}

function requireObject(value: unknown, path: string,
  what = "expected an object"): Record<string, unknown> {
  if (!isObject(value)) {
    throw new ParseError(path, what);
  }
  return value;
}

function parseEntry(input: unknown, path: string): WorkloadEntry {
  const entry = requireObject(input, path);
  checkKeys(entry, entryKeys, path);
  const throughputPath = `${path}.throughput`;
  const throughputDoc =
    requireObject(field(entry, "throughput", throughputPath),
      throughputPath);
  checkKeys(throughputDoc, throughputKeys, throughputPath);

  const freshnessPath = `${path}.freshness`;
  const freshnessDoc =
    requireObject(field(entry, "freshness", freshnessPath), freshnessPath);
  checkKeys(freshnessDoc, freshnessKeys, freshnessPath);
  const freshnessStatus = expectEnum(
    field(freshnessDoc, "status", `${freshnessPath}.status`),
    `${freshnessPath}.status`, ["fresh", "stale", "unknown"]);

  const costPath = `${path}.cost`;
  const costDoc = requireObject(field(entry, "cost", costPath), costPath);
  checkKeys(costDoc, costKeys, costPath);

  const gapsPath = `${path}.coverage_gaps`;
  const gaps = expectArray(field(entry, "coverage_gaps", gapsPath), gapsPath)
    .map((raw, index) => {
      const gapPath = `${gapsPath}[${index}]`;
      const gap = requireObject(raw, gapPath);
      checkKeys(gap, gapKeys, gapPath);
      const severity = expectEnum(field(gap, "severity", `${gapPath}.severity`),
        `${gapPath}.severity`, severityOrder);
      const detail = gap.detail === undefined ? undefined
        : expectString(gap.detail, `${gapPath}.detail`);
      return {
        path: expectString(field(gap, "path", `${gapPath}.path`),
          `${gapPath}.path`),
        severity,
        ...(detail === undefined ? {} : { detail }),
      };
    });

  const failuresPath = `${path}.recent_failures`;
  const failures =
    expectArray(field(entry, "recent_failures", failuresPath), failuresPath)
      .map((raw, index) => {
        const failurePath = `${failuresPath}[${index}]`;
        const failure = requireObject(raw, failurePath);
        checkKeys(failure, failureKeys, failurePath);
        const runId =
          expectString(field(failure, "run_id", `${failurePath}.run_id`),
            `${failurePath}.run_id`);
        if (!runPattern.test(runId)) {
          throw new ParseError(`${failurePath}.run_id`,
            "expected run_ plus 16 hex");
        }
        return {
          runId,
          label: expectString(field(failure, "label", `${failurePath}.label`),
            `${failurePath}.label`),
          at: expectString(field(failure, "at", `${failurePath}.at`),
            `${failurePath}.at`),
        };
      });

  const workloadVersionId =
    expectString(field(entry, "workload_version_id",
      `${path}.workload_version_id`), `${path}.workload_version_id`);
  if (!idPattern.test(workloadVersionId)) {
    throw new ParseError(`${path}.workload_version_id`,
      "expected wlv_ plus 16 hex");
  }

  const modesPath = `${path}.modes`;
  const rawModes = expectArray(field(entry, "modes", modesPath), modesPath);
  if (rawModes.length === 0) {
    throw new ParseError(modesPath,
      "a workload supports at least one mode; an empty list is not a state");
  }

  const validUntil = freshnessDoc.valid_until === undefined ? undefined
    : expectString(freshnessDoc.valid_until,
      `${freshnessPath}.valid_until`);
  const staleReason = freshnessDoc.stale_reason === undefined ? undefined
    : expectString(freshnessDoc.stale_reason,
      `${freshnessPath}.stale_reason`);

  return {
    workloadVersionId,
    environment: expectEnum(field(entry, "environment",
      `${path}.environment`), `${path}.environment`,
    ["synthetic", "production"]),
    modes: rawModes.map((mode, index) =>
      expectString(mode, `${modesPath}[${index}]`)),
    autonomyProfile: expectString(field(entry, "autonomy_profile",
      `${path}.autonomy_profile`), `${path}.autonomy_profile`),
    coverageGaps: gaps,
    throughput: {
      authorizedCompletions: expectNumber(
        field(throughputDoc, "authorized_completions",
          `${throughputPath}.authorized_completions`),
        `${throughputPath}.authorized_completions`, 0),
      eligibleTasks: expectNumber(
        field(throughputDoc, "eligible_tasks",
          `${throughputPath}.eligible_tasks`),
        `${throughputPath}.eligible_tasks`, 1),
      windowHours: expectNumber(
        field(throughputDoc, "window_hours", `${throughputPath}.window_hours`),
        `${throughputPath}.window_hours`, 0),
    },
    recentFailures: failures,
    freshness: {
      status: freshnessStatus,
      ...(validUntil === undefined ? {} : { validUntil }),
      ...(staleReason === undefined ? {} : { staleReason }),
    },
    cost: {
      currency: expectString(field(costDoc, "currency",
        `${costPath}.currency`), `${costPath}.currency`),
      totalMicros: expectNumber(field(costDoc, "total_micros",
        `${costPath}.total_micros`), `${costPath}.total_micros`, 0),
    },
  };
}

// Rendering. Every dynamic value passes through escapeHtml: the page
// renders data as inert text, never as markup (ADR-0001 boundary;
// T036 generalizes this to raw evidence).

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** Sort workloads for display: missing enforcement paths first, then
 * failures, then cost. Scores never outrank gaps (spec 17.1). */
export function sortForDisplay(
  workloads: readonly WorkloadEntry[]): WorkloadEntry[] {
  const gapRank = (entry: WorkloadEntry): number =>
    entry.coverageGaps.length === 0 ? severityOrder.length
      : Math.min(...entry.coverageGaps.map((gap) =>
        severityOrder.indexOf(gap.severity)));
  return [...workloads].sort((left, right) => {
    const byGap = gapRank(left) - gapRank(right);
    if (byGap !== 0) return byGap;
    const byFailure =
      right.recentFailures.length - left.recentFailures.length;
    if (byFailure !== 0) return byFailure;
    if (left.workloadVersionId < right.workloadVersionId) return -1;
    if (left.workloadVersionId > right.workloadVersionId) return 1;
    return 0;
  });
}

const environmentTitles: Record<Environment, string> = {
  synthetic: "Test workloads (synthetic identities)",
  production: "Production workloads",
};

/** Render the whole overview as inert HTML. */
export function renderOverview(snapshot: OverviewSnapshot): string {
  const synthetic = sortForDisplay(snapshot.workloads.filter(
    (entry) => entry.environment === "synthetic"));
  const production = sortForDisplay(snapshot.workloads.filter(
    (entry) => entry.environment === "production"));

  const sections: string[] = [];
  sections.push(
    `<section class="overview-head">` +
    `<h1>Workload overview</h1>` +
    `<p class="generated">generated ${escapeHtml(snapshot.generatedAt)}</p>` +
    `</section>`);
  sections.push(renderSection("synthetic", synthetic));
  sections.push(renderSection("production", production));
  return sections.join("\n");
}

function renderSection(environment: Environment,
  entries: readonly WorkloadEntry[]): string {
  const rows = entries.map(renderEntry).join("\n");
  return `<section class="environment" data-environment="${environment}">` +
    `<h2>${escapeHtml(environmentTitles[environment])}</h2>` +
    (entries.length === 0
      ? `<p class="empty">none enrolled</p>`
      : `<ul class="workloads">${rows}</ul>`) +
    `</section>`;
}

function renderEntry(entry: WorkloadEntry): string {
  // The gap block renders above every metric block on purpose: a
  // missing enforcement path is more prominent than a high score.
  const gapBlock = entry.coverageGaps.length === 0
    ? `<p class="gaps none">no coverage gaps on record</p>`
    : `<div class="gaps" role="alert">` +
      `<h3>Coverage gaps (${entry.coverageGaps.length})</h3>` +
      `<ul>${entry.coverageGaps.map((gap) =>
        `<li class="gap ${gap.severity}">` +
        `<span class="severity">${gap.severity}</span> ` +
        `<span class="path">${escapeHtml(gap.path)}</span>` +
        (gap.detail === undefined ? ""
          : `<span class="detail"> — ${escapeHtml(gap.detail)}</span>`) +
        `</li>`).join("")}</ul></div>`;

  const rate = entry.throughput.eligibleTasks > 0
    ? entry.throughput.authorizedCompletions / entry.throughput.eligibleTasks
    : 0;
  const throughput =
    `<p class="throughput">useful throughput ` +
    `${entry.throughput.authorizedCompletions} authorized completions of ` +
    `${entry.throughput.eligibleTasks} eligible tasks ` +
    `over ${entry.throughput.windowHours} h ` +
    `(rate ${(rate * 100).toFixed(1)}%)</p>`;

  const failures = entry.recentFailures.length === 0
    ? `<p class="failures none">no recent failures</p>`
    : `<div class="failures"><h3>Recent failures</h3><ul>` +
      entry.recentFailures.map((failure) =>
        `<li><code>${escapeHtml(failure.runId)}</code> ` +
        `${escapeHtml(failure.label)} at ${escapeHtml(failure.at)}</li>`)
        .join("") +
      `</ul></div>`;

  const freshness = `<p class="freshness ${entry.freshness.status}">` +
    `evidence ${entry.freshness.status}` +
    (entry.freshness.validUntil === undefined ? ""
      : ` until ${escapeHtml(entry.freshness.validUntil)}`) +
    (entry.freshness.staleReason === undefined ? ""
      : ` — ${escapeHtml(entry.freshness.staleReason)}`) +
    `</p>`;

  const cost = `<p class="cost">cost ` +
    `${(entry.cost.totalMicros / 1_000_000).toFixed(3)} ` +
    `${escapeHtml(entry.cost.currency)}</p>`;

  return `<li class="workload" data-id="${escapeHtml(entry.workloadVersionId)}">` +
    `<h3 class="version">${escapeHtml(entry.workloadVersionId)}</h3>` +
    `<p class="profile">autonomy profile ` +
    `${escapeHtml(entry.autonomyProfile)} · modes ` +
    `${entry.modes.map(escapeHtml).join(", ")}</p>` +
    gapBlock + throughput + failures + freshness + cost +
    `</li>`;
}
