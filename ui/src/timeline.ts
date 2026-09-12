// Run timeline (spec 17.3, T033): agent, tool, broker, injection,
// monitor, and infrastructure events on separate trust-labeled lanes.
// Every finding links to the events it rests on; every external
// effect links to its authorization and its receipt, and a missing
// half of that pair stays visible. Everything renders as inert text:
// no active HTML, no tool execution, no automatic external retrieval
// from a log — object references are digests to read elsewhere, never
// fetches made here.

import { escapeHtml } from "./overview";

export type TrustLabel = "worker_claim" | "collector_fact" |
  "monitor_interpretation";

export type EventKind = "proposed_action" | "broker_decision" |
  "resource_access" | "tool_request" | "tool_response" |
  "external_receipt" | "delegation" | "budget_change" |
  "injection_receipt" | "collector_heartbeat" | "recovery_action";

export type SourceComponent = "collector" | "broker" | "governor" |
  "adapter" | "monitor" | "worker" | "verifier";

export type PayloadKind = "metadata_only" | "object_ref" | "inline";

// The six lanes, in display order. Monitor interpretations always
// take the monitor lane regardless of their event kind; everything
// else follows the kind map below.
export const lanes = ["agent", "tool", "broker", "injection", "monitor",
  "infrastructure"] as const;
export type Lane = (typeof lanes)[number];

export const kindLanes: Record<EventKind, Lane> = {
  proposed_action: "agent",
  resource_access: "agent",
  tool_request: "tool",
  tool_response: "tool",
  broker_decision: "broker",
  external_receipt: "broker",
  delegation: "broker",
  injection_receipt: "injection",
  collector_heartbeat: "infrastructure",
  budget_change: "infrastructure",
  recovery_action: "infrastructure",
};

export interface TimelineEvent {
  readonly id: string;
  readonly eventKind: EventKind;
  readonly trustLabel: TrustLabel;
  readonly sourceId: string;
  readonly component: SourceComponent;
  readonly coverage: boolean | null;
  readonly sequence: number;
  readonly observedAt: string;
  readonly clockUncertaintyMs: number;
  readonly payloadKind: PayloadKind;
  readonly payloadDigest: string | null;
  readonly payloadContent: string | null;
  readonly redacted: boolean;
  readonly truncated: boolean;
  readonly correlationIds: readonly string[];
}

export interface TimelineFinding {
  readonly id: string;
  readonly eventIds: readonly string[];
  readonly description: string;
}

export interface RunTimeline {
  readonly kind: "RunTimeline";
  readonly apiVersion: "v1";
  readonly runId: string;
  readonly events: readonly TimelineEvent[];
  readonly findings: readonly TimelineFinding[];
}

export class TimelineError extends Error {
  constructor(readonly path: string, reason: string) {
    super(`timeline document: ${path}: ${reason}`);
    this.name = "TimelineError";
  }
}

const reEvent = /^evt_[a-z0-9]{8,64}$/;
const reRun = /^run_[a-z0-9]{8,64}$/;
const reSource = /^src_[a-z0-9][a-z0-9-]{3,63}$/;
const reCorrelation = /^cid_[A-Za-z0-9_-]{4,128}$/;
const reDigest = /^sha256:[0-9a-f]{64}$/;
const reStamp = /^\d{4}-\d{2}-\d{2}T/;
const reFinding = /^fnd_[a-z0-9]{8,64}$/;

const eventKinds: readonly EventKind[] = ["proposed_action",
  "broker_decision", "resource_access", "tool_request", "tool_response",
  "external_receipt", "delegation", "budget_change", "injection_receipt",
  "collector_heartbeat", "recovery_action"];
const trustLabels: readonly TrustLabel[] = ["worker_claim",
  "collector_fact", "monitor_interpretation"];
const sourceComponents: readonly SourceComponent[] = ["collector",
  "broker", "governor", "adapter", "monitor", "worker", "verifier"];
const payloadKinds: readonly PayloadKind[] = ["metadata_only",
  "object_ref", "inline"];

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function objectAt(value: unknown, path: string): Record<string, unknown> {
  if (!isObject(value)) {
    throw new TimelineError(path, "expected an object");
  }
  return value;
}

function noUnknown(document: Record<string, unknown>,
  allowed: readonly string[], path: string): void {
  for (const key of Object.keys(document)) {
    if (!allowed.includes(key)) {
      throw new TimelineError(`${path}.${key}`, "unknown field");
    }
  }
}

function required(document: Record<string, unknown>, key: string,
  path: string): unknown {
  if (!(key in document)) {
    throw new TimelineError(`${path}.${key}`, "missing required field");
  }
  return document[key];
}

function str(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TimelineError(path, "expected a non-empty string");
  }
  return value;
}

function pattern(value: string, regex: RegExp, path: string,
  shape: string): string {
  if (!regex.test(value)) {
    throw new TimelineError(path, `expected ${shape}`);
  }
  return value;
}

function enumerated<T extends string>(value: unknown, path: string,
  allowed: readonly T[]): T {
  const text = str(value, path);
  if (!(allowed as readonly string[]).includes(text)) {
    throw new TimelineError(path, `expected one of ${allowed.join(", ")}`);
  }
  return text as T;
}

function arr(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new TimelineError(path, "expected an array");
  }
  return value;
}

function booleanAt(document: Record<string, unknown>, key: string,
  path: string): boolean {
  const value = required(document, key, `${path}.${key}`);
  if (typeof value !== "boolean") {
    throw new TimelineError(`${path}.${key}`, "expected a boolean");
  }
  return value;
}

/** Parse the timeline document strictly. */
export function parseTimeline(input: unknown): RunTimeline {
  const root = objectAt(input, "$");
  noUnknown(root, ["kind", "api_version", "run_id", "events", "findings"],
    "$");
  if (required(root, "kind", "$") !== "RunTimeline") {
    throw new TimelineError("$.kind", "expected RunTimeline");
  }
  if (required(root, "api_version", "$") !== "v1") {
    throw new TimelineError("$.api_version", "expected v1");
  }
  const runId = pattern(str(required(root, "run_id", "$.run_id"),
    "$.run_id"), reRun, "$.run_id", "run_ plus id");

  const events = arr(required(root, "events", "$.events"), "$.events")
    .map((raw, index) => parseEvent(raw, `$.events[${index}]`));

  const seen = new Set<string>();
  for (const event of events) {
    if (seen.has(event.id)) {
      throw new TimelineError("$.events", `event ${event.id} listed twice`);
    }
    seen.add(event.id);
  }

  const findings = root.findings === undefined ? []
    : arr(root.findings, "$.findings").map((raw, index) =>
      parseFinding(raw, `$.findings[${index}]`, seen));
  return { kind: "RunTimeline", apiVersion: "v1", runId, events,
    findings };
}

function parseEvent(raw: unknown, path: string): TimelineEvent {
  const event = objectAt(raw, path);
  noUnknown(event, ["id", "event_kind", "trust_label", "source",
    "sequence", "observed_at", "clock_uncertainty_ms", "payload",
    "correlation_ids"], path);

  const sourcePath = `${path}.source`;
  const source = objectAt(required(event, "source", sourcePath),
    sourcePath);
  noUnknown(source, ["id", "component", "coverage"], sourcePath);
  const sourceId = pattern(str(required(source, "id",
    `${sourcePath}.id`), `${sourcePath}.id`), reSource,
    `${sourcePath}.id`, "src_ plus id");
  const component = enumerated(required(source, "component",
    `${sourcePath}.component`), `${sourcePath}.component`,
    sourceComponents);
  const coverage = source.coverage === undefined ? null
    : booleanAt(source, "coverage", sourcePath);

  const payloadPath = `${path}.payload`;
  const payload = objectAt(required(event, "payload", payloadPath),
    payloadPath);
  noUnknown(payload, ["kind", "digest", "content", "redacted",
    "truncated"], payloadPath);
  const payloadKind = enumerated(required(payload, "kind",
    `${payloadPath}.kind`), `${payloadPath}.kind`, payloadKinds);
  const payloadDigest = payload.digest === undefined ? null
    : pattern(str(payload.digest, `${payloadPath}.digest`),
      reDigest, `${payloadPath}.digest`, "a sha256 digest");
  const payloadContent = payload.content === undefined ? null
    : str(payload.content, `${payloadPath}.content`);

  const correlationIds = event.correlation_ids === undefined ? []
    : arr(event.correlation_ids, `${path}.correlation_ids`)
      .map((cid, cidIndex) => pattern(
        str(cid, `${path}.correlation_ids[${cidIndex}]`),
        reCorrelation, `${path}.correlation_ids[${cidIndex}]`,
        "cid_ plus id"));

  const sequence = required(event, "sequence", `${path}.sequence`);
  if (typeof sequence !== "number" || !Number.isInteger(sequence) ||
    sequence < 0) {
    throw new TimelineError(`${path}.sequence`,
      "expected a non-negative integer");
  }
  const clockUncertainty = required(event, "clock_uncertainty_ms",
    `${path}.clock_uncertainty_ms`);
  if (typeof clockUncertainty !== "number" ||
    !Number.isInteger(clockUncertainty) || clockUncertainty < 0) {
    throw new TimelineError(`${path}.clock_uncertainty_ms`,
      "expected a non-negative integer");
  }

  return {
    id: pattern(str(required(event, "id", `${path}.id`), `${path}.id`),
      reEvent, `${path}.id`, "evt_ plus id"),
    eventKind: enumerated(required(event, "event_kind",
      `${path}.event_kind`), `${path}.event_kind`, eventKinds),
    trustLabel: enumerated(required(event, "trust_label",
      `${path}.trust_label`), `${path}.trust_label`, trustLabels),
    sourceId,
    component,
    coverage,
    sequence,
    observedAt: pattern(str(required(event, "observed_at",
      `${path}.observed_at`), `${path}.observed_at`), reStamp,
      `${path}.observed_at`, "a timestamp"),
    clockUncertaintyMs: clockUncertainty,
    payloadKind,
    payloadDigest,
    payloadContent,
    redacted: booleanAt(payload, "redacted", payloadPath),
    truncated: booleanAt(payload, "truncated", payloadPath),
    correlationIds,
  };
}

function parseFinding(raw: unknown, path: string,
  knownEvents: ReadonlySet<string>): TimelineFinding {
  const finding = objectAt(raw, path);
  noUnknown(finding, ["id", "event_ids", "description"], path);
  const ids = arr(required(finding, "event_ids", `${path}.event_ids`),
    `${path}.event_ids`)
    .map((id, idIndex) => pattern(
      str(id, `${path}.event_ids[${idIndex}]`), reEvent,
      `${path}.event_ids[${idIndex}]`, "evt_ plus id"));
  for (const id of ids) {
    if (!knownEvents.has(id)) {
      throw new TimelineError(`${path}.event_ids`,
        `references unknown event ${id}`);
    }
  }
  return {
    id: pattern(str(required(finding, "id", `${path}.id`), `${path}.id`),
      reFinding, `${path}.id`, "fnd_ plus id"),
    eventIds: ids,
    description: str(required(finding, "description",
      `${path}.description`), `${path}.description`),
  };
}

/** The lane one event renders on. Monitor interpretations always take
 * the monitor lane; other events follow their kind. */
export function laneFor(event: TimelineEvent): Lane {
  if (event.trustLabel === "monitor_interpretation") return "monitor";
  return kindLanes[event.eventKind];
}

/** One external effect pairing: a broker decision and the receipt the
 * recipient side recorded, joined by a shared correlation id. A
 * missing half is carried as null and stays visible in the render. */
export interface EffectPairing {
  readonly correlationId: string;
  readonly authorization: TimelineEvent | null;
  readonly receipt: TimelineEvent | null;
}

/** Pair broker decisions with external receipts through correlation
 * ids. Unpaired halves are kept, never dropped. */
export function pairEffects(
  events: readonly TimelineEvent[]): EffectPairing[] {
  const byCorrelation = new Map<string, EffectPairing>();
  for (const event of events) {
    if (event.eventKind !== "broker_decision" &&
      event.eventKind !== "external_receipt") {
      continue;
    }
    if (event.correlationIds.length === 0) continue;
    const correlationId = event.correlationIds[0];
    if (correlationId === undefined) continue;
    const current = byCorrelation.get(correlationId) ??
      { correlationId, authorization: null, receipt: null };
    const next = event.eventKind === "broker_decision"
      ? { ...current, authorization: current.authorization ?? event }
      : { ...current, receipt: current.receipt ?? event };
    byCorrelation.set(correlationId, next);
  }
  return [...byCorrelation.values()].sort((left, right) =>
    left.correlationId < right.correlationId ? -1 : 1);
}

const trustLabelsText: Record<TrustLabel, string> = {
  worker_claim: "worker claim",
  collector_fact: "collector fact",
  monitor_interpretation: "monitor interpretation",
};

/** Render the timeline as inert HTML. */
export function renderTimeline(timeline: RunTimeline): string {
  const blocks: string[] = [];
  blocks.push(`<section class="timeline-head"><h1>Run timeline ` +
    `${escapeHtml(timeline.runId)}</h1>` +
    `<p class="ordering">lanes hold per-source sequences; no global ` +
    `total order is assumed across sources</p></section>`);

  for (const lane of lanes) {
    const events = timeline.events
      .filter((event) => laneFor(event) === lane)
      .sort(compareEvents);
    blocks.push(`<section class="lane" data-lane="${lane}"><h2>${lane}` +
      `</h2>` +
      (events.length === 0
        ? `<p class="empty">no events</p>`
        : `<ol class="events">${events.map(renderEvent).join("")}</ol>`) +
      `</section>`);
  }

  blocks.push(renderEffects(timeline.events));
  blocks.push(renderFindings(timeline.findings));
  return blocks.join("\n");
}

function compareEvents(left: TimelineEvent, right: TimelineEvent): number {
  if (left.observedAt !== right.observedAt) {
    return left.observedAt < right.observedAt ? -1 : 1;
  }
  if (left.sourceId !== right.sourceId) {
    return left.sourceId < right.sourceId ? -1 : 1;
  }
  return left.sequence - right.sequence;
}

function renderEffects(events: readonly TimelineEvent[]): string {
  const pairings = pairEffects(events);
  if (pairings.length === 0) {
    return `<section class="effects"><h2>External effects</h2>` +
      `<p class="empty">none</p></section>`;
  }
  const items = pairings.map((pairing) => {
    const authorization = pairing.authorization === null
      ? `<span class="missing">authorization missing</span>`
      : `<code>${escapeHtml(pairing.authorization.id)}</code>`;
    const receipt = pairing.receipt === null
      ? `<span class="missing">receipt missing</span>`
      : `<code>${escapeHtml(pairing.receipt.id)}</code>`;
    return `<li>correlation ${escapeHtml(pairing.correlationId)}: ` +
      `authorization ${authorization}, receipt ${receipt}</li>`;
  });
  return `<section class="effects"><h2>External effects</h2><ul>` +
    items.join("") + `</ul></section>`;
}

function renderFindings(findings: readonly TimelineFinding[]): string {
  if (findings.length === 0) {
    return `<section class="findings"><h2>Findings</h2>` +
      `<p class="empty">none</p></section>`;
  }
  const items = findings.map((finding) =>
    `<li><code>${escapeHtml(finding.id)}</code> ` +
    `${escapeHtml(finding.description)} — evidence ` +
    finding.eventIds.map((id) => `<code>${escapeHtml(id)}</code>`)
      .join(" ") +
    `</li>`);
  return `<section class="findings"><h2>Findings</h2><ul>` +
    items.join("") + `</ul></section>`;
}

function renderEvent(event: TimelineEvent): string {
  const payload = payloadText(event);
  const flags = [
    event.redacted ? "redacted" : null,
    event.truncated ? "truncated" : null,
    event.coverage === false ? "source coverage limited" : null,
    event.clockUncertaintyMs > 0
      ? `clock ±${event.clockUncertaintyMs}ms` : null,
  ].filter((flag): flag is string => flag !== null);
  return `<li class="event ${event.trustLabel}" data-id="` +
    `${escapeHtml(event.id)}">` +
    `<span class="trust">${trustLabelsText[event.trustLabel]}</span> ` +
    `<code>${escapeHtml(event.id)}</code> ${event.eventKind} from ` +
    `<code>${escapeHtml(event.sourceId)}</code> (${event.component}) ` +
    `seq ${event.sequence} at ${escapeHtml(event.observedAt)}` +
    (flags.length === 0 ? "" : ` · ${flags.join(", ")}`) +
    ` · ${payload}` +
    `</li>`;
}

function payloadText(event: TimelineEvent): string {
  if (event.payloadKind === "object_ref") {
    const digest = event.payloadDigest === null ? "unknown digest"
      : escapeHtml(event.payloadDigest);
    return `object <code>${digest}</code> — read the raw content from ` +
      `the evidence store; it is not fetched here`;
  }
  if (event.payloadKind === "inline") {
    const content = event.payloadContent === null ? ""
      : `: ${escapeHtml(event.payloadContent)}`;
    return `inline payload${content}`;
  }
  return "metadata only";
}
