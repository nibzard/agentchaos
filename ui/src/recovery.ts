// Recovery and governance view (spec 17.6, T035): fenced groups,
// unknown effects, dirty environments, compensation attempts, and
// cleanup receipts. The emergency safety lever stays visible to
// authorized operators at all times. Routine operation has no human
// approval inbox — there is no approvals queue to render. Policy
// changes and exceptional incident closure carry their own audit
// trail, separate from run operations. The parser rejects unknown
// fields at every level (ADR-0002); the renderer emits inert text.

import { escapeHtml } from "./overview";

export type FencedScopeKind = "experiment" | "tenant";

export type TerminalCleanup = "CLEAN" | "DIRTY_QUARANTINED" | "UNKNOWN";

export type CompensationStatus = "pending" | "paid" | "failed";

export type AuditKind = "policy_change" | "exceptional_closure";

export interface FencedGroup {
  readonly scopeKind: FencedScopeKind;
  readonly scopeId: string;
  readonly reason: string;
  readonly fencedAt: string;
  readonly by: string;
}

export interface UnknownEffect {
  readonly effectId: string;
  readonly description: string;
  readonly correlationId: string | null;
  readonly discoveredAt: string;
}

export interface DirtyEnvironment {
  readonly environmentId: string;
  readonly runId: string;
  readonly terminalState: TerminalCleanup;
  readonly since: string;
}

export interface CompensationAttempt {
  readonly attemptId: string;
  readonly target: string;
  readonly status: CompensationStatus;
  readonly amountMicros: number;
  readonly currency: string;
  readonly receiptDigest: string | null;
}

export interface CleanupReceipt {
  readonly receiptId: string;
  readonly environmentId: string;
  readonly verifiedBy: string;
  readonly digest: string;
  readonly at: string;
}

export interface AuditEntry {
  readonly entryId: string;
  readonly kind: AuditKind;
  readonly action: string;
  readonly actor: string;
  readonly at: string;
}

export interface SafetyLever {
  readonly accessible: boolean;
  readonly path: string;
  readonly authorizedOperators: readonly string[];
}

export interface RecoveryBoard {
  readonly kind: "RecoveryBoard";
  readonly apiVersion: "v1";
  readonly fenced: readonly FencedGroup[];
  readonly unknownEffects: readonly UnknownEffect[];
  readonly dirtyEnvironments: readonly DirtyEnvironment[];
  readonly compensation: readonly CompensationAttempt[];
  readonly cleanupReceipts: readonly CleanupReceipt[];
  readonly lever: SafetyLever;
  readonly auditTrail: readonly AuditEntry[];
}

export class RecoveryError extends Error {
  constructor(readonly path: string, reason: string) {
    super(`recovery document: ${path}: ${reason}`);
    this.name = "RecoveryError";
  }
}

const reExperiment = /^exp_[a-z0-9]{8,64}$/;
const reRun = /^run_[a-z0-9]{8,64}$/;
const reEffect = /^eff_[a-z0-9]{8,64}$/;
const reCorrelation = /^cid_[A-Za-z0-9_-]{4,128}$/;
const reActor = /^act_[a-z0-9][a-z0-9-]{3,63}$/;
const reDigest = /^sha256:[0-9a-f]{64}$/;
const reEnvironment = /^env_[a-z0-9]{8,64}$/;
const reAttempt = /^cmp_[a-z0-9]{8,64}$/;
const reReceipt = /^rcp_[a-z0-9]{8,64}$/;
const reAudit = /^aud_[a-z0-9]{8,64}$/;
const reStamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;
const reSameOriginPath = /^\/[A-Za-z0-9._~/-]*$/;

const terminalStates: readonly TerminalCleanup[] = ["CLEAN",
  "DIRTY_QUARANTINED", "UNKNOWN"];
const compensationStatuses: readonly CompensationStatus[] = ["pending",
  "paid", "failed"];
const auditKinds: readonly AuditKind[] = ["policy_change",
  "exceptional_closure"];
const scopeKinds: readonly FencedScopeKind[] = ["experiment", "tenant"];

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function objectAt(value: unknown, path: string): Record<string, unknown> {
  if (!isObject(value)) {
    throw new RecoveryError(path, "expected an object");
  }
  return value;
}

function noUnknown(document: Record<string, unknown>,
  allowed: readonly string[], path: string): void {
  for (const key of Object.keys(document)) {
    if (!allowed.includes(key)) {
      throw new RecoveryError(`${path}.${key}`, "unknown field");
    }
  }
}

function required(document: Record<string, unknown>, key: string,
  path: string): unknown {
  if (!(key in document)) {
    throw new RecoveryError(`${path}.${key}`, "missing required field");
  }
  return document[key];
}

function str(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new RecoveryError(path, "expected a non-empty string");
  }
  return value;
}

function stamp(value: unknown, path: string): string {
  const text = str(value, path);
  if (!reStamp.test(text)) {
    throw new RecoveryError(path, "expected a UTC timestamp");
  }
  return text;
}

function pattern(value: string, regex: RegExp, path: string,
  shape: string): string {
  if (!regex.test(value)) {
    throw new RecoveryError(path, `expected ${shape}`);
  }
  return value;
}

function enumerated<T extends string>(value: unknown, path: string,
  allowed: readonly T[]): T {
  const text = str(value, path);
  if (!(allowed as readonly string[]).includes(text)) {
    throw new RecoveryError(path, `expected one of ${allowed.join(", ")}`);
  }
  return text as T;
}

function list(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new RecoveryError(path, "expected an array");
  }
  return value;
}

function int(value: unknown, path: string, minimum: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) ||
    value < minimum) {
    throw new RecoveryError(path,
      `expected an integer of at least ${minimum}`);
  }
  return value;
}

function bool(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") {
    throw new RecoveryError(path, "expected a boolean");
  }
  return value;
}

/** Parse the recovery board document strictly. */
export function parseRecovery(input: unknown): RecoveryBoard {
  const root = objectAt(input, "$");
  noUnknown(root, ["kind", "api_version", "fenced", "unknown_effects",
    "dirty_environments", "compensation", "cleanup_receipts", "lever",
    "audit_trail"], "$");
  if (required(root, "kind", "$") !== "RecoveryBoard") {
    throw new RecoveryError("$.kind", "expected RecoveryBoard");
  }
  if (required(root, "api_version", "$") !== "v1") {
    throw new RecoveryError("$.api_version", "expected v1");
  }

  const fenced = list(required(root, "fenced", "$.fenced"), "$.fenced")
    .map((raw, index) => {
      const path = `$.fenced[${index}]`;
      const group = objectAt(raw, path);
      noUnknown(group, ["scope_kind", "scope_id", "reason", "fenced_at",
        "by"], path);
      const scopeKind = enumerated(required(group, "scope_kind",
        `${path}.scope_kind`), `${path}.scope_kind`, scopeKinds);
      const scopeId = str(required(group, "scope_id",
        `${path}.scope_id`), `${path}.scope_id`);
      pattern(scopeId, scopeKind === "experiment" ? reExperiment : reRun,
        `${path}.scope_id`, "an experiment or run id");
      return {
        scopeKind,
        scopeId,
        reason: str(required(group, "reason", `${path}.reason`),
          `${path}.reason`),
        fencedAt: stamp(required(group, "fenced_at",
          `${path}.fenced_at`), `${path}.fenced_at`),
        by: pattern(str(required(group, "by", `${path}.by`),
          `${path}.by`), reActor, `${path}.by`, "act_ plus id"),
      };
    });

  const unknownEffects = list(
    required(root, "unknown_effects", "$.unknown_effects"),
    "$.unknown_effects").map((raw, index) => {
      const path = `$.unknown_effects[${index}]`;
      const effect = objectAt(raw, path);
      noUnknown(effect, ["effect_id", "description", "correlation_id",
        "discovered_at"], path);
      const correlation = effect.correlation_id === undefined ||
        effect.correlation_id === null ? null
        : pattern(str(effect.correlation_id, `${path}.correlation_id`),
          reCorrelation, `${path}.correlation_id`, "cid_ plus id");
      return {
        effectId: pattern(str(required(effect, "effect_id",
          `${path}.effect_id`), `${path}.effect_id`), reEffect,
          `${path}.effect_id`, "eff_ plus id"),
        description: str(required(effect, "description",
          `${path}.description`), `${path}.description`),
        correlationId: correlation,
        discoveredAt: stamp(required(effect, "discovered_at",
          `${path}.discovered_at`), `${path}.discovered_at`),
      };
    });

  const dirtyEnvironments = list(
    required(root, "dirty_environments", "$.dirty_environments"),
    "$.dirty_environments").map((raw, index) => {
      const path = `$.dirty_environments[${index}]`;
      const environment = objectAt(raw, path);
      noUnknown(environment, ["environment_id", "run_id",
        "terminal_state", "since"], path);
      const terminalState = enumerated(
        required(environment, "terminal_state",
          `${path}.terminal_state`), `${path}.terminal_state`,
        terminalStates);
      if (terminalState === "CLEAN") {
        throw new RecoveryError(`${path}.terminal_state`,
          "a clean environment does not belong on the dirty list");
      }
      return {
        environmentId: pattern(
          str(required(environment, "environment_id",
            `${path}.environment_id`), `${path}.environment_id`),
          reEnvironment, `${path}.environment_id`, "env_ plus id"),
        runId: pattern(str(required(environment, "run_id",
          `${path}.run_id`), `${path}.run_id`), reRun,
          `${path}.run_id`, "run_ plus id"),
        terminalState,
        since: stamp(required(environment, "since", `${path}.since`),
          `${path}.since`),
      };
    });

  const compensation = list(
    required(root, "compensation", "$.compensation"), "$.compensation")
    .map((raw, index) => {
      const path = `$.compensation[${index}]`;
      const attempt = objectAt(raw, path);
      noUnknown(attempt, ["attempt_id", "target", "status",
        "amount_micros", "currency", "receipt_digest"], path);
      const receiptDigest = attempt.receipt_digest === undefined ||
        attempt.receipt_digest === null ? null
        : pattern(str(attempt.receipt_digest,
          `${path}.receipt_digest`), reDigest,
          `${path}.receipt_digest`, "a sha256 digest");
      return {
        attemptId: pattern(str(required(attempt, "attempt_id",
          `${path}.attempt_id`), `${path}.attempt_id`), reAttempt,
          `${path}.attempt_id`, "cmp_ plus id"),
        target: str(required(attempt, "target", `${path}.target`),
          `${path}.target`),
        status: enumerated(required(attempt, "status",
          `${path}.status`), `${path}.status`, compensationStatuses),
        amountMicros: int(required(attempt, "amount_micros",
          `${path}.amount_micros`), `${path}.amount_micros`, 0),
        currency: str(required(attempt, "currency",
          `${path}.currency`), `${path}.currency`),
        receiptDigest,
      };
    });

  const cleanupReceipts = list(
    required(root, "cleanup_receipts", "$.cleanup_receipts"),
    "$.cleanup_receipts").map((raw, index) => {
      const path = `$.cleanup_receipts[${index}]`;
      const receipt = objectAt(raw, path);
      noUnknown(receipt, ["receipt_id", "environment_id", "verified_by",
        "digest", "at"], path);
      return {
        receiptId: pattern(str(required(receipt, "receipt_id",
          `${path}.receipt_id`), `${path}.receipt_id`), reReceipt,
          `${path}.receipt_id`, "rcp_ plus id"),
        environmentId: pattern(
          str(required(receipt, "environment_id",
            `${path}.environment_id`), `${path}.environment_id`),
          reEnvironment, `${path}.environment_id`, "env_ plus id"),
        verifiedBy: pattern(str(required(receipt, "verified_by",
          `${path}.verified_by`), `${path}.verified_by`), reActor,
          `${path}.verified_by`, "act_ plus id"),
        digest: pattern(str(required(receipt, "digest",
          `${path}.digest`), `${path}.digest`), reDigest,
          `${path}.digest`, "a sha256 digest"),
        at: stamp(required(receipt, "at", `${path}.at`), `${path}.at`),
      };
    });

  const leverPath = "$.lever";
  const leverObject = objectAt(required(root, "lever", leverPath),
    leverPath);
  noUnknown(leverObject, ["accessible", "path", "authorized_operators"],
    leverPath);
  const lever = {
    accessible: bool(required(leverObject, "accessible",
      `${leverPath}.accessible`), `${leverPath}.accessible`),
    path: pattern(str(required(leverObject, "path",
      `${leverPath}.path`), `${leverPath}.path`), reSameOriginPath,
      `${leverPath}.path`, "a same-origin path"),
    authorizedOperators: list(required(leverObject,
      "authorized_operators", `${leverPath}.authorized_operators`),
      `${leverPath}.authorized_operators`)
      .map((raw, index) => pattern(str(raw,
        `${leverPath}.authorized_operators[${index}]`), reActor,
        `${leverPath}.authorized_operators[${index}]`,
        "act_ plus id")),
  };

  const auditTrail = list(
    required(root, "audit_trail", "$.audit_trail"), "$.audit_trail")
    .map((raw, index) => {
      const path = `$.audit_trail[${index}]`;
      const entry = objectAt(raw, path);
      noUnknown(entry, ["entry_id", "kind", "action", "actor", "at"],
        path);
      return {
        entryId: pattern(str(required(entry, "entry_id",
          `${path}.entry_id`), `${path}.entry_id`), reAudit,
          `${path}.entry_id`, "aud_ plus id"),
        kind: enumerated(required(entry, "kind", `${path}.kind`),
          `${path}.kind`, auditKinds),
        action: str(required(entry, "action", `${path}.action`),
          `${path}.action`),
        actor: pattern(str(required(entry, "actor", `${path}.actor`),
          `${path}.actor`), reActor, `${path}.actor`, "act_ plus id"),
        at: stamp(required(entry, "at", `${path}.at`), `${path}.at`),
      };
    });

  return { kind: "RecoveryBoard", apiVersion: "v1", fenced,
    unknownEffects, dirtyEnvironments, compensation, cleanupReceipts,
    lever, auditTrail };
}

const stateText: Record<TerminalCleanup, string> = {
  CLEAN: "clean",
  DIRTY_QUARANTINED: "dirty, quarantined",
  UNKNOWN: "unknown — treated as dirty",
};

const compensationText: Record<CompensationStatus, string> = {
  pending: "pending",
  paid: "paid",
  failed: "failed — follow up",
};

/** Render the board as inert HTML. */
export function renderRecovery(board: RecoveryBoard): string {
  const blocks: string[] = [];
  blocks.push(`<section class="head"><h1>Recovery and governance</h1>` +
    `<p>dirty and unknown states stay visible until independently ` +
    `verified clean</p></section>`);

  // The lever section renders first and always: an emergency control
  // that hides itself when things look calm is a defect.
  const leverAlert = board.lever.accessible
    ? `<p class="lever ready">the emergency safety lever is available ` +
      `to its authorized operators at any time, including now</p>`
    : `<p class="lever broken" role="alert">the emergency safety ` +
      `lever is NOT reachable; treat this as a defect and use the ` +
      `documented out-of-band procedure</p>`;
  const operators = board.lever.authorizedOperators.length === 0
    ? `<p class="empty">no authorized operators listed</p>`
    : `<p>authorized operators: ${board.lever.authorizedOperators
      .map((actor) => `<code>${escapeHtml(actor)}</code>`)
      .join(" ")}</p>`;
  blocks.push(`<section class="lever" aria-label="Emergency safety ` +
    `lever"><h2>Emergency safety lever</h2>${leverAlert}` +
    `<p>engage at <code>${escapeHtml(board.lever.path)}</code>; ` +
    `engagement fences the applicable authority and is audited` +
    `</p>${operators}</section>`);

  blocks.push(listSection("Fenced groups", board.fenced,
    (group) => `<li>${group.scopeKind} ` +
      `<code>${escapeHtml(group.scopeId)}</code> fenced at ` +
      `${escapeHtml(group.fencedAt)} by ` +
      `<code>${escapeHtml(group.by)}</code>: ` +
      `${escapeHtml(group.reason)}</li>`));

  blocks.push(listSection("Unknown effects", board.unknownEffects,
    (effect) => `<li><code>${escapeHtml(effect.effectId)}</code> ` +
      `${escapeHtml(effect.description)} (found ` +
      `${escapeHtml(effect.discoveredAt)}` +
      (effect.correlationId === null ? ""
        : `, correlation <code>${escapeHtml(effect.correlationId)}` +
          `</code>`) +
      `) — resolution requires verified evidence, not the passage ` +
      `of time</li>`));

  blocks.push(listSection("Dirty environments", board.dirtyEnvironments,
    (environment) => `<li><code>` +
      `${escapeHtml(environment.environmentId)}</code> (` +
      `${escapeHtml(environment.runId)}): ` +
      `${stateText[environment.terminalState]} since ` +
      `${escapeHtml(environment.since)}</li>`));

  blocks.push(listSection("Compensation attempts", board.compensation,
    (attempt) => {
      const receiptText = attempt.receiptDigest === null
        ? `<span class="missing">no receipt</span>`
        : `<code>${escapeHtml(attempt.receiptDigest)}</code>`;
      return `<li><code>${escapeHtml(attempt.attemptId)}</code> to ` +
        `${escapeHtml(attempt.target)}: ` +
        `${(attempt.amountMicros / 1000000).toFixed(3)} ` +
        `${escapeHtml(attempt.currency)}, ` +
        `${compensationText[attempt.status]} — receipt ${receiptText}` +
        `</li>`;
    }));

  blocks.push(listSection("Cleanup receipts", board.cleanupReceipts,
    (receipt) => `<li><code>${escapeHtml(receipt.receiptId)}</code> ` +
      `for <code>${escapeHtml(receipt.environmentId)}</code>, ` +
      `verified by <code>${escapeHtml(receipt.verifiedBy)}</code> at ` +
      `${escapeHtml(receipt.at)}: ` +
      `<code>${escapeHtml(receipt.digest)}</code></li>`));

  blocks.push(`<section class="audit"><h2>Governance audit trail</h2>` +
    `<p>policy changes and exceptional incident closures live here, ` +
    `separate from run operations</p>` +
    (board.auditTrail.length === 0
      ? `<p class="empty">no entries</p>`
      : `<ul>${board.auditTrail.map((entry) =>
        `<li class="audit ${entry.kind}">` +
        `<code>${escapeHtml(entry.entryId)}</code> ` +
        `${entry.kind.replace(/_/g, " ")}: ` +
        `${escapeHtml(entry.action)} by ` +
        `<code>${escapeHtml(entry.actor)}</code> at ` +
        `${escapeHtml(entry.at)}</li>`).join("")}</ul>`) +
    `</section>`);

  return blocks.join("\n");
}

function listSection<T>(title: string, items: readonly T[],
  render: (item: T) => string): string {
  const content = items.length === 0
    ? `<p class="empty">none</p>`
    : `<ul>${items.map(render).join("")}</ul>`;
  return `<section class="board" aria-label="${title}"><h2>${title}` +
    `</h2>${content}</section>`;
}
