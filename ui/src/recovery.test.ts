// Suite for the recovery and governance view (T035): strict parsing
// with paths, the always-visible emergency lever, dirty and unknown
// states that stay visible, separate governance audit trail, and the
// absence of any human approval inbox.
import { describe, expect, test } from "bun:test";
import { parseRecovery, renderRecovery } from "./recovery";

interface Mutable {
  [key: string]: unknown;
}

function boardDocument(overrides: Mutable = {}): Mutable {
  return {
    kind: "RecoveryBoard",
    api_version: "v1",
    fenced: [{
      scope_kind: "experiment",
      scope_id: "exp_isoreexec0001",
      reason: "unauthorized write attempt",
      fenced_at: "2026-09-12T00:10:00Z",
      by: "act_operator-ona01",
    }],
    unknown_effects: [{
      effect_id: "eff_pending000001",
      description: "a dispatched write with no receipt",
      correlation_id: "cid_effect0001",
      discovered_at: "2026-09-12T00:11:00Z",
    }],
    dirty_environments: [{
      environment_id: "env_sandbox00000001",
      run_id: "run_isoreexec0001",
      terminal_state: "DIRTY_QUARANTINED",
      since: "2026-09-12T00:12:00Z",
    }],
    compensation: [{
      attempt_id: "cmp_refund00000001",
      target: "tenant:retail-partner",
      status: "pending",
      amount_micros: 2500000,
      currency: "USD",
      receipt_digest: null,
    }],
    cleanup_receipts: [{
      receipt_id: "rcp_cleanup0000001",
      environment_id: "env_sandbox00000001",
      verified_by: "act_verifier-ext01",
      digest: "sha256:" + "ab".repeat(32),
      at: "2026-09-12T01:00:00Z",
    }],
    lever: {
      accessible: true,
      path: "/v1/safety-levers/tenant/engage",
      authorized_operators: ["act_operator-ona01"],
    },
    audit_trail: [{
      entry_id: "aud_policy000000001",
      kind: "policy_change",
      action: "tightened the external-write allowlist",
      actor: "act_operator-ona01",
      at: "2026-09-11T00:00:00Z",
    }],
    ...overrides,
  };
}

describe("parseRecovery", () => {
  test("accepts a well-formed board", () => {
    const board = parseRecovery(boardDocument());
    expect(board.fenced[0]!.scopeId).toBe("exp_isoreexec0001");
    expect(board.lever.authorizedOperators)
      .toEqual(["act_operator-ona01"]);
    expect(board.auditTrail[0]!.kind).toBe("policy_change");
  });

  test("tenant scope takes a run id", () => {
    const board = parseRecovery(boardDocument({
      fenced: [{ scope_kind: "tenant", scope_id: "run_isoreexec0001",
        reason: "r", fenced_at: "2026-09-12T00:00:00Z",
        by: "act_operator-ona01" }],
    }));
    expect(board.fenced[0]!.scopeKind).toBe("tenant");
  });

  const rejections: Array<[string, unknown, RegExp]> = [
    ["unknown root field",
      { ...boardDocument(), extra: 1 },
      /\$\.extra: unknown field/],
    ["wrong kind",
      boardDocument({ kind: "Board" }),
      /\$\.kind: expected RecoveryBoard/],
    ["unknown fenced field",
      boardDocument({ fenced: [{ scope_kind: "experiment",
        scope_id: "exp_isoreexec0001", reason: "r",
        fenced_at: "2026-09-12T00:00:00Z",
        by: "act_operator-ona01", extra: 1 }] }),
      /\$\.fenced\[0\]\.extra: unknown field/],
    ["fenced experiment with a run id",
      boardDocument({ fenced: [{ scope_kind: "experiment",
        scope_id: "run_isoreexec0001", reason: "r",
        fenced_at: "2026-09-12T00:00:00Z",
        by: "act_operator-ona01" }] }),
      /\$\.fenced\[0\]\.scope_id/],
    ["bad actor id",
      boardDocument({ fenced: [{ scope_kind: "experiment",
        scope_id: "exp_isoreexec0001", reason: "r",
        fenced_at: "2026-09-12T00:00:00Z", by: "root" }] }),
      /\$\.fenced\[0\]\.by: expected act_ plus id/],
    ["naive timestamp",
      boardDocument({ unknown_effects: [{ effect_id: "eff_x000000000001",
        description: "d", correlation_id: null,
        discovered_at: "this morning" }] }),
      /\$\.unknown_effects\[0\]\.discovered_at: expected a UTC timestamp/],
    ["bad correlation id",
      boardDocument({ unknown_effects: [{ effect_id: "eff_x000000000001",
        description: "d", correlation_id: "nope",
        discovered_at: "2026-09-12T00:00:00Z" }] }),
      /\$\.unknown_effects\[0\]\.correlation_id: expected cid_ plus id/],
    ["a clean environment on the dirty list",
      boardDocument({ dirty_environments: [{
        environment_id: "env_sandbox00000001",
        run_id: "run_isoreexec0001", terminal_state: "CLEAN",
        since: "2026-09-12T00:00:00Z" }] }),
      /does not belong on the dirty list/],
    ["unknown terminal state",
      boardDocument({ dirty_environments: [{
        environment_id: "env_sandbox00000001",
        run_id: "run_isoreexec0001", terminal_state: "SPARKLY",
        since: "2026-09-12T00:00:00Z" }] }),
      /\$\.dirty_environments\[0\]\.terminal_state: expected one of/],
    ["negative compensation",
      boardDocument({ compensation: [{ attempt_id: "cmp_refund00000001",
        target: "t", status: "pending", amount_micros: -1,
        currency: "USD", receipt_digest: null }] }),
      /\$\.compensation\[0\]\.amount_micros/],
    ["bad receipt digest",
      boardDocument({ compensation: [{ attempt_id: "cmp_refund00000001",
        target: "t", status: "paid", amount_micros: 1,
        currency: "USD", receipt_digest: "trust me" }] }),
      /\$\.compensation\[0\]\.receipt_digest: expected a sha256 digest/],
    ["lever with an off-site path",
      boardDocument({ lever: { accessible: true,
        path: "https://evil.example/lever",
        authorized_operators: [] } }),
      /\$\.lever\.path: expected a same-origin path/],
    ["lever with a script path",
      boardDocument({ lever: { accessible: true,
        path: "/v1/safety-levers/engage?next=javascript:1",
        authorized_operators: [] } }),
      /\$\.lever\.path: expected a same-origin path/],
    ["unknown audit kind",
      boardDocument({ audit_trail: [{ entry_id: "aud_policy000000001",
        kind: "routine_approval", action: "a",
        actor: "act_operator-ona01", at: "2026-09-12T00:00:00Z" }] }),
      /\$\.audit_trail\[0\]\.kind: expected one of/],
  ];
  for (const [name, document, message] of rejections) {
    test(`rejects ${name}`, () => {
      expect(() => parseRecovery(document)).toThrow(message);
    });
  }
});

describe("renderRecovery", () => {
  test("shows every recovery surface", () => {
    const html = renderRecovery(parseRecovery(boardDocument()));
    expect(html).toContain("Fenced groups");
    expect(html).toContain("Unknown effects");
    expect(html).toContain("Dirty environments");
    expect(html).toContain("Compensation attempts");
    expect(html).toContain("Cleanup receipts");
    expect(html).toContain("Governance audit trail");
  });

  test("the emergency lever is always visible, ready or not", () => {
    const ready = renderRecovery(parseRecovery(boardDocument()));
    expect(ready).toContain("Emergency safety lever");
    expect(ready).toContain(
      "available to its authorized operators at any time");
    const broken = renderRecovery(parseRecovery(boardDocument({
      lever: { accessible: false, path: "/v1/safety-levers/engage",
        authorized_operators: [] },
    })));
    expect(broken).toContain("Emergency safety lever");
    expect(broken).toContain("NOT reachable");
    expect(broken).toContain("no authorized operators listed");
  });

  test("an empty board still renders the lever", () => {
    const html = renderRecovery(parseRecovery(boardDocument({
      fenced: [], unknown_effects: [], dirty_environments: [],
      compensation: [], cleanup_receipts: [], audit_trail: [],
    })));
    expect(html).toContain("Emergency safety lever");
    expect((html.match(/class="empty">none</g) ?? []).length)
      .toBe(5);
  });

  test("dirty and unknown states stay visible with their meaning",
    () => {
      const html = renderRecovery(parseRecovery(boardDocument({
        dirty_environments: [
          { environment_id: "env_sandbox00000001",
            run_id: "run_isoreexec0001",
            terminal_state: "DIRTY_QUARANTINED",
            since: "2026-09-12T00:00:00Z" },
          { environment_id: "env_sandbox00000002",
            run_id: "run_isoreexec0002", terminal_state: "UNKNOWN",
            since: "2026-09-12T00:00:00Z" },
        ],
      })));
      expect(html).toContain("dirty, quarantined");
      expect(html).toContain("unknown — treated as dirty");
    });

  test("a compensation attempt without a receipt says so", () => {
    const html = renderRecovery(parseRecovery(boardDocument()));
    expect(html).toContain("cmp_refund00000001");
    expect(html).toContain("no receipt");
    expect(html).toContain("pending");
  });

  test("a failed compensation attempt calls for follow-up", () => {
    const html = renderRecovery(parseRecovery(boardDocument({
      compensation: [{ attempt_id: "cmp_refund00000001", target: "t",
        status: "failed", amount_micros: 1, currency: "USD",
        receipt_digest: null }],
    })));
    expect(html).toContain("failed — follow up");
  });

  test("the audit trail stays separate from run operations", () => {
    const html = renderRecovery(parseRecovery(boardDocument()));
    expect(html).toContain(
      "policy change: tightened the external-write allowlist");
    expect(html).toContain("separate from run operations");
  });

  test("an exceptional closure renders with its own label", () => {
    const html = renderRecovery(parseRecovery(boardDocument({
      audit_trail: [{ entry_id: "aud_closure0000001",
        kind: "exceptional_closure",
        action: "closed an incident without a cleanup receipt",
        actor: "act_operator-ona01", at: "2026-09-12T00:00:00Z" }],
    })));
    expect(html).toContain("exceptional closure");
  });

  test("no human approval inbox exists anywhere", () => {
    const html = renderRecovery(parseRecovery(boardDocument()));
    expect(html).not.toMatch(/approval|approve|inbox|awaiting human/);
  });

  test("renders hostile reasons inert", () => {
    const hostile = '<script>x()</script>"><img src=x onerror=1>';
    const html = renderRecovery(parseRecovery(boardDocument({
      fenced: [{ scope_kind: "experiment", scope_id: "exp_000000000000001",
        reason: hostile, fenced_at: "2026-09-12T00:00:00Z",
        by: "act_operator-ona01" }],
    })));
    expect(html).not.toContain("<script");
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;script&gt;");
  });
});
