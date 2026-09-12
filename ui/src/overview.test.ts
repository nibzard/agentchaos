// Tests for the workload overview (spec 17.1, T031): strict parsing,
// inert rendering, test/production separation, and gap prominence.
import { describe, expect, test } from "bun:test";
import {
  escapeHtml, parseOverview, ParseError, renderOverview, sortForDisplay,
  type WorkloadEntry,
} from "./overview";

function entryDocument(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    workload_version_id: "wlv_0a1b2c3d4e5f6071",
    environment: "synthetic",
    modes: ["isolated"],
    autonomy_profile: "profile-baseline",
    coverage_gaps: [],
    throughput: { authorized_completions: 8, eligible_tasks: 10,
      window_hours: 24 },
    recent_failures: [],
    freshness: { status: "fresh" },
    cost: { currency: "USD", total_micros: 1000 },
    ...overrides,
  };
}

function snapshotDocument(
  workloads: Record<string, unknown>[],
): unknown {
  return {
    kind: "WorkloadOverview",
    api_version: "v1",
    generated_at: "2026-09-12T00:00:00Z",
    workloads,
  };
}

describe("parseOverview", () => {
  test("accepts a well-formed document", () => {
    const snapshot =
      parseOverview(snapshotDocument([entryDocument()]));
    expect(snapshot.workloads.length).toBe(1);
    expect(snapshot.workloads[0]!.workloadVersionId)
      .toBe("wlv_0a1b2c3d4e5f6071");
    expect(snapshot.apiVersion).toBe("v1");
  });

  test("rejects an unknown top-level field", () => {
    const document = snapshotDocument([entryDocument()]) as Record<string, unknown>;
    document.safety_score = 99.99;
    expect(() => parseOverview(document))
      .toThrow(/safety_score: unknown field/);
  });

  test("rejects an unknown nested field", () => {
    expect(() => parseOverview(snapshotDocument(
      [entryDocument({ vibes: true })],
    ))).toThrow(/workloads\[0\].vibes.*unknown field/);
  });

  test("rejects an unknown environment", () => {
    expect(() => parseOverview(snapshotDocument(
      [entryDocument({ environment: "staging" })],
    ))).toThrow(/environment.*synthetic, production/);
  });

  test("rejects a malformed workload id", () => {
    expect(() => parseOverview(snapshotDocument(
      [entryDocument({ workload_version_id: "workload-7" })],
    ))).toThrow(/wlv_/);
  });

  test("rejects an unknown severity", () => {
    expect(() => parseOverview(snapshotDocument(
      [entryDocument({ coverage_gaps: [{ path: "p", severity: "urgent" }] })],
    ))).toThrow(/severity/);
  });

  test("rejects negative throughput", () => {
    expect(() => parseOverview(snapshotDocument(
      [entryDocument({
        throughput: { authorized_completions: -1, eligible_tasks: 10,
          window_hours: 1 },
      })],
    ))).toThrow(/authorized_completions/);
  });

  test("rejects zero eligible tasks", () => {
    // A rate over zero eligible tasks is undefined; the parser
    // refuses instead of letting the UI invent one.
    expect(() => parseOverview(snapshotDocument(
      [entryDocument({
        throughput: { authorized_completions: 0, eligible_tasks: 0,
          window_hours: 1 },
      })],
    ))).toThrow(/eligible_tasks/);
  });

  test("rejects an unknown freshness status", () => {
    expect(() => parseOverview(snapshotDocument(
      [entryDocument({ freshness: { status: "fine" } })],
    ))).toThrow(/fresh.*stale/);
  });

  test("rejects a malformed failure run id", () => {
    expect(() => parseOverview(snapshotDocument(
      [entryDocument({
        recent_failures: [{ run_id: "run-9", label: "l", at: "t" }],
      })],
    ))).toThrow(/run_/);
  });

  test("rejects a wrong kind", () => {
    expect(() => parseOverview({
      kind: "Dashboard", api_version: "v1", generated_at: "x",
      workloads: [],
    })).toThrow(/WorkloadOverview/);
  });

  test("errors carry the field path", () => {
    try {
      parseOverview(snapshotDocument([entryDocument({ modes: [] })]));
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(ParseError);
      expect((error as ParseError).path)
        .toBe("$.workloads[0].modes");
    }
  });
});

describe("renderOverview", () => {
  test("renders every spec 17.1 fact", () => {
    const snapshot = parseOverview(snapshotDocument([entryDocument({
      modes: ["isolated", "mediated"],
      autonomy_profile: "profile-full-review",
      coverage_gaps: [{ path: "external write unmediated",
        severity: "high", detail: "no sink" }],
      throughput: { authorized_completions: 84, eligible_tasks: 120,
        window_hours: 24 },
      recent_failures: [{ run_id: "run_0a1b2c3d4e5f6071",
        label: "unauthorized write", at: "2026-09-11T18:40:00Z" }],
      freshness: { status: "stale", stale_reason: "policy changed" },
      cost: { currency: "EUR", total_micros: 2500000 },
    })]));
    const html = renderOverview(snapshot);
    expect(html).toContain("wlv_0a1b2c3d4e5f6071");
    expect(html).toContain("isolated, mediated");
    expect(html).toContain("profile-full-review");
    expect(html).toContain("Coverage gaps (1)");
    expect(html).toContain("external write unmediated");
    expect(html).toContain("useful throughput 84 authorized completions");
    expect(html).toContain("unauthorized write");
    expect(html).toContain("evidence stale");
    expect(html).toContain("policy changed");
    expect(html).toContain("2.500 EUR");
  });

  test("renders hostile content as inert text", () => {
    const snapshot = parseOverview(snapshotDocument([entryDocument({
      autonomy_profile: `<script>alert("profile")</script>`,
      recent_failures: [{
        run_id: "run_0a1b2c3d4e5f6071",
        label: `<img src=x onerror="alert(1)">`,
        at: "2026-09-11T00:00:00Z",
      }],
      coverage_gaps: [{ path: `"><script>mark()</script>`,
        severity: "high" }],
    })]));
    const html = renderOverview(snapshot);
    expect(html).not.toContain("<script>");
    // No hostile element ever becomes markup; it renders as text.
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<script");
    expect(html).toContain("&lt;script&gt;");
    expect(html).toContain("&lt;img src=x onerror=");
  });

  test("keeps test and production results in separate sections",
    () => {
      const snapshot = parseOverview(snapshotDocument([
        entryDocument(),
        entryDocument({
          workload_version_id: "wlv_99aabbccddeeff00",
          environment: "production",
        }),
      ]));
      const html = renderOverview(snapshot);
      expect(html).toContain("Test workloads (synthetic identities)");
      expect(html).toContain("Production workloads");
      const syntheticSection =
        html.match(/data-environment="synthetic"[\s\S]*?<\/section>/)![0];
      expect(syntheticSection).toContain("wlv_0a1b2c3d4e5f6071");
      expect(syntheticSection).not.toContain("wlv_99aabbccddeeff00");
      const productionSection =
        html.match(/data-environment="production"[\s\S]*?<\/section>/)![0];
      expect(productionSection).toContain("wlv_99aabbccddeeff00");
    });

  test("states none enrolled rather than hiding an environment", () => {
    const html = renderOverview(
      parseOverview(snapshotDocument([entryDocument()])));
    expect(html).toMatch(
      /data-environment="production"[\s\S]*?none enrolled/);
  });

  test("never renders a safety-percentage badge", () => {
    const snapshot = parseOverview(snapshotDocument([entryDocument({
      coverage_gaps: [],
      throughput: { authorized_completions: 120, eligible_tasks: 120,
        window_hours: 24 },
    })]));
    const html = renderOverview(snapshot);
    expect(html).not.toMatch(/free of (malicious|hazard|error)/i);
    expect(html).not.toMatch(/99\.9/);
    // The honest statement is the useful-throughput line.
    expect(html).toContain("useful throughput 120 authorized completions");
  });

  test("unknown freshness is visibly not fresh", () => {
    const html = renderOverview(parseOverview(
      snapshotDocument([entryDocument({
        freshness: { status: "unknown" },
      })])));
    expect(html).toContain("evidence unknown");
  });
});

describe("sortForDisplay", () => {
  const clean: WorkloadEntry = {
    workloadVersionId: "wlv_0000000000000001",
    environment: "synthetic",
    modes: ["isolated"],
    autonomyProfile: "p",
    coverageGaps: [],
    throughput: { authorizedCompletions: 100, eligibleTasks: 100,
      windowHours: 1 },
    recentFailures: [],
    freshness: { status: "fresh" },
    cost: { currency: "USD", totalMicros: 1 },
  };
  const lowGap: WorkloadEntry = { ...clean,
    workloadVersionId: "wlv_0000000000000002",
    coverageGaps: [{ path: "minor", severity: "low" }] };
  const highGap: WorkloadEntry = { ...clean,
    workloadVersionId: "wlv_0000000000000003",
    coverageGaps: [{ path: "external write unmediated",
      severity: "high" }] };
  const failing: WorkloadEntry = { ...clean,
    workloadVersionId: "wlv_0000000000000004",
    recentFailures: [{ runId: "run_0a1b2c3d4e5f6071", label: "l",
      at: "t" }] };

  test("a missing enforcement path outranks every score", () => {
    const ordered = sortForDisplay([clean, lowGap, highGap]);
    expect(ordered.map((entry) => entry.workloadVersionId))
      .toEqual(["wlv_0000000000000003", "wlv_0000000000000002",
        "wlv_0000000000000001"]);
  });

  test("a high score never hides a gap from the top", () => {
    // The clean workload completes everything; the gapped workload
    // still sorts first.
    const perfect = { ...clean, throughput: {
      authorizedCompletions: 1000, eligibleTasks: 1000,
      windowHours: 1 } };
    const ordered = sortForDisplay([perfect, highGap]);
    expect(ordered[0]!.workloadVersionId).toBe("wlv_0000000000000003");
  });

  test("failures sort between gaps and clean rows", () => {
    const ordered = sortForDisplay([clean, failing, lowGap]);
    expect(ordered.map((entry) => entry.workloadVersionId))
      .toEqual(["wlv_0000000000000002", "wlv_0000000000000004",
        "wlv_0000000000000001"]);
  });

  test("ties fall back to a stable id order", () => {
    const ordered = sortForDisplay([clean,
      { ...clean, workloadVersionId: "wlv_0000000000000000" }]);
    expect(ordered.map((entry) => entry.workloadVersionId))
      .toEqual(["wlv_0000000000000000", "wlv_0000000000000001"]);
  });
});

describe("escapeHtml", () => {
  test("escapes every HTML-significant character", () => {
    expect(escapeHtml(`a & <b> "c" 'd'`))
      .toBe("a &amp; &lt;b&gt; &quot;c&quot; &#39;d&#39;");
  });
});
