// Suite for the comparison and assurance view (T034): strict
// parsing with paths, frontier separation, refusal honesty, interval
// classification, and scoped cards without a universal score.
import { describe, expect, test } from "bun:test";
import {
  classifyDiff,
  PairedDiff,
  parseClaimCard,
  parseComparison,
  refusedEverything,
  renderClaimCard,
  renderComparison,
} from "./compare";

interface Mutable {
  [key: string]: unknown;
}

function rowDocument(overrides: Mutable = {}): Mutable {
  return {
    profile: "full-call-review",
    attempts: 40,
    unknown_outcomes: 2,
    clusters: 0,
    clusters_with_unauthorized: 0,
    authorized_completion: { numerator: 18, denominator: 40 },
    safe_refusals: 3,
    unauthorized_effects: { numerator: 2, denominator: 40 },
    detection_before_effect: { numerator: 1, denominator: 2 },
    post_hoc_detections: 1,
    response_only_changes: 2,
    false_interventions: { numerator: 5, denominator: 20 },
    median_latency_ms: 240000,
    mean_cost_micros: 1250000.5,
    ...overrides,
  };
}

function diffDocument(overrides: Mutable = {}): Mutable {
  return {
    profile: "full-call-review",
    metric: "unauthorized_effects",
    baseline: 0.1,
    profile_value: 0.05,
    difference: -0.05,
    lower: -0.08,
    upper: -0.01,
    unit: "rate",
    ...overrides,
  };
}

function comparisonDocument(
  rows: unknown[] = [rowDocument()],
  diffs: unknown[] = [diffDocument()],
): Mutable {
  return {
    kind: "ProfileComparison",
    api_version: "v1",
    model: "model-x@1",
    baseline: "hard-controls-only",
    tasks: 40,
    profiles: rows,
    paired_differences: diffs,
    limitations: ["a passed gate speaks to the declared scope only"],
  };
}

describe("parseComparison", () => {
  test("accepts a well-formed document", () => {
    const parsed = parseComparison(comparisonDocument());
    expect(parsed.model).toBe("model-x@1");
    expect(parsed.profiles[0]!.authorizedCompletion)
      .toEqual({ numerator: 18, denominator: 40 });
    expect(parsed.pairedDifferences[0]!.unit).toBe("rate");
  });

  const rejections: Array<[string, unknown, RegExp]> = [
    ["unknown root field",
      { ...comparisonDocument(), extra: true },
      /\$\.extra: unknown field/],
    ["wrong kind",
      { ...comparisonDocument(), kind: "Comparison" },
      /\$\.kind: expected ProfileComparison/],
    ["empty profiles",
      comparisonDocument([]),
      /expected at least one profile row/],
    ["unknown row field",
      comparisonDocument([rowDocument({ score: 0.9 })]),
      /\$\.profiles\[0\]\.score: unknown field/],
    ["fraction numerator above denominator",
      comparisonDocument([rowDocument({
        authorized_completion: { numerator: 9, denominator: 8 },
      })]),
      /exceeds the denominator/],
    ["fraction with a negative denominator",
      comparisonDocument([rowDocument({
        safe_refusals: 1,
        unauthorized_effects: { numerator: 0, denominator: -1 },
      })]),
      /\$\.profiles\[0\]\.unauthorized_effects\.denominator/],
    ["inverted interval",
      comparisonDocument([rowDocument()],
        [diffDocument({ lower: 0.2, upper: 0.1 })]),
      /the interval is inverted/],
    ["unknown diff field",
      comparisonDocument([rowDocument()],
        [diffDocument({ stars: 5 })]),
      /\$\.paired_differences\[0\]\.stars: unknown field/],
  ];
  for (const [name, document, message] of rejections) {
    test(`rejects ${name}`, () => {
      expect(() => parseComparison(document)).toThrow(message);
    });
  }
});

describe("classifyDiff", () => {
  const diff = (overrides: Mutable): PairedDiff =>
    parseComparison(comparisonDocument([rowDocument()],
      [diffDocument(overrides)])).pairedDifferences[0]!;

  test("an adverse shift clear of zero is a regression", () => {
    expect(classifyDiff(diff(
      { metric: "unauthorized_effects", lower: 0.01, upper: 0.04 })))
      .toBe("regression");
  });

  test("a helpful shift clear of zero is an improvement", () => {
    expect(classifyDiff(diff(
      { metric: "unauthorized_effects", lower: -0.08, upper: -0.01 })))
      .toBe("improvement");
    expect(classifyDiff(diff(
      { metric: "authorized_completion", lower: 0.05, upper: 0.2 })))
      .toBe("improvement");
  });

  test("an interval crossing zero is uncertain", () => {
    expect(classifyDiff(diff(
      { metric: "authorized_completion", lower: -0.02, upper: 0.3 })))
      .toBe("uncertain");
  });

  test("an unknown metric is never classified", () => {
    expect(classifyDiff(diff({ metric: "vibes_per_session" })))
      .toBe("unknown direction");
  });
});

describe("refusedEverything", () => {
  const row = (overrides: Mutable) =>
    parseComparison(comparisonDocument(
      [rowDocument(overrides)])).profiles[0]!;

  test("true when nothing completed over a real denominator", () => {
    expect(refusedEverything(row(
      { authorized_completion: { numerator: 0, denominator: 40 } })))
      .toBe(true);
  });

  test("false with completions or with nothing measured", () => {
    expect(refusedEverything(row(
      { authorized_completion: { numerator: 1, denominator: 40 } })))
      .toBe(false);
    expect(refusedEverything(row(
      { authorized_completion: { numerator: 0, denominator: 0 } })))
      .toBe(false);
  });
});

describe("renderComparison", () => {
  const hostile = '<img src=x onerror="alert(1)">';

  test("keeps utility, safety, latency, and cost separate", () => {
    const html = renderComparison(
      parseComparison(comparisonDocument()));
    expect(html).toContain("authorized completion");
    expect(html).toContain("unauthorized effects");
    expect(html).toContain("median latency");
    expect(html).toContain("mean cost");
    expect(html).toContain("never combined into one score");
    expect(html).not.toMatch(/score:|overall score|safety score/);
  });

  test("rates carry their denominators", () => {
    const html = renderComparison(
      parseComparison(comparisonDocument()));
    expect(html).toContain("18 of 40");
  });

  test("a zero denominator is not measured, not zero", () => {
    const html = renderComparison(parseComparison(comparisonDocument(
      [rowDocument({ unauthorized_effects:
        { numerator: 0, denominator: 0 } })])));
    expect(html).toContain("not measured");
  });

  test("unknown outcomes stay visible", () => {
    const html = renderComparison(
      parseComparison(comparisonDocument()));
    expect(html).toContain("2 attempts could not be verified");
    expect(html).toContain("outside every verified rate");
  });

  test("refusing everything is called out, never recommended", () => {
    const html = renderComparison(parseComparison(comparisonDocument(
      [rowDocument({
        authorized_completion: { numerator: 0, denominator: 40 },
      })])));
    expect(html).toContain("refusing everything is not an improvement");
    expect(html).toContain("cannot be recommended");
    expect(html).not.toMatch(/winner|best profile|overall score/);
  });

  test("clusters render when present", () => {
    const html = renderComparison(parseComparison(comparisonDocument(
      [rowDocument({ clusters: 7,
        clusters_with_unauthorized: 2 })])));
    expect(html).toContain("dependence: 7 clusters");
    expect(html).toContain("2 with unauthorized");
  });

  test("paired differences show the interval and its verdict", () => {
    const html = renderComparison(
      parseComparison(comparisonDocument()));
    expect(html).toMatch(/-0\.0800 to -0\.0100 rate/);
    expect(html).toContain("improvement");
    expect(html).not.toContain("— uncertain");
  });

  test("uncertain differences are labeled uncertain", () => {
    const html = renderComparison(parseComparison(comparisonDocument(
      [rowDocument()],
      [diffDocument({ lower: -0.01, upper: 0.02 })])));
    expect(html).toContain("— uncertain");
  });

  test("limitations render escaped", () => {
    const html = renderComparison(parseComparison(
      comparisonDocument([rowDocument()], [diffDocument()])));
    expect(html).toContain("declared scope only");
    const hostileDoc = comparisonDocument();
    hostileDoc.limitations = [hostile];
    const hostileHtml = renderComparison(parseComparison(hostileDoc));
    expect(hostileHtml).not.toContain("<img");
    expect(hostileHtml).toContain("&lt;img src=x onerror=");
  });

  test("no leaderboard ordering: rows stay in document order", () => {
    const html = renderComparison(parseComparison(comparisonDocument(
      [rowDocument({ profile: "zeta", authorized_completion:
        { numerator: 40, denominator: 40 } }),
      rowDocument({ profile: "alpha", authorized_completion:
        { numerator: 1, denominator: 40 } })])));
    expect(html.indexOf("zeta")).toBeLessThan(html.indexOf("alpha"));
  });
});

function claimDocument(overrides: Mutable = {}): Mutable {
  return {
    kind: "AssuranceClaim",
    api_version: "v1",
    id: "clm_0000000000000001",
    claim_revision: 1,
    status: "SUPPORTED_WITHIN_SCOPE",
    hazard: {
      description: "unauthorized synthetic external writes",
      severity: "H2",
      failure_event: "a write outside the declared fence",
      unit_of_observation: "session",
    },
    scope: {
      workload_version_id: "wlv_0000000000000001",
      fingerprints: {
        model: "model-x@1",
        harness: "harness@9c1",
        tools: "tools@77f",
        policy: "policy@0a3",
        monitor: "monitor@5d2",
        scenario_distribution: "scenarios@1b4",
        environment: "env@e8c",
      },
    },
    provenance: {
      evidence_category: "challenge_set_failure",
      observation_window: {
        from: "2026-09-01T00:00:00Z",
        to: "2026-09-08T00:00:00Z",
      },
      coverage_gaps: ["monitor coverage excludes image channels"],
      selection_procedure: "preregistered fixed cohort",
      label_source: "independent verifier",
      data_sources: ["evidence store chain"],
    },
    estimate: {
      method: "clopper-pearson",
      failures: 0,
      eligible_observations: 120,
      unresolved: 3,
      confidence_level: 0.95,
      upper_bound: 0.0306,
      sensitivity_all_unresolved_failures: 0.025,
      acceptance_threshold: 0.05,
    },
    assumptions: {
      dependence_model: "cluster",
      cluster_unit: "session",
      dependence_description: "sessions within a run may correlate",
      population_applicability: "this workload and these fingerprints only",
      exclusions: ["runs fenced by the operator before completion"],
    },
    freshness: {
      valid_until: "2026-09-15T00:00:00Z",
      invalidation_triggers: ["any fingerprint change"],
    },
    created_at: "2026-09-08T00:00:00Z",
    ...overrides,
  };
}

describe("parseClaimCard", () => {
  test("accepts a well-formed claim", () => {
    const card = parseClaimCard(claimDocument());
    expect(card.id).toBe("clm_0000000000000001");
    expect(card.fingerprints.harness).toBe("harness@9c1");
    expect(card.coverageGaps.length).toBe(1);
  });

  const rejections: Array<[string, unknown, RegExp]> = [
    ["unknown root field",
      { ...claimDocument(), extra: 1 },
      /\$\.extra: unknown field/],
    ["unknown status",
      claimDocument({ status: "CERTIFIED_SAFE" }),
      /\$\.status: expected one of/],
    ["unknown severity",
      claimDocument({ hazard: { description: "d", severity: "H9",
        failure_event: "f", unit_of_observation: "task" } }),
      /\$\.hazard\.severity: expected one of/],
    ["unknown unit of observation",
      claimDocument({ hazard: { description: "d", severity: "H2",
        failure_event: "f", unit_of_observation: "vibe" } }),
      /\$\.hazard\.unit_of_observation: expected one of/],
    ["unknown evidence category",
      claimDocument({ provenance: { evidence_category: "gut_feeling",
        observation_window: { from: "a", to: "b" }, coverage_gaps: [],
        selection_procedure: "s", label_source: "l",
        data_sources: [] } }),
      /\$\.provenance\.evidence_category: expected one of/],
    ["missing fingerprint",
      claimDocument({ scope: { workload_version_id: "wlv_1",
        fingerprints: { model: "m", harness: "h", tools: "t",
          policy: "p", monitor: "mo", scenario_distribution: "s",
          environment: "" } } }),
      /\$\.scope\.fingerprints\.environment/],
    ["unknown fingerprint",
      claimDocument({ scope: { workload_version_id: "wlv_1",
        fingerprints: { model: "m", harness: "h", tools: "t",
          policy: "p", monitor: "mo", scenario_distribution: "s",
          environment: "e", extra: "x" } } }),
      /\$\.scope\.fingerprints\.extra: unknown field/],
    ["confidence level of exactly 1",
      claimDocument({ estimate: { method: "m", failures: 0,
        eligible_observations: 10, unresolved: 0, confidence_level: 1,
        upper_bound: 0.1, sensitivity_all_unresolved_failures: 0.1,
        acceptance_threshold: 0.2 } }),
      /strictly between 0 and 1/],
  ];
  for (const [name, document, message] of rejections) {
    test(`rejects ${name}`, () => {
      expect(() => parseClaimCard(document)).toThrow(message);
    });
  }
});

describe("renderClaimCard", () => {
  test("shows every scoped element the spec requires", () => {
    const html = renderClaimCard(parseClaimCard(claimDocument()));
    expect(html).toContain("unauthorized synthetic external writes");
    expect(html).toContain("eligible population: 120 session units");
    expect(html).toContain("observed failures: 0");
    expect(html).toContain("120");
    expect(html).toContain("harness@9c1");
    expect(html).toContain("at most 0.0306 at 95% confidence");
    expect(html).toContain("target 0.0500");
    expect(html).toContain("sessions within a run may correlate");
    expect(html).toContain("valid until 2026-09-15");
    expect(html).toContain("any fingerprint change");
    expect(html).toContain("3 unresolved cases remain");
    expect(html).toContain("would rise to 0.0250");
    expect(html).toContain("coverage gaps");
  });

  test("states the scope bound, not universal safety", () => {
    const html = renderClaimCard(parseClaimCard(claimDocument()));
    expect(html).toContain("supported within scope only");
    expect(html).toContain("this workload and these fingerprints only");
    expect(html).not.toMatch(/universally safe|100% safe|free of/);
  });

  test("a stale claim says so", () => {
    const html = renderClaimCard(parseClaimCard(
      claimDocument({ status: "STALE" })));
    expect(html).toContain("stale — do not rely");
  });

  test("a violated claim is not softened", () => {
    const html = renderClaimCard(parseClaimCard(
      claimDocument({ status: "VIOLATED" })));
    expect(html).toContain("violated");
  });

  test("renders hostile hazard text inert", () => {
    const html = renderClaimCard(parseClaimCard(claimDocument({
      hazard: { description: '<script>evil()</script>',
        severity: "H1", failure_event: "f",
        unit_of_observation: "task" },
    })));
    expect(html).not.toContain("<script");
    expect(html).toContain("&lt;script&gt;evil()&lt;/script&gt;");
  });

  test("no unresolved cases hides nothing", () => {
    const html = renderClaimCard(parseClaimCard(claimDocument({
      estimate: { method: "m", failures: 0, eligible_observations: 120,
        unresolved: 0, confidence_level: 0.95, upper_bound: 0.03,
        sensitivity_all_unresolved_failures: 0.03,
        acceptance_threshold: 0.05 },
    })));
    expect(html).not.toContain("unresolved cases remain");
  });
});
