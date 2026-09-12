// Tests for the experiment builder (spec 17.2, T032): strict catalog
// parsing, blockers that explain instead of overriding, defaults with
// synthetic identities and an isolated mode, a manifest draft valid
// by construction, and scheduling only after a compiled preview.
import { describe, expect, test } from "bun:test";
import {
  blockers, BuilderError, canSchedule, newBuilderState, parseCatalog,
  renderBuilder, selectWorkload, setBudgets, setMode, setProfiles,
  toManifest, toggleScenario, toggleTarget, withPlanDigest,
  type BuilderCatalog, type BuilderState,
} from "./builder";

const catalogDocument = {
  kind: "BuilderCatalog",
  api_version: "v1",
  workloads: [
    {
      workload_version_id: "wlv_repomaintenance01",
      modes: ["isolated_reexecution", "observe"],
      enrolled_targets: ["tgt_repcheckout000001", "tgt_reposandbox0002"],
    },
    {
      workload_version_id: "wlv_triagetooling0002",
      modes: ["observe"],
      enrolled_targets: [],
    },
    {
      workload_version_id: "wlv_canarycandidate3",
      modes: ["customer_canary"],
      enrolled_targets: ["tgt_canaryenv0000001"],
    },
  ],
  scenarios: [
    {
      scenario_version_id: "scn_impossibletask01",
      modes: ["isolated_reexecution", "observe"],
    },
    {
      scenario_version_id: "scn_benignbaseline01",
      modes: ["observe"],
    },
    {
      scenario_version_id: "scn_canaryprobe00001",
      modes: ["customer_canary"],
    },
  ],
  profiles: [
    { profile_id: "aup_baselinehard0001", description: "hard controls only" },
    { profile_id: "aup_fullreview0001", description: "full-call review" },
  ],
};

const catalog: BuilderCatalog = parseCatalog(catalogDocument);

/** A complete, blocker-free selection. */
function completeState(): BuilderState {
  return withPlanDigest(toggleTarget(toggleScenario(setProfiles(
    selectWorkload(newBuilderState(), "wlv_repomaintenance01"),
    "aup_baselinehard0001", "aup_fullreview0001"),
    "scn_impossibletask01"), "tgt_repcheckout000001"),
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
}

describe("parseCatalog", () => {
  test("accepts a well-formed catalog", () => {
    expect(catalog.workloads.length).toBe(3);
    expect(catalog.profiles[0]!.profileId).toBe("aup_baselinehard0001");
  });

  test("rejects unknown fields at every level", () => {
    const top = { ...catalogDocument, convenience: true };
    expect(() => parseCatalog(top)).toThrow(/convenience: unknown field/);
    const nested = {
      ...catalogDocument,
      workloads: [{ ...catalogDocument.workloads[0]!, hint: "x" }],
    };
    expect(() => parseCatalog(nested))
      .toThrow(/workloads\[0\].hint: unknown field/);
  });

  test("rejects malformed ids and modes", () => {
    const badWorkload = {
      ...catalogDocument,
      workloads: [{ workload_version_id: "workload-1", modes: ["observe"],
        enrolled_targets: [] }],
    };
    expect(() => parseCatalog(badWorkload)).toThrow(/wlv_/);
    const badMode = {
      ...catalogDocument,
      workloads: [{ workload_version_id: "wlv_repomaintenance01",
        modes: ["vibes"], enrolled_targets: [] }],
    };
    expect(() => parseCatalog(badMode)).toThrow(/modes\[0\]/);
    const badKind = { ...catalogDocument, kind: "Catalog" };
    expect(() => parseCatalog(badKind)).toThrow(/BuilderCatalog/);
  });

  test("errors name the field path", () => {
    try {
      parseCatalog({ ...catalogDocument, scenarios: [{}, {}] });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(BuilderError);
      expect((error as BuilderError).path).toBe("$.scenarios[0].scenario_version_id");
    }
  });
});

describe("defaults", () => {
  test("start synthetic and isolated with mandatory recording",
    () => {
      const state = newBuilderState();
      expect(state.mode).toBe("isolated_reexecution");
      expect(state.planDigest).toBeNull();
      const manifest = toManifest(state2Complete(), catalog);
      expect(manifest.identities).toEqual({
        kind: "synthetic_dedicated", max_sessions: 2 });
      expect((manifest.recording as Record<string, unknown>).mandatory)
        .toBe(true);
      expect((manifest.effect_sinks as Record<string, unknown>[])[0]!.kind)
        .toBe("synthetic");
    });
});

function state2Complete(): BuilderState {
  // The manifest emitter refuses standing blockers, so the defaults
  // test needs a complete selection first; this helper mirrors
  // completeState without the plan digest.
  return toggleTarget(toggleScenario(setProfiles(
    selectWorkload(newBuilderState(), "wlv_repomaintenance01"),
    "aup_baselinehard0001", "aup_fullreview0001"),
    "scn_impossibletask01"), "tgt_repcheckout000001");
}

describe("blockers", () => {
  test("an empty selection lists what is missing", () => {
    const reasons = blockers(newBuilderState(), catalog);
    expect(reasons).toContain("select a workload");
    // The workload blocker short-circuits the rest.
    expect(reasons.length).toBe(1);
  });

  test("mode support is checked against the workload and scenarios",
    () => {
      const state = setMode(state2Complete(), "customer_canary");
      const reasons = blockers(state, catalog);
      expect(reasons.join(" | "))
        .toContain("mode customer_canary is not supported");
      expect(reasons.join(" | "))
        .toContain("scenarios do not support mode customer_canary");
    });

  test("the same profile twice is not a pair", () => {
    const state = setProfiles(state2Complete(),
      "aup_baselinehard0001", "aup_baselinehard0001");
    expect(blockers(state, catalog).join(" | "))
      .toContain("the baseline and treatment profiles are the same");
  });

  test("targets must be enrolled for the selected workload", () => {
    const switched = selectWorkload(state2Complete(),
      "wlv_repomaintenance01");
    // Enrolled target toggles fine.
    expect(blockers(switched, catalog).length).toBe(0);
  });

  test("switching workloads drops targets chosen for the old one",
    () => {
      const state = selectWorkload(state2Complete(),
        "wlv_triagetooling0002");
      expect(state.targetIds).toEqual([]);
      expect(blockers(state, catalog)).toContain(
        "select at least one enrolled target");
    });

  test("budgets are validated, not assumed", () => {
    const state = setBudgets(state2Complete(), {
      maxDurationS: 0, maxConcurrentSessions: 2,
      perSessionCostMaxMicros: 1, aggregateCostMaxMicros: 1,
      currency: "USD",
    });
    expect(blockers(state, catalog).join(" | "))
      .toContain("max duration must be between");
    const inverted = setBudgets(state2Complete(), {
      maxDurationS: 60, maxConcurrentSessions: 2,
      perSessionCostMaxMicros: 1_000, aggregateCostMaxMicros: 100,
      currency: "USD",
    });
    expect(blockers(inverted, catalog).join(" | "))
      .toContain("aggregate cost maximum is below the per-session maximum");
  });
});

describe("toManifest", () => {
  test("emits a complete manifest draft", () => {
    const manifest = toManifest(completeState(), catalog);
    expect(manifest.workload_version_id).toBe("wlv_repomaintenance01");
    expect(manifest.mode).toBe("isolated_reexecution");
    expect(manifest.baseline_profile_id).toBe("aup_baselinehard0001");
    expect(manifest.treatment_profile_id).toBe("aup_fullreview0001");
    const selectors =
      manifest.selectors as Record<string, unknown>[];
    expect(selectors[0]!.kind).toBe("enrolled_targets");
    expect(selectors[0]!.target_ids).toEqual(["tgt_repcheckout000001"]);
    const stopRules = manifest.stop_rules as Record<string, string>[];
    expect(stopRules.some((rule) =>
      rule.condition === "unauthorized_effect")).toBe(true);
  });

  test("refuses to emit a blocked configuration", () => {
    expect(() => toManifest(newBuilderState(), catalog))
      .toThrow(/cannot advance/);
  });

  test("customer canary switches identities and sinks", () => {
    const state = setMode(withPlanDigest(toggleTarget(toggleScenario(
      setProfiles(selectWorkload(newBuilderState(), "wlv_canarycandidate3"),
        "aup_baselinehard0001", "aup_fullreview0001"),
      "scn_canaryprobe00001"), "tgt_canaryenv0000001"), null),
      "customer_canary");
    const manifest = toManifest(state, catalog);
    expect((manifest.identities as Record<string, unknown>).kind)
      .toBe("enrolled_opt_in");
    expect((manifest.effect_sinks as Record<string, unknown>[])[0]!.kind)
      .toBe("enrolled_service");
    // Scheduling stays off until enrollment is confirmed outside the
    // builder, even with a complete canary configuration.
    expect(canSchedule(state, catalog)).toBe(false);
  });
});

describe("scheduling", () => {
  test("requires a compiled preview and no blockers", () => {
    expect(canSchedule(state2Complete(), catalog)).toBe(false);
    const withoutDigest = state2Complete();
    expect(canSchedule(withoutDigest, catalog)).toBe(false);
    expect(canSchedule(completeState(), catalog)).toBe(true);
  });

  test("a blocker keeps scheduling off even with a preview", () => {
    const blocked = setBudgets(completeState(), {
      maxDurationS: 0, maxConcurrentSessions: 2,
      perSessionCostMaxMicros: 1, aggregateCostMaxMicros: 1,
      currency: "USD",
    });
    expect(canSchedule(blocked, catalog)).toBe(false);
  });
});

describe("renderBuilder", () => {
  test("lists why the configuration cannot advance", () => {
    const html = renderBuilder(newBuilderState(), catalog);
    expect(html).toContain("Cannot advance");
    expect(html).toContain("select a workload");
    expect(html).toContain("schedule control disabled");
  });

  test("offers no ignore-safety checkbox", () => {
    const html = renderBuilder(newBuilderState(), catalog);
    expect(html).not.toMatch(/checkbox/i);
    expect(html).not.toMatch(/ignore safety/i);
    expect(html).toContain("there is no override");
    expect(html).toContain("recording is mandatory");
  });

  test("shows the preview digest only when compiled", () => {
    const pending = renderBuilder(state2Complete(), catalog);
    expect(pending).toContain("not compiled yet");
    expect(pending).toContain("only plan authority");
    const ready = renderBuilder(completeState(), catalog);
    expect(ready).toContain("sha256:0123456789abcdef");
    expect(ready).toContain("schedule control available");
  });

  test("renders selections as inert text", () => {
    const hostile = {
      ...catalogDocument,
      profiles: [
        { profile_id: "aup_baselinehard0001",
          description: `<script>x</script>` },
      ],
    };
    const html = renderBuilder(newBuilderState(),
      parseCatalog(hostile));
    expect(html).not.toContain("<script>");
  });
});
