// Suite for the run timeline (T033). Mirrors the overview and builder
// suites: strict-parse rejections with paths, lane assignment,
// correlation pairing, missing-half visibility, and inert rendering.
import { describe, expect, test } from "bun:test";
import { isInertHtml } from "./inert";
import {
  EffectPairing,
  lanes,
  laneFor,
  pairEffects,
  parseTimeline,
  renderTimeline,
  TimelineEvent,
} from "./timeline";

interface Mutable {
  [key: string]: unknown;
}

function eventDocument(overrides: Mutable = {}): Mutable {
  return {
    id: "evt_agentplan000001",
    event_kind: "proposed_action",
    trust_label: "worker_claim",
    source: { id: "src_worker-session1", component: "worker" },
    sequence: 4,
    observed_at: "2026-09-12T00:00:04Z",
    clock_uncertainty_ms: 0,
    payload: { kind: "inline", content: "plan: read the diff",
      redacted: false, truncated: false },
    correlation_ids: [],
    ...overrides,
  };
}

function decisionDocument(): Mutable {
  return eventDocument({
    id: "evt_brokerallow00001",
    event_kind: "broker_decision",
    trust_label: "collector_fact",
    source: { id: "src_broker-main01", component: "broker" },
    sequence: 1,
    observed_at: "2026-09-12T00:00:05Z",
    payload: { kind: "metadata_only", redacted: false, truncated: false },
    correlation_ids: ["cid_effect0001"],
  });
}

function receiptDocument(): Mutable {
  return eventDocument({
    id: "evt_vendorreceipt001",
    event_kind: "external_receipt",
    trust_label: "collector_fact",
    source: { id: "src_sink-audit0001", component: "collector" },
    sequence: 9,
    observed_at: "2026-09-12T00:00:06Z",
    payload: { kind: "object_ref",
      digest: "sha256:" + "a1".repeat(32), redacted: false,
      truncated: false },
    correlation_ids: ["cid_effect0001"],
  });
}

function timelineDocument(events: unknown[]): Mutable {
  return {
    kind: "RunTimeline",
    api_version: "v1",
    run_id: "run_isoreexec0001",
    events,
    findings: [{
      id: "fnd_fenceescape001",
      event_ids: [events.length === 0 ? "evt_agentplan000001"
        : (events[0] as Mutable).id],
      description: "the plan asked for a write outside the fence",
    }],
  };
}

function overrideFinding(document: Mutable,
  eventIds: string[]): Mutable {
  (document.findings as Mutable[])[0]!.event_ids = eventIds;
  return document;
}

describe("parseTimeline", () => {
  test("accepts a well-formed document", () => {
    const parsed = parseTimeline(timelineDocument(
      [eventDocument(), decisionDocument(), receiptDocument()]));
    expect(parsed.runId).toBe("run_isoreexec0001");
    expect(parsed.events.length).toBe(3);
    expect(parsed.events[0]!.sourceId).toBe("src_worker-session1");
    expect(parsed.events[0]!.payloadContent)
      .toBe("plan: read the diff");
  });

  test("findings are optional", () => {
    const document = timelineDocument([eventDocument()]);
    delete document.findings;
    expect(parseTimeline(document).findings).toEqual([]);
  });

  test("coverage is optional and carried", () => {
    const document = timelineDocument([eventDocument({
      source: { id: "src_worker-session1", component: "worker",
        coverage: false },
    })]);
    expect(parseTimeline(document).events[0]!.coverage).toBe(false);
  });

  const rejections: Array<[string, unknown, RegExp]> = [
    ["unknown root field",
      { ...timelineDocument([eventDocument()]), extra: 1 },
      /\$\.extra: unknown field/],
    ["wrong kind",
      { ...timelineDocument([eventDocument()]), kind: "Timeline" },
      /\$\.kind: expected RunTimeline/],
    ["bad run id",
      { ...timelineDocument([eventDocument()]), run_id: "run_X" },
      /\$\.run_id: expected run_ plus id/],
    ["unknown event field",
      timelineDocument([eventDocument({ surprise: 1 })]),
      /\$\.events\[0\]\.surprise: unknown field/],
    ["unknown source field",
      timelineDocument([eventDocument({
        source: { id: "src_worker-session1", component: "worker",
          extra: 1 },
      })]),
      /\$\.events\[0\]\.source\.extra: unknown field/],
    ["unknown payload field",
      timelineDocument([eventDocument({
        payload: { kind: "metadata_only", redacted: false,
          truncated: false, extra: 1 },
      })]),
      /\$\.events\[0\]\.payload\.extra: unknown field/],
    ["bad event id",
      timelineDocument([eventDocument({ id: "evt_BAD" })]),
      /\$\.events\[0\]\.id: expected evt_ plus id/],
    ["unknown event kind",
      timelineDocument([eventDocument({ event_kind: "vibe" })]),
      /\$\.events\[0\]\.event_kind: expected one of/],
    ["unknown trust label",
      timelineDocument([eventDocument({ trust_label: "gospel" })]),
      /\$\.events\[0\]\.trust_label: expected one of/],
    ["unknown source component",
      timelineDocument([eventDocument({
        source: { id: "src_worker-session1", component: "oracle" },
      })]),
      /\$\.events\[0\]\.source\.component: expected one of/],
    ["bad source id",
      timelineDocument([eventDocument({
        source: { id: "src_BAD", component: "worker" },
      })]),
      /\$\.events\[0\]\.source\.id: expected src_ plus id/],
    ["negative sequence",
      timelineDocument([eventDocument({ sequence: -1 })]),
      /\$\.events\[0\]\.sequence: expected a non-negative integer/],
    ["fractional clock uncertainty",
      timelineDocument([eventDocument({ clock_uncertainty_ms: 1.5 })]),
      /\$\.events\[0\]\.clock_uncertainty_ms/],
    ["bad timestamp",
      timelineDocument([eventDocument({ observed_at: "yesterday" })]),
      /\$\.events\[0\]\.observed_at: expected a timestamp/],
    ["bad payload kind",
      timelineDocument([eventDocument({
        payload: { kind: "hand_waved", redacted: false, truncated: false },
      })]),
      /\$\.events\[0\]\.payload\.kind: expected one of/],
    ["bad payload digest",
      timelineDocument([eventDocument({
        payload: { kind: "object_ref", digest: "md5:zz", redacted: false,
          truncated: false },
      })]),
      /\$\.events\[0\]\.payload\.digest: expected a sha256 digest/],
    ["bad correlation id",
      timelineDocument([eventDocument({ correlation_ids: ["effect1"] })]),
      /\$\.events\[0\]\.correlation_ids\[0\]: expected cid_ plus id/],
    ["duplicate event id",
      timelineDocument([eventDocument(), eventDocument()]),
      /listed twice/],
    ["finding with unknown event",
      overrideFinding(timelineDocument([eventDocument()]),
        ["evt_missing0000001"]),
      /references unknown event evt_missing0000001/],
  ];
  for (const [name, document, message] of rejections) {
    test(`rejects ${name}`, () => {
      expect(() => parseTimeline(document)).toThrow(message);
    });
  }
});

describe("laneFor", () => {
  test("monitor interpretation wins over kind", () => {
    const interpretation = parseTimeline(timelineDocument(
      [eventDocument({ trust_label: "monitor_interpretation",
        source: { id: "src_monitor-watch1", component: "monitor" } })]))
      .events[0]!;
    expect(laneFor(interpretation)).toBe("monitor");
  });

  test("every kind lands on its lane", () => {
    const cases: Array<[string, string]> = [
      ["proposed_action", "agent"],
      ["resource_access", "agent"],
      ["tool_request", "tool"],
      ["tool_response", "tool"],
      ["broker_decision", "broker"],
      ["external_receipt", "broker"],
      ["delegation", "broker"],
      ["injection_receipt", "injection"],
      ["collector_heartbeat", "infrastructure"],
      ["budget_change", "infrastructure"],
      ["recovery_action", "infrastructure"],
    ];
    const parsed = parseTimeline(timelineDocument(cases.map(([kind],
      index) => eventDocument({
      id: `evt_${kind.replace(/_/g, "")}00000000${index}`,
      event_kind: kind,
    }))));
    for (const [index, [, lane]] of cases.entries()) {
      expect(laneFor(parsed.events[index]!)).toBe(lane);
    }
  });
});

describe("pairEffects", () => {
  const parsed = () => parseTimeline(timelineDocument(
    [eventDocument(), decisionDocument(), receiptDocument()]));

  function byId(events: readonly TimelineEvent[],
    id: string): TimelineEvent {
    return events.find((event) => event.id === id)!;
  }

  test("joins a decision with its receipt", () => {
    const events = parsed().events;
    const pairings = pairEffects(events);
    expect(pairings.length).toBe(1);
    expect(pairings[0]!.correlationId).toBe("cid_effect0001");
    expect(pairings[0]!.authorization!.id).toBe("evt_brokerallow00001");
    expect(pairings[0]!.receipt!.id).toBe("evt_vendorreceipt001");
  });

  test("keeps a decision with no receipt", () => {
    const events = parsed().events
      .filter((event) => event.id !== "evt_vendorreceipt001");
    const pairings = pairEffects(events);
    expect(pairings.length).toBe(1);
    expect(pairings[0]!.receipt).toBeNull();
  });

  test("keeps a receipt with no decision", () => {
    const events = parsed().events
      .filter((event) => event.id !== "evt_brokerallow00001");
    const pairings = pairEffects(events);
    expect(pairings.length).toBe(1);
    expect(pairings[0]!.authorization).toBeNull();
  });

  test("ignores events without correlation ids and sorts by id",
    () => {
      const solo = byId(parsed().events, "evt_agentplan000001");
      const pairings = pairEffects([solo]);
      expect(pairings).toEqual([]);
      const second = receiptDocument();
      second.correlation_ids = ["cid_effect0000"];
      const more = pairEffects(parseTimeline(timelineDocument(
        [decisionDocument(), second])).events);
      expect(more.map((pair: EffectPairing) => pair.correlationId))
        .toEqual(["cid_effect0000", "cid_effect0001"]);
    });
});

describe("renderTimeline", () => {
  const hostile = '<img src=x onerror="alert(1)"><script>bad()</script>';

  function render(events: unknown[]): string {
    return renderTimeline(parseTimeline(timelineDocument(events)));
  }

  test("renders all six lanes in order", () => {
    const html = render([eventDocument(), decisionDocument(),
      receiptDocument()]);
    const positions = lanes.map((lane) =>
      html.indexOf(`data-lane="${lane}"`));
    expect(positions.every((position) => position >= 0)).toBe(true);
    expect([...positions].sort((left, right) => left - right))
      .toEqual(positions);
  });

  test("empty lanes say so", () => {
    const html = render([eventDocument()]);
    expect(html).toContain('<p class="empty">no events</p>');
  });

  test("labels the trust of every event", () => {
    const html = render([eventDocument(), decisionDocument()]);
    expect((html.match(/class="event worker_claim"/g) ?? []).length)
      .toBe(1);
    expect((html.match(/class="event collector_fact"/g) ?? []).length)
      .toBe(1);
    expect(html).toContain('<span class="trust">worker claim</span>');
    expect(html).toContain('<span class="trust">collector fact</span>');
  });

  test("shows the per-source sequence and the no-global-order note",
    () => {
      const html = render([eventDocument()]);
      expect(html).toContain("seq 4");
      expect(html).toMatch(/no global total order/);
    });

  test("renders object refs as digests, never fetches", () => {
    const html = render([receiptDocument()]);
    expect(html).toContain("sha256:a1a1");
    expect(html).not.toMatch(/XMLHttpRequest|<img|<script/);
    expect(html).toContain("does not fetch it");
  });

  test("renders inline content escaped", () => {
    const html = render([eventDocument({
      payload: { kind: "inline", content: hostile, redacted: false,
        truncated: false },
    })]);
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<script");
    expect(html).toContain("&lt;img src=x onerror=");
  });

  test("renders monitor interpretations even on agent kinds", () => {
    const html = render([eventDocument({
      trust_label: "monitor_interpretation",
      source: { id: "src_monitor-watch1", component: "monitor" },
    })]);
    expect(html).toContain("monitor interpretation");
  });

  test("flags redaction, truncation, limited coverage, clock skew",
    () => {
      const html = render([eventDocument({
        source: { id: "src_worker-session1", component: "worker",
          coverage: false },
        clock_uncertainty_ms: 250,
        payload: { kind: "inline", content: "cut off", redacted: true,
          truncated: true },
      })]);
      expect(html).toContain("redacted");
      expect(html).toContain("truncated");
      expect(html).toContain("source coverage limited");
      expect(html).toContain("clock ±250ms");
    });

  test("pairs effects and keeps missing halves visible", () => {
    const paired = render([decisionDocument(), receiptDocument()]);
    expect(paired).toContain("cid_effect0001");
    expect(paired).not.toContain("missing");

    const noReceipt = render([decisionDocument()]);
    expect(noReceipt).toContain("receipt missing");

    const noDecision = render([receiptDocument()]);
    expect(noDecision).toContain("authorization missing");
  });

  test("links findings to their events", () => {
    const html = render([eventDocument()]);
    expect(html).toContain("fnd_fenceescape001");
    expect(html).toContain("evt_agentplan000001");
    expect(html).toContain("the plan asked for a write outside the fence");
  });

  test("escapes hostile finding descriptions", () => {
    const document = timelineDocument([eventDocument()]);
    (document.findings as Mutable[])[0]!.description = hostile;
    const html = renderTimeline(parseTimeline(document));
    expect(html).not.toContain("<script");
    expect(html).toContain("&lt;script&gt;bad()&lt;/script&gt;");
  });

  test("a hostile payload stays inert through the full render", () => {
    const html = render([eventDocument({
      payload: { kind: "inline", content: hostile, redacted: false,
        truncated: false },
    })]);
    const item = html.slice(html.indexOf('<li class="event'),
      html.indexOf("</li>", html.indexOf('<li class="event')) + 5);
    expect(isInertHtml(item)).toBe(true);
    expect(html).toContain("&lt;img src=x onerror=");
  });
});
