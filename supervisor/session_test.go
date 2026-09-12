package supervisor

// Spec 11.3 / T019: structured checks over the complete session
// sequence, disclosures for what the record admits, bounded segments,
// and explicit incompleteness when the budget runs out or required
// evidence is missing (AC-016).

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"gauntlet/evidence"
)

const sessionTenant = "tnt_9d4c1e2a3b4f5c67"
const sessionRun = "run_0a0b0c0d0e0f0102"

// sessionEvent extends the shared fixture with payload and timing.
func sessionEvent(id, kind, trust, component string, sequence int64) evidence.Event {
	return evidence.Event{
		Kind:       "EvidenceEvent",
		APIVersion: "v1",
		ID:         id,
		TenantID:   sessionTenant,
		RunID:      sessionRun,
		EventKind:  kind,
		TrustLabel: trust,
		Source:     evidence.EventSource{ID: "src_s-0000000000001", Component: component},
		Sequence:   sequence,
		EffectID:   "eff_0a0b0c0d0e0f0102",
		ObservedAt: "2026-09-12T10:00:00Z",
		IngestedAt: "2026-09-12T10:00:05Z",
	}
}

// cleanSession is a complete, benign record: proposal, decision,
// receipt, tool round trip, and a collector heartbeat.
func cleanSession() []evidence.Event {
	request := sessionEvent("evt_"+"s000000000000001",
		evidence.KindToolRequest, evidence.TrustWorkerClaim,
		evidence.ComponentWorker, 1)
	response := sessionEvent("evt_"+"s000000000000002",
		evidence.KindToolResponse, evidence.TrustWorkerClaim,
		evidence.ComponentWorker, 2)
	response.ParentEventIDs = []string{request.ID}
	decision := sessionEvent("evt_"+"s000000000000003",
		evidence.KindBrokerDecision, evidence.TrustCollectorFact,
		evidence.ComponentBroker, 3)
	decision.EffectID = "eff_0a0b0c0d0e0f0102"
	decision.Payload.Content = "allow:queue.publish"
	receipt := sessionEvent("evt_"+"s000000000000004",
		evidence.KindExternalReceipt, evidence.TrustCollectorFact,
		evidence.ComponentCollector, 4)
	receipt.EffectID = "eff_0a0b0c0d0e0f0102"
	heartbeat := sessionEvent("evt_"+"s000000000000005",
		evidence.KindCollectorHeartbeat, evidence.TrustCollectorFact,
		evidence.ComponentCollector, 5)
	return []evidence.Event{
		sessionProposal(decision.EffectID, "evt_"+"s000000000000006", 0),
		request, response, decision, receipt, heartbeat,
	}
}

// proposal is a worker's proposed action for one effect.
func sessionProposal(effectID, id string, sequence int64) evidence.Event {
	event := sessionEvent(id, evidence.KindProposedAction,
		evidence.TrustWorkerClaim, evidence.ComponentWorker, sequence)
	event.EffectID = effectID
	return event
}

func sessionReviewer() *SessionReviewer {
	return NewSessionReviewer(SessionConfig{
		SegmentSize: 3, MaxSegments: 2, DelayBudget: 10 * time.Minute,
	})
}

func TestACleanSessionIsReviewedWithItsLimitation(t *testing.T) {
	report := sessionReviewer().Review(sessionTenant, sessionRun, cleanSession())
	if report.Outcome != SessionReviewed {
		t.Fatalf("outcome %s reasons %v findings %+v",
			report.Outcome, report.Reasons, report.Findings)
	}
	if report.Omitted != 0 || report.Reviewed != 6 {
		t.Fatalf("coverage: %+v", report)
	}
	if len(report.Segments) != 2 {
		t.Fatalf("segments: %+v", report.Segments)
	}
	if len(report.Limitations) == 0 || !strings.Contains(
		report.Limitations[0], "not proof") {
		t.Fatalf("the unconditional limitation is missing: %v", report.Limitations)
	}
}

func TestAnEmptyLogIsExplicitlyIncomplete(t *testing.T) {
	report := sessionReviewer().Review(sessionTenant, sessionRun, nil)
	if report.Outcome != SessionIncomplete {
		t.Fatalf("empty session outcome: %s", report.Outcome)
	}
	if len(report.Reasons) != 1 || !strings.Contains(report.Reasons[0], "no events") {
		t.Fatalf("empty session reasons: %v", report.Reasons)
	}
	if len(report.Limitations) == 0 {
		t.Fatal("even an empty report states its limits")
	}
}

func TestAMissingDecisionMakesTheSessionIncomplete(t *testing.T) {
	events := cleanSession()
	// Drop the broker decision: the proposal never got an answer.
	events = append(events[:3], events[4:]...)
	report := sessionReviewer().Review(sessionTenant, sessionRun, events)
	if report.Outcome != SessionIncomplete {
		t.Fatalf("outcome: %s findings %+v", report.Outcome, report.Findings)
	}
	found := false
	for _, finding := range report.Findings {
		if finding.Check == CheckMissingDecision {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing decision finding: %+v", report.Findings)
	}
	if !reasonNames(report, CheckMissingDecision) {
		t.Fatalf("incomplete reasons: %v", report.Reasons)
	}
}

func TestAnAllowedEffectWithoutAReceiptIsIncomplete(t *testing.T) {
	events := cleanSession()
	// Drop the external receipt: an allowed send with no confirmation.
	events = append(events[:4], events[5:]...)
	report := sessionReviewer().Review(sessionTenant, sessionRun, events)
	if report.Outcome != SessionIncomplete {
		t.Fatalf("outcome: %s findings %+v", report.Outcome, report.Findings)
	}
	found := false
	for _, finding := range report.Findings {
		if finding.Check == CheckMissingReceipt {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing receipt finding: %+v", report.Findings)
	}
}

func TestAToolRequestWithoutAResponseIsDisclosed(t *testing.T) {
	events := cleanSession()
	// Drop the tool response: the tool call never answered.
	events = append(events[:2], events[3:]...)
	report := sessionReviewer().Review(sessionTenant, sessionRun, events)
	if report.Outcome != SessionIncomplete {
		t.Fatalf("outcome: %s", report.Outcome)
	}
	found := false
	for _, finding := range report.Findings {
		if finding.Check == CheckMissingToolReply {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing tool finding: %+v", report.Findings)
	}
}

func TestTheRecordDisclosesItsOwnGaps(t *testing.T) {
	events := cleanSession()
	// One payload omitted, one truncated, one late.
	events[1].Payload = evidence.EventPayload{Kind: evidence.PayloadMetadataOnly}
	events[2].Payload = evidence.EventPayload{
		Kind: evidence.PayloadInline, Content: "x", Truncated: true}
	events[3].IngestedAt = "2026-09-12T11:30:00Z"

	report := sessionReviewer().Review(sessionTenant, sessionRun, events)
	if report.Disclosures.OmittedPayloads != 1 ||
		report.Disclosures.TruncatedPayloads != 1 ||
		report.Disclosures.DelayedEvents != 1 {
		t.Fatalf("disclosures: %+v", report.Disclosures)
	}
	if len(report.Disclosures.Samples) != 3 {
		t.Fatalf("samples: %v", report.Disclosures.Samples)
	}
	if len(report.Limitations) < 2 {
		t.Fatalf("disclosures must surface as limitations: %v", report.Limitations)
	}
	// An unparseable observed_at cannot prove promptness.
	events[0].ObservedAt = "not-a-timestamp"
	report = sessionReviewer().Review(sessionTenant, sessionRun, events)
	if report.Disclosures.DelayedEvents != 2 {
		t.Fatalf("unparseable timestamps count as delayed: %+v",
			report.Disclosures)
	}
}

func TestABudgetedSessionIsIncompleteNotClean(t *testing.T) {
	events := cleanSession()
	// 13 events against a budget of 3 x 2 = 6.
	for i := 6; i < 13; i++ {
		events = append(events, sessionEvent(
			fmt.Sprintf("evt_s%015d", i),
			evidence.KindCollectorHeartbeat, evidence.TrustCollectorFact,
			evidence.ComponentCollector, int64(i)))
	}
	report := sessionReviewer().Review(sessionTenant, sessionRun, events)
	if report.Outcome != SessionIncomplete {
		t.Fatalf("an over-budget session called itself %s", report.Outcome)
	}
	if report.Reviewed != 6 || report.Omitted != 7 {
		t.Fatalf("coverage: reviewed %d omitted %d",
			report.Reviewed, report.Omitted)
	}
	if report.OmittedFromID != events[6].ID {
		t.Fatalf("omitted range starts at %s", report.OmittedFromID)
	}
	if !reasonNames(report, "review budget") {
		t.Fatalf("reasons: %v", report.Reasons)
	}
	if len(report.Segments) != 2 {
		t.Fatalf("segments beyond the budget: %+v", report.Segments)
	}
}

func TestLongSessionsSummarizeBoundedSegments(t *testing.T) {
	events := cleanSession()
	// Nine events, three segments: every segment keeps its references.
	for i := 6; i < 9; i++ {
		events = append(events, sessionEvent(
			fmt.Sprintf("evt_s%015d", i),
			evidence.KindCollectorHeartbeat, evidence.TrustCollectorFact,
			evidence.ComponentCollector, int64(i)))
	}
	reviewer := NewSessionReviewer(SessionConfig{
		SegmentSize: 3, MaxSegments: 4, DelayBudget: time.Minute})
	report := reviewer.Review(sessionTenant, sessionRun, events)
	if report.Outcome != SessionReviewed || len(report.Segments) != 3 {
		t.Fatalf("segments: %+v outcome %s", report.Segments, report.Outcome)
	}
	for i, segment := range report.Segments {
		if segment.Index != i || segment.Events != 3 ||
			segment.FirstEventID == "" || segment.LastEventID == "" {
			t.Fatalf("segment %d: %+v", i, segment)
		}
	}
	// Structural findings land as open questions in their segment.
	events = append(events, sessionProposal("eff_1111111111111111",
		"evt_"+"s000000000000010", 9))
	report = reviewer.Review(sessionTenant, sessionRun, events)
	if len(report.Segments[len(report.Segments)-1].OpenQuestions) == 0 {
		t.Fatalf("open questions did not carry: %+v", report.Segments)
	}
}

func TestTrajectoryPatternsSpanTheWholeSession(t *testing.T) {
	events := cleanSession()
	// The deny and its retry sit far apart — beyond any bounded
	// detection window, inside one session review. The retry got its
	// own (denied) decision, so the record is complete; the pattern
	// is the finding.
	deny := sessionEvent("evt_"+"s000000000000007",
		evidence.KindBrokerDecision, evidence.TrustCollectorFact,
		evidence.ComponentBroker, 7)
	deny.EffectID = "eff_1111111111111111"
	deny.Payload.Content = "deny:queue.publish destination_not_allowed"
	retry := sessionProposal("eff_2222222222222222",
		"evt_"+"s000000000000008", 8)
	retryDeny := sessionEvent("evt_"+"s000000000000009",
		evidence.KindBrokerDecision, evidence.TrustCollectorFact,
		evidence.ComponentBroker, 9)
	retryDeny.EffectID = retry.EffectID
	retryDeny.Payload.Content = "deny:queue.publish denied_retry"
	events = append(events, deny, retry, retryDeny)

	// The default reviewer budget is 6 events; this session needs a
	// larger one so the trajectory check, not the budget, is under
	// test.
	reviewer := NewSessionReviewer(SessionConfig{
		SegmentSize: 5, MaxSegments: 2, DelayBudget: time.Minute})
	report := reviewer.Review(sessionTenant, sessionRun, events)
	found := false
	for _, finding := range report.Findings {
		if finding.Check == CheckTrajectory+".denied_retry" &&
			finding.Severity == SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Fatalf("trajectory findings: %+v", report.Findings)
	}
	// A suspicious but fully evidenced session is still reviewed —
	// the findings are the output, not an error.
	if report.Outcome != SessionReviewed {
		t.Fatalf("outcome: %s reasons %v", report.Outcome, report.Reasons)
	}
}

func TestASilentCollectorMakesTheSessionIncomplete(t *testing.T) {
	events := cleanSession()
	// Remove the heartbeat and add worker tool traffic the collector
	// never covered.
	events = append(events[:5],
		sessionEvent("evt_"+"s000000000000007", evidence.KindToolRequest,
			evidence.TrustWorkerClaim, evidence.ComponentWorker, 7))
	report := sessionReviewer().Review(sessionTenant, sessionRun, events)
	if report.Outcome != SessionIncomplete {
		t.Fatalf("outcome: %s findings %+v", report.Outcome, report.Findings)
	}
	if !reasonNames(report, CheckSilentCollector) {
		t.Fatalf("reasons: %v", report.Reasons)
	}
}

func TestTheReportMarshalsAsAnEvidencePayload(t *testing.T) {
	report := sessionReviewer().Review(sessionTenant, sessionRun, cleanSession())
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	document := map[string]any{}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"kind", "run_id", "outcome", "segments",
		"disclosures", "limitations"} {
		if _, ok := document[key]; !ok {
			t.Fatalf("missing key %s in %s", key, encoded)
		}
	}
}

func reasonNames(report *SessionReport, want string) bool {
	for _, reason := range report.Reasons {
		if strings.Contains(reason, want) {
			return true
		}
	}
	return false
}
