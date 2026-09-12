package supervisor

// Session review, spec 11.1 layer 4 and spec 11.3 (T019): structured
// checks over the complete recorded event sequence of one session,
// bounded incremental segments for long logs, and an explicit
// incomplete outcome when the review budget runs out or required
// evidence is missing. A session is never marked clean because its
// log fit in a budget; processing a log is not proof that every
// behavior was understood.

import (
	"fmt"
	"strings"
	"time"

	"gauntlet/evidence"
)

// Session outcomes. AC-016: every session receives a final review or
// an explicit incompleteness — there is no third state.
const (
	SessionReviewed   = "reviewed"
	SessionIncomplete = "incomplete"
)

// Structured check names.
const (
	CheckMissingDecision  = "missing_decision"
	CheckMissingReceipt   = "missing_receipt"
	CheckMissingToolReply = "missing_tool_response"
	CheckSilentCollector  = "collector_silent"
	CheckTrajectory       = "trajectory"
	checkSampleLimit      = 8
	segmentQuestionLimit  = 4
	reasonLimit           = 8
)

// SessionConfig bounds one session review (spec 11.3).
type SessionConfig struct {
	// SegmentSize is how many events one semantic segment summarizes.
	SegmentSize int
	// MaxSegments is the review budget: the segment count a session
	// review may consume. Logs beyond the budget are disclosed as
	// omitted and the outcome is incomplete.
	MaxSegments int
	// DelayBudget is how far an event's ingest may trail its
	// observation before the report discloses it as delayed.
	DelayBudget time.Duration
}

// DefaultSessionConfig returns the session review defaults.
func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		SegmentSize: 50,
		MaxSegments: 8,
		DelayBudget: 10 * time.Minute,
	}
}

// SessionFinding is one structured check result. It names the check,
// the severity, and the events that triggered it.
type SessionFinding struct {
	Check     string   `json:"check"`
	Severity  string   `json:"severity"`
	Detail    string   `json:"detail"`
	EventRefs []string `json:"event_refs,omitempty"`
}

// SegmentSummary summarizes one reviewed segment. Summaries retain
// references and unresolved questions; the raw windows stay
// retrievable in the evidence store (spec 11.3).
type SegmentSummary struct {
	Index         int      `json:"index"`
	FirstEventID  string   `json:"first_event_id"`
	LastEventID   string   `json:"last_event_id"`
	Events        int      `json:"events"`
	OpenQuestions []string `json:"open_questions,omitempty"`
}

// SessionDisclosures report what the record itself admits: payloads
// the capture omitted or truncated, and events that arrived late.
// Disclosures are facts about the log, not accusations.
type SessionDisclosures struct {
	OmittedPayloads   int      `json:"omitted_payloads"`
	TruncatedPayloads int      `json:"truncated_payloads"`
	DelayedEvents     int      `json:"delayed_events"`
	Samples           []string `json:"samples,omitempty"`
}

// SessionReport is the final review of one session. The outcome is
// reviewed or incomplete, never clean-by-silence.
type SessionReport struct {
	Kind          string             `json:"kind"`
	APIVersion    string             `json:"api_version"`
	RunID         string             `json:"run_id"`
	TenantID      string             `json:"tenant_id"`
	Outcome       string             `json:"outcome"`
	Reasons       []string           `json:"incomplete_reasons,omitempty"`
	Reviewed      int                `json:"reviewed"`
	Omitted       int                `json:"omitted"`
	OmittedFromID string             `json:"omitted_from_event_id,omitempty"`
	Findings      []SessionFinding   `json:"findings,omitempty"`
	Segments      []SegmentSummary   `json:"segments"`
	Disclosures   SessionDisclosures `json:"disclosures"`
	Limitations   []string           `json:"limitations"`
	CheckedAt     string             `json:"checked_at"`
}

// SessionReviewer runs the structured checks over one session's event
// sequence (spec 11.1 layer 4). It is deterministic: no model, no
// network, no credentials — the semantic window review it summarizes
// is bounded by configuration, and the whole log is still scanned by
// the cheap structural checks.
type SessionReviewer struct {
	config SessionConfig
	now    func() time.Time
}

// NewSessionReviewer builds a reviewer; a zero config becomes the
// defaults.
func NewSessionReviewer(config SessionConfig) *SessionReviewer {
	if config.SegmentSize <= 0 {
		config = DefaultSessionConfig()
	}
	if config.MaxSegments <= 0 || config.DelayBudget <= 0 {
		defaults := DefaultSessionConfig()
		if config.MaxSegments <= 0 {
			config.MaxSegments = defaults.MaxSegments
		}
		if config.DelayBudget <= 0 {
			config.DelayBudget = defaults.DelayBudget
		}
	}
	return &SessionReviewer{config: config, now: time.Now}
}

// Review checks one session's events in ingest order. The report is
// always complete: an over-budget or under-evidenced session gets an
// explicit incomplete outcome with reasons, never a quiet pass.
func (r *SessionReviewer) Review(tenantID, runID string,
	events []evidence.Event) *SessionReport {
	report := &SessionReport{
		Kind:       "SessionReport",
		APIVersion: "v1",
		RunID:      runID,
		TenantID:   tenantID,
		CheckedAt:  r.now().UTC().Format("2006-01-02T15:04:05Z"),
		Segments:   []SegmentSummary{},
	}

	if len(events) == 0 {
		report.Outcome = SessionIncomplete
		report.addReason("no events were recorded for the session")
		report.Limitations = r.limitations(report)
		return report
	}

	// Structural checks run over the complete sequence — they are
	// linear and cheap, so budget never blinds them.
	report.Findings = append(report.Findings, indexEffects(events)...)
	disclosures := disclose(events, r.config.DelayBudget)
	report.Disclosures = disclosures

	// Trajectory check: the fast detector with a whole-session window
	// finds patterns a bounded window can miss (denied retries across
	// hours, bursts that straddle the boundary).
	detectorConfig := DefaultDetectorConfig()
	detectorConfig.WindowSize = len(events)
	detection := NewFastDetector(detectorConfig).Detect(events)
	for _, suspicion := range detection.Suspicions {
		check := CheckTrajectory + "." + suspicion.Rule
		if suspicion.Rule == "collector_silent" {
			// A silent collector is missing evidence, not just a
			// pattern: the session record cannot be complete.
			check = CheckSilentCollector
		}
		finding := SessionFinding{
			Check:     check,
			Severity:  suspicion.Severity,
			Detail:    suspicion.Detail,
			EventRefs: suspicion.EventRefs,
		}
		if finding.Severity == "" {
			finding.Severity = SeverityLow
		}
		report.Findings = append(report.Findings, finding)
	}

	// Semantic segments, bounded by the review budget. Everything the
	// budget could not cover is disclosed and the session cannot be
	// called reviewed (spec 11.3: incomplete, not clean).
	budget := r.config.SegmentSize * r.config.MaxSegments
	reviewed := events
	if len(events) > budget {
		reviewed = events[:budget]
		report.Omitted = len(events) - budget
		report.OmittedFromID = events[budget].ID
		report.addReason(fmt.Sprintf(
			"session log of %d events exceeds the review budget of %d",
			len(events), budget))
	}
	for start := 0; start < len(reviewed); start += r.config.SegmentSize {
		end := start + r.config.SegmentSize
		if end > len(reviewed) {
			end = len(reviewed)
		}
		segment := SegmentSummary{
			Index:        len(report.Segments),
			FirstEventID: reviewed[start].ID,
			LastEventID:  reviewed[end-1].ID,
			Events:       end - start,
		}
		for _, finding := range report.Findings {
			if len(segment.OpenQuestions) >= segmentQuestionLimit {
				break
			}
			if structuralCheck(finding) && startsIn(finding.EventRefs,
				reviewed[start:end]) {
				segment.OpenQuestions = append(segment.OpenQuestions,
					finding.Detail)
			}
		}
		report.Segments = append(report.Segments, segment)
	}
	report.Reviewed = len(reviewed)

	if report.Omitted > 0 || anyMissingEvidence(report.Findings) {
		if report.Outcome == "" {
			report.Outcome = SessionIncomplete
		}
		for _, finding := range report.Findings {
			if !missingEvidence(finding) {
				continue
			}
			report.addReason(fmt.Sprintf("%s: %s", finding.Check, finding.Detail))
		}
	} else {
		report.Outcome = SessionReviewed
	}
	report.Limitations = r.limitations(report)
	return report
}

// limitations states what the report does not claim. The base
// limitation is unconditional: processing a session log is not proof
// that every behavior was understood (spec 11.3).
func (r *SessionReviewer) limitations(report *SessionReport) []string {
	base := "processing the session log is not proof that every " +
		"behavior was understood"
	out := []string{base}
	if report.Omitted > 0 {
		out = append(out, fmt.Sprintf(
			"%d events beyond the review budget were not semantically "+
				"reviewed; the structural checks still covered them",
			report.Omitted))
	}
	if len(report.Disclosures.Samples) > 0 {
		out = append(out, fmt.Sprintf(
			"the record itself reports %d omitted payloads, %d truncated "+
				"payloads, and %d delayed events",
			report.Disclosures.OmittedPayloads,
			report.Disclosures.TruncatedPayloads,
			report.Disclosures.DelayedEvents))
	}
	return out
}

func (r *SessionReport) addReason(reason string) {
	if len(r.Reasons) >= reasonLimit {
		return
	}
	r.Reasons = append(r.Reasons, reason)
}

// anyMissingEvidence reports whether any finding names evidence the
// record should carry and does not.
func anyMissingEvidence(findings []SessionFinding) bool {
	for _, finding := range findings {
		if missingEvidence(finding) {
			return true
		}
	}
	return false
}

// missingEvidence reports whether a finding names evidence the record
// should carry and does not. Missing evidence makes the session
// incomplete: the review cannot certify what it cannot see.
func missingEvidence(finding SessionFinding) bool {
	return finding.Check == CheckMissingDecision ||
		finding.Check == CheckMissingReceipt ||
		finding.Check == CheckMissingToolReply ||
		finding.Check == CheckSilentCollector
}

// indexEffects runs the coverage checks: every proposed effect has a
// broker decision, every allowed effect has an external receipt, and
// every tool request has its tool response.
func indexEffects(events []evidence.Event) []SessionFinding {
	decisions := map[string]*evidence.Event{}
	receipts := map[string]bool{}
	allowed := map[string]bool{}
	responses := map[string]bool{}
	var findings []SessionFinding

	for i := range events {
		event := &events[i]
		switch event.EventKind {
		case evidence.KindBrokerDecision:
			if event.EffectID != "" {
				decisions[event.EffectID] = event
				if strings.HasPrefix(event.Payload.Content, "allow") {
					allowed[event.EffectID] = true
				}
			}
		case evidence.KindExternalReceipt:
			receipts[event.EffectID] = true
		case evidence.KindToolResponse:
			for _, parent := range event.ParentEventIDs {
				responses[parent] = true
			}
		}
	}

	for i := range events {
		event := &events[i]
		switch event.EventKind {
		case evidence.KindProposedAction:
			if event.EffectID != "" && decisions[event.EffectID] == nil {
				findings = append(findings, SessionFinding{
					Check:    CheckMissingDecision,
					Severity: SeverityHigh,
					Detail: fmt.Sprintf(
						"proposed action %s has no broker decision on record",
						event.EffectID),
					EventRefs: []string{event.ID},
				})
			}
		case evidence.KindBrokerDecision:
			if event.EffectID != "" && allowed[event.EffectID] &&
				!receipts[event.EffectID] {
				findings = append(findings, SessionFinding{
					Check:    CheckMissingReceipt,
					Severity: SeverityHigh,
					Detail: fmt.Sprintf(
						"effect %s was allowed but no external receipt "+
							"confirms what the send did", event.EffectID),
					EventRefs: []string{event.ID},
				})
			}
		case evidence.KindToolRequest:
			if !responses[event.ID] {
				findings = append(findings, SessionFinding{
					Check:    CheckMissingToolReply,
					Severity: SeverityLow,
					Detail: fmt.Sprintf(
						"tool request %s has no tool response on record",
						event.ID),
					EventRefs: []string{event.ID},
				})
			}
		}
	}
	return findings
}

// disclose counts what the record admits about itself and keeps a
// bounded sample of event ids.
func disclose(events []evidence.Event,
	delayBudget time.Duration) SessionDisclosures {
	out := SessionDisclosures{}
	for i := range events {
		event := &events[i]
		note := false
		if event.Payload.Kind == evidence.PayloadMetadataOnly ||
			event.Payload.Tombstone {
			out.OmittedPayloads++
			note = true
		}
		if event.Payload.Truncated {
			out.TruncatedPayloads++
			note = true
		}
		if delay := ingestDelay(event, delayBudget); delay {
			out.DelayedEvents++
			note = true
		}
		if note && len(out.Samples) < checkSampleLimit {
			out.Samples = append(out.Samples, event.ID)
		}
	}
	return out
}

// ingestDelay reports whether the event's ingest trailed its
// observation by more than the budget. Unparseable timestamps count
// as delayed: the record cannot prove they were prompt.
func ingestDelay(event *evidence.Event, delayBudget time.Duration) bool {
	observed, err := time.Parse(time.RFC3339Nano, event.ObservedAt)
	if err != nil {
		return event.IngestedAt != ""
	}
	ingested, err := time.Parse(time.RFC3339Nano, event.IngestedAt)
	if err != nil {
		return false
	}
	delay := ingested.Sub(observed)
	if delay < 0 {
		delay = -delay
	}
	return delay > delayBudget
}

// structuralCheck reports whether the finding comes from the
// structural coverage checks; those carry open questions into the
// segments that contain their events.
func structuralCheck(finding SessionFinding) bool {
	return strings.HasPrefix(finding.Check, CheckMissingDecision) ||
		strings.HasPrefix(finding.Check, CheckMissingReceipt) ||
		strings.HasPrefix(finding.Check, CheckMissingToolReply)
}

// startsIn reports whether any of the ids belongs to the window.
func startsIn(ids []string, window []evidence.Event) bool {
	present := make(map[string]bool, len(window))
	for i := range window {
		present[window[i].ID] = true
	}
	for _, id := range ids {
		if present[id] {
			return true
		}
	}
	return false
}
