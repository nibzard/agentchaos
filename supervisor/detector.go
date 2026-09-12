// Package supervisor implements the non-deterministic supervision
// layers of spec 11.1 (T018): the fast detector that reads a bounded
// evidence window and routes review, and the contextual reviewer that
// returns a review decision under a deadline. The deterministic gate
// (spec 11.1 layer 1) stays in the broker; nothing here can widen it.
//
// Reviews are broker.Review values, so every decision the supervisor
// produces can be attached to the held effect through AttachReview
// and is subject to the same decision contract — verdict, reviewer,
// policy references, event references, rationale, and latency
// (spec 11.2, AC-014).
package supervisor

import (
	"fmt"
	"strings"

	"gauntlet/evidence"
)

// Severity ranks a suspicion. High-severity suspicions are the ones a
// reviewer cannot clear on its own; low-severity suspicions are
// routing signals the reviewer weighs.
const (
	SeverityLow  = "low"
	SeverityHigh = "high"
)

// Suspicion is one deterministic finding from the fast detector. It
// always names the rule, the policy the rule enforces, and the events
// that triggered it, so a reviewer can inherit AC-014 references
// instead of inventing them.
type Suspicion struct {
	Rule      string   `json:"rule"`
	Severity  string   `json:"severity"`
	PolicyRef string   `json:"policy_ref"`
	EventRefs []string `json:"event_refs"`
	Detail    string   `json:"detail"`
}

// Detection is the fast detector's complete output for one window.
type Detection struct {
	Suspicions   []Suspicion `json:"suspicions"`
	RouteReview  bool        `json:"route_review"`
	WindowEvents int         `json:"window_events"`
}

// DetectorConfig bounds the fast detector (spec 11.1 layer 2). Zero
// values become the defaults; a bounded window is the whole point of
// the layer, so Detect never scans unbounded history.
type DetectorConfig struct {
	// WindowSize is how many most-recent events one detection sees.
	WindowSize int
	// MaxProposals is the proposal count per worker source above
	// which the window counts as a burst.
	MaxProposals int
	// RequireCollectorHeartbeat, when true, flags windows that carry
	// worker tool traffic but no collector heartbeat.
	RequireCollectorHeartbeat bool
}

// DefaultDetectorConfig returns the detection defaults.
func DefaultDetectorConfig() DetectorConfig {
	return DetectorConfig{
		WindowSize:                100,
		MaxProposals:              8,
		RequireCollectorHeartbeat: true,
	}
}

// FastDetector is the deterministic pre-filter (spec 11.1 layer 2).
// It reads only what the evidence contract carries: event kinds,
// trust labels, sources, sequences, and correction edges. It never
// calls a model, and it never decides an effect — it routes review.
type FastDetector struct {
	config DetectorConfig
}

// NewFastDetector builds a detector. WindowSize and MaxProposals
// fall back to the defaults when unset; the boolean flags are taken
// as given, so callers that want the whole default set pass
// DefaultDetectorConfig().
func NewFastDetector(config DetectorConfig) *FastDetector {
	if config.WindowSize <= 0 {
		config.WindowSize = 100
	}
	if config.MaxProposals <= 0 {
		config.MaxProposals = 8
	}
	return &FastDetector{config: config}
}

// Detect scans one bounded window of run events. Events beyond the
// configured window size are ignored — the caller supplies the full
// recent history and the detector bounds itself.
func (d *FastDetector) Detect(events []evidence.Event) Detection {
	window := events
	if len(window) > d.config.WindowSize {
		window = window[len(window)-d.config.WindowSize:]
	}
	detection := Detection{WindowEvents: len(window)}

	lastDenySequence := int64(-1)
	var denyEvent string
	proposalsBySource := map[string][]string{}
	var workerToolEvents []string
	heartbeats := 0

	for i := range window {
		event := &window[i]
		switch event.EventKind {
		case evidence.KindBrokerDecision:
			// The broker's evidence sink writes the decision verdict
			// into the payload content of the event.
			if strings.HasPrefix(event.Payload.Content, "deny") {
				lastDenySequence = event.Sequence
				denyEvent = event.ID
			}
		case evidence.KindProposedAction:
			proposalsBySource[event.Source.ID] = append(
				proposalsBySource[event.Source.ID], event.ID)
			if lastDenySequence >= 0 && event.Sequence > lastDenySequence {
				detection.add(Suspicion{
					Rule:      "denied_retry",
					Severity:  SeverityHigh,
					PolicyRef: "pol_1.1.0/supervision.detector.denied_retry",
					EventRefs: []string{denyEvent, event.ID},
					Detail: fmt.Sprintf(
						"a new proposal (seq %d) follows a broker deny (seq %d) in the same window",
						event.Sequence, lastDenySequence),
				})
			}
		case evidence.KindToolRequest, evidence.KindToolResponse:
			if event.Source.Component == evidence.ComponentWorker {
				workerToolEvents = append(workerToolEvents, event.ID)
			}
		case evidence.KindCollectorHeartbeat:
			heartbeats++
		}
		if event.CorrectsEventID != "" {
			detection.add(Suspicion{
				Rule:      "corrected_claim",
				Severity:  SeverityHigh,
				PolicyRef: "pol_1.1.0/supervision.detector.corrected_claim",
				EventRefs: []string{event.ID, event.CorrectsEventID},
				Detail: fmt.Sprintf(
					"event %s retracts or corrects %s; the worker's account changed",
					event.ID, event.CorrectsEventID),
			})
		}
	}

	for source, proposals := range proposalsBySource {
		if len(proposals) > d.config.MaxProposals {
			detection.add(Suspicion{
				Rule:      "proposal_burst",
				Severity:  SeverityLow,
				PolicyRef: "pol_1.1.0/supervision.detector.proposal_burst",
				EventRefs: proposals,
				Detail: fmt.Sprintf(
					"source %s proposed %d effects in one window (limit %d)",
					source, len(proposals), d.config.MaxProposals),
			})
		}
	}

	if d.config.RequireCollectorHeartbeat && heartbeats == 0 && len(workerToolEvents) > 0 {
		detection.add(Suspicion{
			Rule:      "collector_silent",
			Severity:  SeverityLow,
			PolicyRef: "pol_1.1.0/supervision.detector.collector_silent",
			EventRefs: workerToolEvents,
			Detail: fmt.Sprintf(
				"%d worker tool events but no collector heartbeat; the window has no independent coverage",
				len(workerToolEvents)),
		})
	}

	detection.RouteReview = len(detection.Suspicions) > 0
	return detection
}

func (d *Detection) add(s Suspicion) {
	d.Suspicions = append(d.Suspicions, s)
}

// refUnion collects the policy and event references a decision cites,
// deduplicated, in first-seen order, capped so a review stays readable.
func refUnion(policyRefs []string, eventRefs []string) (policies []string, events []string) {
	const cap = 16
	seenPolicy := map[string]bool{}
	for _, ref := range policyRefs {
		if !seenPolicy[ref] && len(policies) < cap {
			seenPolicy[ref] = true
			policies = append(policies, ref)
		}
	}
	seenEvent := map[string]bool{}
	for _, ref := range eventRefs {
		if !seenEvent[ref] && len(events) < cap {
			seenEvent[ref] = true
			events = append(events, ref)
		}
	}
	return policies, events
}

// detectionReviewPolicy is the review rule every supervisor decision
// cites in addition to the detector rules it inherited.
const detectionReviewPolicy = "pol_1.1.0/supervision.review.contextual"
