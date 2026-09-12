package supervisor

import (
	"context"

	"gauntlet/broker"
	"gauntlet/evidence"
)

// Supervisor ties the two review layers together for one proposal:
// the fast detector decides whether the effect needs a contextual
// review, and the reviewer decides it under the profile's deadline
// and fallback (spec 11.1, T018). The broker's deterministic gate
// stays in front — a supervisor decision can only attach to an
// effect the gate already held for review.
type Supervisor struct {
	Detector *FastDetector
	Reviewer ContextualReviewer
}

// New builds a Supervisor from the default detector and any
// contextual reviewer.
func New(reviewer ContextualReviewer) *Supervisor {
	return &Supervisor{Detector: NewFastDetector(DefaultDetectorConfig()), Reviewer: reviewer}
}

// Consider runs the layers for one proposal over the run's recent
// evidence. When the detector routes review, the reviewer's decision
// comes back ready to attach with AttachReview. When it does not,
// Review is the zero value and the caller attaches nothing: the
// deterministic gate alone decides the effect.
func (s *Supervisor) Consider(
	ctx context.Context,
	proposal broker.ProposedAction,
	purpose string,
	events []evidence.Event,
) (broker.Review, Detection, error) {
	detection := s.Detector.Detect(events)
	if !detection.RouteReview {
		return broker.Review{}, detection, nil
	}
	review, err := s.Reviewer.Review(ctx, ReviewTask{
		Proposal:     proposal,
		Purpose:      purpose,
		Detection:    detection,
		RecentEvents: events,
	})
	if err != nil {
		return broker.Review{}, detection, err
	}
	return review, detection, nil
}
