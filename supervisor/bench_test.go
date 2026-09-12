package supervisor

import (
	"context"
	"testing"
	"time"

	"gauntlet/broker"
)

// Benchmarks for the contextual reviewer targets (T043, spec 21): the
// default three-second decision deadline with a hold fallback, and
// the deterministic reviewer's decision latency that cheap profiles
// pay per gated proposal.

// BenchmarkReferenceReviewDecision measures the deterministic
// reference reviewer's fast path: decisions per second available to a
// profile that needs no model call.
func BenchmarkReferenceReviewDecision(b *testing.B) {
	reviewer := NewReferenceReviewer()
	task := ReviewTask{
		Proposal:     proposal(),
		Purpose:      "close issue #7",
		RecentEvents: cleanWindow(),
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		review, err := reviewer.Review(ctx, task)
		if err != nil {
			b.Fatal(err)
		}
		if problems := review.ValidateReview(); len(problems) != 0 {
			b.Fatalf("review left the contract: %+v", problems)
		}
	}
}

// slowReviewer never answers in time: it simulates a reviewer whose
// model call outlives the deadline.
type slowReviewer struct {
	delay time.Duration
}

func (s slowReviewer) Review(_ context.Context,
	_ ReviewTask) (broker.Review, error) {
	time.Sleep(s.delay)
	return broker.Review{}, nil
}

// BenchmarkDeadlineFallbackEnforcement measures the deadline machinery
// itself: with a five-millisecond deadline over a reviewer that would
// take ten times longer, every decision must land at the deadline
// with the profile's hold fallback — never a silent allow and never a
// hang waiting for the model.
func BenchmarkDeadlineFallbackEnforcement(b *testing.B) {
	policy := DefaultReviewPolicy()
	policy.Deadline = 5 * time.Millisecond
	reviewer := NewDeadlineReviewer(slowReviewer{delay: 50 * time.Millisecond},
		policy)
	task := ReviewTask{
		Proposal:     proposal(),
		Purpose:      "close issue #7",
		RecentEvents: cleanWindow(),
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		review, err := reviewer.Review(ctx, task)
		if err == nil && review.Verdict == broker.ReviewAllow {
			b.Fatal("a timed-out review allowed an effect")
		}
	}
	b.StopTimer()
	b.ReportMetric(DefaultDeadline.Seconds(), "default-deadline-s")
}
