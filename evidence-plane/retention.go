package evidence

import (
	"fmt"
	"time"
)

// Retention windows and legal holds (spec 19, T037). Retention
// reconciles with append-only evidence through tombstones: the
// chained originals never change — verification keeps proving what
// was captured — while the live copies readers see lose the expired
// bytes. Aggregate or redacted claims (the 180-day tier) live in the
// control plane, not in this store.

// Product defaults from spec 19. These are defaults, not legal
// retention advice; deployments may shorten or extend them within
// deployment policy.
const (
	DefaultRawPayloadRetention    = 7 * 24 * time.Hour
	DefaultDetailedEventRetention = 30 * 24 * time.Hour
)

// RetentionPolicy names the two windows this store enforces.
type RetentionPolicy struct {
	// RawPayloads bounds object storage references: past the window
	// the reference is tombstoned (payload deletion). The tombstone
	// keeps the digest — the evidence names what existed.
	RawPayloads time.Duration
	// DetailedEvents bounds inline content: past the window the live
	// copy downgrades to a metadata-only reference with no content.
	DetailedEvents time.Duration
}

// DefaultRetentionPolicy is the spec 19 product default.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		RawPayloads:    DefaultRawPayloadRetention,
		DetailedEvents: DefaultDetailedEventRetention,
	}
}

// LegalHold freezes retention for one run. Held events are skipped
// by every retention pass until the hold is released or expires.
type LegalHold struct {
	RunID   string    `json:"run_id"`
	Reason  string    `json:"reason"`
	HeldBy  string    `json:"held_by"`
	HeldAt  time.Time `json:"held_at"`
	Expires time.Time `json:"expires,omitempty"`
}

// RetentionOutcome reports what one retention pass did.
type RetentionOutcome struct {
	// ObjectRefsTombstoned counts object references whose payload
	// window lapsed and whose bytes are now deleted from the live
	// view.
	ObjectRefsTombstoned int
	// InlineDowngraded counts inline payloads downgraded to
	// metadata-only because the detailed-event window lapsed.
	InlineDowngraded int
	// Held counts events skipped because their run is under an
	// active legal hold. Held content does not expire.
	Held int
}

// SetLegalHold freezes retention for one run. A hold without a
// reason is refused: an unexplained freeze on an append-only record
// is exactly what the audit trail must be able to explain.
func (r *Recorder) SetLegalHold(principal *Principal, runID, reason string,
	expires time.Time) error {
	if err := checkRetentionAuthority(principal); err != nil {
		return err
	}
	if !reRunID.MatchString(runID) {
		return fmt.Errorf("run id %q is not a run_ id", runID)
	}
	if reason == "" {
		return fmt.Errorf("a legal hold needs a reason")
	}
	if !expires.IsZero() && !expires.After(r.now()) {
		return fmt.Errorf("a hold cannot expire in the past")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	store := r.tenantStore(principal.TenantID)
	if store.holds == nil {
		store.holds = make(map[string]LegalHold)
	}
	store.holds[runID] = LegalHold{
		RunID:   runID,
		Reason:  reason,
		HeldBy:  principal.Actor(),
		HeldAt:  r.now(),
		Expires: expires,
	}
	return nil
}

// ReleaseLegalHold lifts a hold. Released runs expire on the next
// retention pass.
func (r *Recorder) ReleaseLegalHold(principal *Principal, runID string) error {
	if err := checkRetentionAuthority(principal); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	store, ok := r.tenants[principal.TenantID]
	if !ok {
		return nil
	}
	delete(store.holds, runID)
	return nil
}

// LegalHolds lists the active holds for the caller's tenant. Expired
// holds are reported as absent; they no longer protect content.
func (r *Recorder) LegalHolds(principal *Principal) ([]LegalHold, error) {
	if err := checkReader(principal); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	store, ok := r.tenants[principal.TenantID]
	if !ok {
		return nil, nil
	}
	now := r.now()
	var holds []LegalHold
	for _, hold := range store.holds {
		if !hold.Expires.IsZero() && !hold.Expires.After(now) {
			continue
		}
		holds = append(holds, hold)
	}
	return holds, nil
}

// ApplyRetentionPolicy runs one retention pass. Tombstones and
// downgrades touch only the live copies; the chain and the chained
// originals are untouched, so Verify keeps proving what was stored.
func (r *Recorder) ApplyRetentionPolicy(principal *Principal,
	policy RetentionPolicy) (RetentionOutcome, error) {
	outcome := RetentionOutcome{}
	if err := checkRetentionAuthority(principal); err != nil {
		return outcome, err
	}
	if policy.RawPayloads <= 0 || policy.DetailedEvents <= 0 {
		return outcome, fmt.Errorf(
			"retention windows must be positive; refusing to run a pass that would delete everything")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	store, ok := r.tenants[principal.TenantID]
	if !ok {
		return outcome, nil
	}
	now := r.now()
	rawHorizon := now.Add(-policy.RawPayloads)
	detailedHorizon := now.Add(-policy.DetailedEvents)
	for _, stored := range store.events {
		if held(stored.live, store.holds, now) {
			outcome.Held++
			continue
		}
		observed, err := time.Parse(time.RFC3339Nano,
			stored.live.ObservedAt)
		if err != nil {
			continue
		}
		payload := stored.live.Payload
		switch {
		case payload.Kind == PayloadObjectRef &&
			!payload.Tombstone && observed.Before(rawHorizon):
			// Payload deletion: the digest stays on the tombstone —
			// the event keeps naming what existed — and the chained
			// original keeps the full reference for verification.
			stored.live.Payload.Tombstone = true
			outcome.ObjectRefsTombstoned++
		case payload.Kind == PayloadInline && payload.Content != "" &&
			observed.Before(detailedHorizon):
			// Downgrade to metadata-only: no content, no size, the
			// redaction flag set so readers see that bytes existed
			// and are gone.
			stored.live.Payload = EventPayload{
				Kind:     PayloadMetadataOnly,
				Redacted: true,
			}
			outcome.InlineDowngraded++
		}
	}
	return outcome, nil
}

// held reports whether an event's run sits under an active hold.
func held(event *Event, holds map[string]LegalHold,
	now time.Time) bool {
	hold, ok := holds[event.RunID]
	if !ok {
		return false
	}
	if !hold.Expires.IsZero() && !hold.Expires.After(now) {
		return false
	}
	return true
}

// checkRetentionAuthority gates retention mutations to operators and
// the supervisor system. Collectors read and write events; they do
// not decide what the deployment must keep.
func checkRetentionAuthority(principal *Principal) error {
	if principal == nil {
		return fmt.Errorf("unauthenticated caller")
	}
	switch principal.Role {
	case RoleOperator, RoleService:
		return nil
	default:
		return fmt.Errorf(
			"role %s cannot change retention or holds", principal.Role)
	}
}
