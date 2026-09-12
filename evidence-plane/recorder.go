package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Roles recognized by the evidence plane (spec 18.3).
const (
	RoleWorker    = "worker"
	RoleService   = "service"
	RoleCollector = "collector"
	RoleOperator  = "operator"
)

// Principal is the authenticated caller. The transport resolves it;
// a tenant in a body never overrides it.
type Principal struct {
	ID       string
	TenantID string
	Role     string
}

// Finding severities and categories used by the recorder (spec 18.1,
// 14.6). Sequence gaps and clock disagreement are evidence gaps; they
// say the record is incomplete, not that a policy was violated.
const (
	SeverityH1          = "H1"
	CategoryEvidenceGap = "evidence_gap"
	FindingStateOpen    = "open"
)

// Finding mirrors the Finding contract (shared/schemas/finding.schema
// .json) for the findings the recorder derives itself.
type Finding struct {
	Kind         string        `json:"kind"`
	APIVersion   string        `json:"api_version"`
	ID           string        `json:"id"`
	TenantID     string        `json:"tenant_id"`
	RunID        string        `json:"run_id,omitempty"`
	Category     string        `json:"category"`
	Severity     string        `json:"severity"`
	Title        string        `json:"title"`
	Description  string        `json:"description,omitempty"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
	CoverageGap  *CoverageGap  `json:"coverage_gap,omitempty"`
	State        string        `json:"state"`
	CreatedAt    string        `json:"created_at"`
}

// EvidenceRef ties a finding to the events that triggered it.
type EvidenceRef struct {
	EventID string `json:"event_id"`
	Note    string `json:"note,omitempty"`
}

// CoverageGap names what the record is missing: which source, which
// event kind was expected, and the sequence range that never arrived.
// The Finding contract requires it on every evidence_gap finding — a
// gap must say what is absent, not just that something is.
type CoverageGap struct {
	ExpectedEventKind    string `json:"expected_event_kind"`
	SourceID             string `json:"source_id"`
	ExpectedSequenceFrom int64  `json:"expected_sequence_from,omitempty"`
	ExpectedSequenceTo   int64  `json:"expected_sequence_to,omitempty"`
}

// EventOutcome is the per-event disposition inside one batch.
type EventOutcome struct {
	EventID string `json:"event_id"`
	Outcome string `json:"outcome"` // stored | duplicate
	Detail  string `json:"detail,omitempty"`
}

// SourceCheckpoint is a signed checkpoint over one source's sequence
// range at ingest time (spec 9.4). The digest covers the source's
// stored events in that range.
type SourceCheckpoint struct {
	TenantID                 string    `json:"tenant_id"`
	SourceID                 string    `json:"source_id"`
	SequenceFrom             int64     `json:"sequence_from"`
	SequenceTo               int64     `json:"sequence_to"`
	PreviousCheckpointDigest string    `json:"previous_checkpoint_digest,omitempty"`
	Digest                   string    `json:"digest"`
	Signature                Signature `json:"signature"`
	// Checkpoint embedded form, mirroring the EvidenceEvent contract's
	// checkpoint object, for collectors that re-emit it.
	Embedded Checkpoint `json:"embedded"`
}

// IngestResult is the batch reply.
type IngestResult struct {
	Accepted    int                `json:"accepted"`
	Duplicates  int                `json:"duplicates"`
	Outcomes    []EventOutcome     `json:"outcomes,omitempty"`
	Findings    []Finding          `json:"findings,omitempty"`
	ChainDigest string             `json:"chain_digest"`
	ChainLength int                `json:"chain_length"`
	Checkpoints []SourceCheckpoint `json:"checkpoints,omitempty"`
}

// VerificationReport is the integrity answer (spec 9.4: a hash chain
// detects some later modification — this is that check).
type VerificationReport struct {
	Intact             bool   `json:"intact"`
	TenantID           string `json:"tenant_id"`
	EventsChecked      int    `json:"events_checked"`
	CheckpointsChecked int    `json:"checkpoints_checked"`
	ChainDigest        string `json:"chain_digest"`
	FirstBreak         string `json:"first_break,omitempty"`
}

// storedEvent keeps the original record the chain covers, plus the
// live copy retention may tombstone.
type storedEvent struct {
	event  *Event
	live   *Event
	digest string // chain digest over the original
	prev   string
}

// sourceState tracks one source's sequence frontier per tenant.
type sourceState struct {
	last             int64
	seen             map[int64]bool
	checkpointDigest string
}

// Recorder is the authoritative evidence store (spec 9.4). State is
// per tenant: chains, sequences, findings, and checkpoints never leak
// across tenants.
type Recorder struct {
	now           func() time.Time
	skewTolerance time.Duration
	signingKey    ed25519.PrivateKey
	keyID         string

	mu          sync.Mutex
	tenants     map[string]*tenantStore
	idempotency map[string]idempotentCall
}

// tenantStore is one tenant's append-only log and derived state.
type tenantStore struct {
	tenant      string
	events      []*storedEvent
	byID        map[string]*storedEvent
	sources     map[string]*sourceState
	chainHead   string
	findings    []Finding
	checkpoints []SourceCheckpoint
}

type idempotentCall struct {
	bodyDigest string
	reply      any
	settled    bool
	ready      chan struct{}
}

// Option configures a recorder at construction.
type Option func(*Recorder)

// WithClock replaces the wall clock (tests).
func WithClock(now func() time.Time) Option {
	return func(r *Recorder) { r.now = now }
}

// WithSkewTolerance sets how far an event's observed_at may sit from
// the ingest clock before the disagreement becomes a finding.
func WithSkewTolerance(d time.Duration) Option {
	return func(r *Recorder) { r.skewTolerance = d }
}

// DefaultSkewTolerance bounds normal collector-to-recorder latency.
const DefaultSkewTolerance = 10 * time.Minute

// New builds a recorder with a fresh signing key for checkpoints.
func New(opts ...Option) *Recorder {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("ed25519 key generation failed: " + err.Error())
	}
	recorder := &Recorder{
		now:           time.Now,
		skewTolerance: DefaultSkewTolerance,
		signingKey:    private,
		keyID:         "key_" + hex.EncodeToString([]byte{public[0], public[1]}) + "-evidence-plane",
		tenants:       make(map[string]*tenantStore),
		idempotency:   make(map[string]idempotentCall),
	}
	for _, opt := range opts {
		opt(recorder)
	}
	return recorder
}

// SigningKeyID identifies the checkpoint signing key.
func (r *Recorder) SigningKeyID() string { return r.keyID }

// IngestRefusal reports why a batch was refused whole. Nothing is
// stored on refusal: a partial batch would make the replay answer lie.
type IngestRefusal struct {
	Errors []ContractError
}

func (refusal *IngestRefusal) Error() string {
	if len(refusal.Errors) == 0 {
		return "batch refused"
	}
	first := refusal.Errors[0]
	return fmt.Sprintf("batch refused: %s: %s", first.Check, first.Detail)
}

// Ingest validates and appends one batch. The batch is all-or-nothing:
// any contract violation refuses the whole batch, because a stored
// half would turn an idempotent replay into a different answer.
// Duplicates are not violations — at-least-once delivery deduplicates
// by event id (spec 18.3).
func (r *Recorder) Ingest(principal *Principal, batch *Batch) (*IngestResult, error) {
	if principal == nil {
		return nil, fmt.Errorf("unauthenticated caller cannot ingest evidence")
	}
	if batch == nil {
		return nil, &IngestRefusal{Errors: []ContractError{
			{Check: "batch", Path: "$.events", Detail: "no events in batch"},
		}}
	}

	// Contract validation and authority first, before any state moves.
	var refusals []ContractError
	for i, event := range batch.Events {
		if event == nil {
			refusals = append(refusals, ContractError{Check: "events",
				Path: fmt.Sprintf("$.events[%d]", i), Detail: "event is null"})
			continue
		}
		for _, problem := range event.ValidateEvent() {
			problem.Path = fmt.Sprintf("$.events[%d]%s", i, trimDollar(problem.Path))
			refusals = append(refusals, problem)
		}
		if event.TenantID != principal.TenantID {
			refusals = append(refusals, ContractError{Check: "tenant_id",
				Path:   fmt.Sprintf("$.events[%d].tenant_id", i),
				Detail: "the authenticated tenant owns every event in the batch",
			})
		}
		if problem := labelAuthority(principal, event); problem != nil {
			problem.Path = fmt.Sprintf("$.events[%d]%s", i, trimDollar(problem.Path))
			refusals = append(refusals, *problem)
		}
	}
	if len(refusals) > 0 {
		return nil, &IngestRefusal{Errors: refusals}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	store := r.tenantStore(principal.TenantID)
	now := r.now()
	result := &IngestResult{ChainDigest: store.chainHead, ChainLength: len(store.events)}
	var findings []Finding

	for _, event := range batch.Events {
		if _, seen := store.byID[event.ID]; seen {
			result.Duplicates++
			result.Outcomes = append(result.Outcomes, EventOutcome{
				EventID: event.ID, Outcome: "duplicate",
				Detail: "at-least-once delivery; the first copy stands",
			})
			continue
		}
		source := store.sourceState(event.Source.ID)
		// Sequence reuse under a fresh id is a contract violation, not
		// a delivery artifact: two different events claim one slot.
		if source.seen[event.Sequence] {
			return nil, &IngestRefusal{Errors: []ContractError{{
				Check: "sequence", Path: "$.sequence",
				Detail: fmt.Sprintf("source %s sequence %d already recorded under another event id",
					event.Source.ID, event.Sequence),
			}}}
		}
		ingestAt := now.UTC().Format("2006-01-02T15:04:05Z")
		stored := &storedEvent{
			event: CloneEvent(event),
			live:  CloneEvent(event),
		}
		stored.live.IngestedAt = ingestAt
		stored.event.IngestedAt = ingestAt

		// A jump past the frontier is a gap: events may have been lost.
		// A late arrival below it is out of order. Both are explicit
		// findings, never silent repairs (spec 9.4).
		if event.Sequence > source.last+1 {
			findings = append(findings, r.gapFinding(principal.TenantID, event, source))
		} else if event.Sequence < source.last {
			findings = append(findings, Finding{
				Kind: "Finding", APIVersion: "v1", ID: mintFindingID(),
				TenantID: principal.TenantID, RunID: event.RunID,
				Category: CategoryEvidenceGap, Severity: SeverityH1,
				Title: fmt.Sprintf("source %s delivered sequence %d out of order",
					event.Source.ID, event.Sequence),
				Description: fmt.Sprintf(
					"the frontier stood at %d; no global total order is assumed, so the event is stored as delivered",
					source.last),
				EvidenceRefs: []EvidenceRef{{EventID: event.ID, Note: "the late arrival"}},
				CoverageGap: &CoverageGap{
					ExpectedEventKind: event.EventKind, SourceID: event.Source.ID,
					ExpectedSequenceFrom: event.Sequence, ExpectedSequenceTo: event.Sequence,
				},
				State: FindingStateOpen, CreatedAt: ingestAt,
			})
		}
		source.seen[event.Sequence] = true
		if event.Sequence > source.last {
			source.last = event.Sequence
		}

		stored.prev = store.chainHead
		stored.digest = chainDigest(stored.event, store.chainHead)
		store.chainHead = stored.digest
		store.events = append(store.events, stored)
		store.byID[event.ID] = stored
		result.Accepted++
		result.Outcomes = append(result.Outcomes, EventOutcome{
			EventID: event.ID, Outcome: "stored",
		})

		// Clock disagreement between the source and the recorder is a
		// finding of its own (spec 9.4).
		if observed, err := time.Parse(time.RFC3339Nano, event.ObservedAt); err == nil {
			skew := now.Sub(observed)
			if skew < 0 {
				skew = -skew
			}
			if skew > r.skewTolerance {
				findings = append(findings, Finding{
					Kind: "Finding", APIVersion: "v1", ID: mintFindingID(),
					TenantID: principal.TenantID, RunID: event.RunID,
					Category: CategoryEvidenceGap, Severity: SeverityH1,
					Title: fmt.Sprintf("source %s clock disagrees with the recorder by more than %s",
						event.Source.ID, r.skewTolerance),
					Description: fmt.Sprintf(
						"observed_at %s against ingest %s; recorded uncertainty %d ms",
						event.ObservedAt, ingestAt, event.ClockUncertaintyMS),
					EvidenceRefs: []EvidenceRef{{EventID: event.ID, Note: "the skewed event"}},
					CoverageGap: &CoverageGap{
						ExpectedEventKind: event.EventKind, SourceID: event.Source.ID,
					},
					State: FindingStateOpen, CreatedAt: ingestAt,
				})
			}
		}
	}

	// One signed checkpoint per source that appears in the batch.
	checkpoints := r.checkpointSourcesLocked(store, batch)

	result.Findings = findings
	store.findings = append(store.findings, findings...)
	result.ChainDigest = store.chainHead
	result.ChainLength = len(store.events)
	result.Checkpoints = checkpoints
	store.checkpoints = append(store.checkpoints, checkpoints...)
	return result, nil
}

// checkpointSourcesLocked signs one checkpoint per source that appears
// in the batch, covering that source's contiguous range now stored.
func (r *Recorder) checkpointSourcesLocked(store *tenantStore, batch *Batch) []SourceCheckpoint {
	touched := map[string]bool{}
	for _, event := range batch.Events {
		touched[event.Source.ID] = true
	}
	ids := make([]string, 0, len(touched))
	for id := range touched {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]SourceCheckpoint, 0, len(ids))
	for _, id := range ids {
		state := store.sourceState(id)
		from, to := state.contiguousFrontier()
		if to < from {
			continue
		}
		checkpoint := SourceCheckpoint{
			TenantID:                 store.tenant,
			SourceID:                 id,
			SequenceFrom:             from,
			SequenceTo:               to,
			PreviousCheckpointDigest: state.checkpointDigest,
		}
		checkpoint.Digest = r.sign(&checkpoint)
		state.checkpointDigest = checkpoint.Digest
		out = append(out, checkpoint)
	}
	return out
}

// contiguousFrontier returns the widest contiguous range this source
// has stored. A checkpoint never claims coverage over a gap: signing
// [from, to] asserts every sequence in between is present.
func (s *sourceState) contiguousFrontier() (from, to int64) {
	if len(s.seen) == 0 {
		return 0, -1
	}
	from = s.last
	for seq := range s.seen {
		if seq < from {
			from = seq
		}
	}
	to = from
	for s.seen[to+1] {
		to++
	}
	return from, to
}

// sign computes the checkpoint digest and its detached signature.
func (r *Recorder) sign(checkpoint *SourceCheckpoint) string {
	basis := map[string]any{
		"key_id": r.keyID, "tenant_id": checkpoint.TenantID,
		"source_id":     checkpoint.SourceID,
		"sequence_from": checkpoint.SequenceFrom, "sequence_to": checkpoint.SequenceTo,
	}
	if checkpoint.PreviousCheckpointDigest != "" {
		basis["previous_checkpoint_digest"] = checkpoint.PreviousCheckpointDigest
	}
	encoded, _ := json.Marshal(basis)
	sum := sha256.Sum256(encoded)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	checkpoint.Signature = Signature{
		Algorithm: "ed25519",
		KeyID:     r.keyID,
		Value: base64.StdEncoding.EncodeToString(
			ed25519.Sign(r.signingKey, []byte(digest))),
	}
	checkpoint.Embedded = Checkpoint{
		SequenceFrom: checkpoint.SequenceFrom, SequenceTo: checkpoint.SequenceTo,
		PreviousCheckpointDigest: checkpoint.PreviousCheckpointDigest,
		Digest:                   digest, Signature: checkpoint.Signature,
	}
	return digest
}

// gapFinding records the missing sequence range explicitly. The kinds
// of the lost events are unknowable; expected_event_kind carries the
// stream's kind — the kind the source was recording when it skipped.
func (r *Recorder) gapFinding(tenantID string, event *Event, source *sourceState) Finding {
	ingestAt := r.now().UTC().Format("2006-01-02T15:04:05Z")
	return Finding{
		Kind: "Finding", APIVersion: "v1", ID: mintFindingID(),
		TenantID: tenantID, RunID: event.RunID,
		Category: CategoryEvidenceGap, Severity: SeverityH1,
		Title: fmt.Sprintf("source %s skipped sequences %d to %d",
			event.Source.ID, source.last+1, event.Sequence-1),
		Description: "events may have been lost between the collector and the recorder; " +
			"a hash chain detects later modification, not missing capture",
		EvidenceRefs: []EvidenceRef{{EventID: event.ID, Note: "the event that revealed the gap"}},
		CoverageGap: &CoverageGap{
			ExpectedEventKind: event.EventKind, SourceID: event.Source.ID,
			ExpectedSequenceFrom: source.last + 1, ExpectedSequenceTo: event.Sequence - 1,
		},
		State: FindingStateOpen, CreatedAt: ingestAt,
	}
}

// labelAuthority checks the caller's role against each event's trust
// label (spec 18.3: worker identities cannot ingest authoritative
// collector events). Collector facts require the collector role;
// monitor interpretations come from supervisor-system callers; worker
// claims are open to any authenticated role.
func labelAuthority(principal *Principal, event *Event) *ContractError {
	switch event.TrustLabel {
	case TrustCollectorFact:
		if principal.Role != RoleCollector {
			return &ContractError{Check: "trust_label", Path: "$.trust_label",
				Detail: "only a collector identity may record a collector fact"}
		}
	case TrustMonitorReading:
		switch principal.Role {
		case RoleCollector, RoleService, RoleOperator:
		default:
			return &ContractError{Check: "trust_label", Path: "$.trust_label",
				Detail: "a monitor interpretation comes from a monitor, collector, service, or operator"}
		}
	case TrustWorkerClaim:
		// Any authenticated role may submit a claim; the label itself
		// marks it as the worker's account, lower-trust by definition.
	}
	return nil
}

// Verify recomputes the whole tenant chain and re-verifies every
// checkpoint signature (spec 9.4). A modified or removed event breaks
// the chain; a re-signed checkpoint that does not verify breaks too.
func (r *Recorder) Verify(principal *Principal) (*VerificationReport, error) {
	if principal == nil {
		return nil, fmt.Errorf("unauthenticated caller cannot verify evidence")
	}
	if err := checkReader(principal); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	store, ok := r.tenants[principal.TenantID]
	if !ok {
		return &VerificationReport{Intact: true, TenantID: principal.TenantID}, nil
	}
	report := &VerificationReport{TenantID: principal.TenantID}
	prev := ""
	for _, stored := range store.events {
		report.EventsChecked++
		if stored.prev != prev {
			report.FirstBreak = fmt.Sprintf("event %s breaks the chain at position %d",
				stored.event.ID, report.EventsChecked-1)
			return report, nil
		}
		if chainDigest(stored.event, prev) != stored.digest {
			report.FirstBreak = fmt.Sprintf("event %s content changed after storage",
				stored.event.ID)
			return report, nil
		}
		prev = stored.digest
	}
	for i := range store.checkpoints {
		report.CheckpointsChecked++
		if !r.verifyCheckpoint(&store.checkpoints[i]) {
			report.FirstBreak = fmt.Sprintf("checkpoint %d for source %s fails verification",
				i, store.checkpoints[i].SourceID)
			return report, nil
		}
	}
	report.Intact = true
	report.ChainDigest = prev
	return report, nil
}

// verifyCheckpoint recomputes the digest basis and checks the
// detached signature.
func (r *Recorder) verifyCheckpoint(checkpoint *SourceCheckpoint) bool {
	basis := map[string]any{
		"key_id": checkpoint.Signature.KeyID, "tenant_id": checkpoint.TenantID,
		"source_id":     checkpoint.SourceID,
		"sequence_from": checkpoint.SequenceFrom, "sequence_to": checkpoint.SequenceTo,
	}
	if checkpoint.PreviousCheckpointDigest != "" {
		basis["previous_checkpoint_digest"] = checkpoint.PreviousCheckpointDigest
	}
	encoded, _ := json.Marshal(basis)
	sum := sha256.Sum256(encoded)
	if "sha256:"+hex.EncodeToString(sum[:]) != checkpoint.Digest {
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(checkpoint.Signature.Value)
	if err != nil {
		return false
	}
	public := r.signingKey.Public().(ed25519.PublicKey)
	return ed25519.Verify(public, []byte(checkpoint.Digest), signature)
}

// Events lists a tenant's stored events, newest last. Any run filter
// narrows to that run. Readers receive the live copies, whose payloads
// retention may have tombstoned.
func (r *Recorder) Events(principal *Principal, runID string) ([]*Event, error) {
	if err := checkReader(principal); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	store, ok := r.tenants[principal.TenantID]
	if !ok {
		return []*Event{}, nil
	}
	out := []*Event{}
	for _, stored := range store.events {
		if runID != "" && stored.live.RunID != runID {
			continue
		}
		out = append(out, CloneEvent(stored.live))
	}
	return out, nil
}

// Findings lists a tenant's derived findings.
func (r *Recorder) Findings(principal *Principal) ([]Finding, error) {
	if err := checkReader(principal); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	store, ok := r.tenants[principal.TenantID]
	if !ok {
		return []Finding{}, nil
	}
	out := make([]Finding, len(store.findings))
	copy(out, store.findings)
	return out, nil
}

// Chain reports the tenant's chain head and event count.
func (r *Recorder) Chain(principal *Principal) (digest string, length int, err error) {
	if err := checkReader(principal); err != nil {
		return "", 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	store, ok := r.tenants[principal.TenantID]
	if !ok {
		return "", 0, nil
	}
	return store.chainHead, len(store.events), nil
}

// ApplyRetention tombstones object payloads older than the horizon
// (spec 9.4 retention, spec 19). Only the live copies change; the
// chained originals keep the captured bytes, so verification still
// proves what was stored. Metadata-only and inline events have
// nothing to delete. A tombstoned reference keeps its digest: the
// evidence names what existed even after the object is gone.
func (r *Recorder) ApplyRetention(principal *Principal, olderThan time.Duration) (tombstoned int, err error) {
	if err := checkReader(principal); err != nil {
		return 0, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	store, ok := r.tenants[principal.TenantID]
	if !ok {
		return 0, nil
	}
	horizon := r.now().Add(-olderThan)
	for _, stored := range store.events {
		if stored.live.Payload.Kind != PayloadObjectRef || stored.live.Payload.Tombstone {
			continue
		}
		observed, perr := time.Parse(time.RFC3339Nano, stored.live.ObservedAt)
		if perr != nil || !observed.Before(horizon) {
			continue
		}
		stored.live.Payload.Tombstone = true
		tombstoned++
	}
	return tombstoned, nil
}

// checkReader gates read access: the evidence store serves
// supervisor-system roles, not workers. Workers see evidence through
// the control plane, not the authoritative store.
func checkReader(principal *Principal) error {
	if principal == nil {
		return fmt.Errorf("unauthenticated caller")
	}
	switch principal.Role {
	case RoleService, RoleOperator, RoleCollector:
		return nil
	default:
		return fmt.Errorf("role %s cannot read the evidence store", principal.Role)
	}
}

func (r *Recorder) tenantStore(tenantID string) *tenantStore {
	store, ok := r.tenants[tenantID]
	if !ok {
		store = &tenantStore{
			tenant:  tenantID,
			byID:    make(map[string]*storedEvent),
			sources: make(map[string]*sourceState),
		}
		r.tenants[tenantID] = store
	}
	return store
}

func (s *tenantStore) sourceState(sourceID string) *sourceState {
	state, ok := s.sources[sourceID]
	if !ok {
		state = &sourceState{seen: make(map[int64]bool), last: -1}
		s.sources[sourceID] = state
	}
	return state
}

// chainDigest hashes the event's canonical bytes onto the chain.
func chainDigest(event *Event, prev string) string {
	basis := append(event.canonicalBytes(), []byte("\n"+prev)...)
	sum := sha256.Sum256(basis)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func mintFindingID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return "fnd_" + hex.EncodeToString(raw)
}

func trimDollar(path string) string {
	if len(path) > 1 && path[0] == '$' {
		return path[1:]
	}
	return path
}

// ledgerKey scopes an idempotency key to a tenant (spec 18.3).
func ledgerKey(tenantID, key string) string {
	return tenantID + "\x00" + key
}

// idempotencyWait bounds how long a request waits for a concurrent
// request that reserved the same idempotency key.
const idempotencyWait = 10 * time.Second

// Reserve enforces the mutation contract: the first caller of a
// (tenant, key) reserves it, identical reuse replays the first reply,
// and reuse with a different body conflicts.
func (r *Recorder) Reserve(tenantID, key, bodyDigest string) (reply any, replay bool, err error) {
	scoped := ledgerKey(tenantID, key)
	r.mu.Lock()
	previous, seen := r.idempotency[scoped]
	if !seen {
		r.idempotency[scoped] = idempotentCall{
			bodyDigest: bodyDigest, ready: make(chan struct{}),
		}
		r.mu.Unlock()
		return nil, false, nil
	}
	r.mu.Unlock()
	if previous.bodyDigest != bodyDigest {
		return nil, true, errIdempotencyConflict
	}
	select {
	case <-previous.ready:
	case <-time.After(idempotencyWait):
		return nil, true, errIdempotencyPending
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	settled := r.idempotency[scoped]
	if settled.bodyDigest == bodyDigest && settled.settled {
		return settled.reply, true, nil
	}
	return nil, false, nil
}

// Complete stores the reply for a reserved key and wakes waiters.
func (r *Recorder) Complete(tenantID, key, bodyDigest string, reply any) {
	scoped := ledgerKey(tenantID, key)
	r.mu.Lock()
	defer r.mu.Unlock()
	if call, seen := r.idempotency[scoped]; seen && call.bodyDigest == bodyDigest && !call.settled {
		call.reply = reply
		call.settled = true
		r.idempotency[scoped] = call
		close(call.ready)
	}
}

// Release drops a pending reservation after a failed execution.
func (r *Recorder) Release(tenantID, key, bodyDigest string) {
	scoped := ledgerKey(tenantID, key)
	r.mu.Lock()
	defer r.mu.Unlock()
	if call, seen := r.idempotency[scoped]; seen && call.bodyDigest == bodyDigest && !call.settled {
		delete(r.idempotency, scoped)
		close(call.ready)
	}
}

var (
	errIdempotencyConflict = fmt.Errorf("idempotency key reused with a different body")
	errIdempotencyPending  = fmt.Errorf("idempotency key still executing; retry")
)
