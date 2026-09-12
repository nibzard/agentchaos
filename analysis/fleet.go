// Fleet trajectory analysis (T050, spec 10.1, AC-030).
//
// The fleet analyzer is the P1 review layer that works across
// sessions: it reads cross-session metadata and identities and finds
// shared-resource and campaign patterns — runs that communicate
// through the same delegation identity, the same artifact, the same
// correlation id, or direct event lineage.
//
// The package computes; it never judges. A pattern is a set of cited
// edges between runs, not a verdict about intent. Every edge carries
// the event ids it was built from, so a reviewer can walk any finding
// back to the authoritative records (AC-030: patterns found with
// provenance). Edges built from worker claims are marked as such;
// worker transcripts are lower-trust evidence (spec 9.4).
//
// Tenant isolation is structural: one analysis covers exactly one
// tenant. Input that mixes tenants is refused whole, so no cross-
// tenant edge can ever be constructed here.
package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Edge kinds: the metadata surfaces two runs can share.
const (
	EdgeSharedDelegation = "shared_delegation"
	EdgeSharedArtifact   = "shared_artifact"
	EdgeSharedCorrelation = "shared_correlation"
	EdgeCrossRunLineage  = "cross_run_lineage"
)

// FleetEvent is the metadata the analyzer reads. The JSON tags mirror
// the EvidenceEvent contract (shared/schemas/evidence-event.schema
// .json), so authoritative evidence events unmarshal into it as-is;
// raw payloads never enter the analyzer, only their digests and
// storage references (spec 19: minimized capture).
type FleetEvent struct {
	TenantID       string       `json:"tenant_id"`
	RunID          string       `json:"run_id"`
	ID             string       `json:"id"`
	EventKind      string       `json:"event_kind"`
	TrustLabel     string       `json:"trust_label"`
	Source         FleetSource  `json:"source"`
	Sequence       int64        `json:"sequence"`
	ObservedAt     string       `json:"observed_at"`
	DelegationID   string       `json:"delegation_id,omitempty"`
	CorrelationIDs []string     `json:"correlation_ids,omitempty"`
	ParentEventIDs []string     `json:"parent_event_ids,omitempty"`
	Payload        FleetPayload `json:"payload"`
}

// FleetSource carries only the component; identities of collectors
// stay out of the analysis surface.
type FleetSource struct {
	Component string `json:"component"`
}

// FleetPayload is the closed payload reference of the evidence
// contract: kind plus the digest and storage reference. No content.
type FleetPayload struct {
	Kind       string `json:"kind"`
	Digest     string `json:"digest,omitempty"`
	StorageRef string `json:"storage_ref,omitempty"`
}

// FleetEdge is one observed link between two runs. Key is the shared
// identity (delegation id, digest, storage reference, correlation id,
// or the parent event id for lineage). Events cites every event id
// the edge was built from, sorted; TrustLabels records which labels
// those events carried.
type FleetEdge struct {
	Kind        string   `json:"kind"`
	Key         string   `json:"key"`
	Runs        []string `json:"runs"`
	Events      []string `json:"events"`
	TrustLabels []string `json:"trust_labels"`
}

// FleetPattern is a connected group of runs plus the edges that
// connect them. Runs outside any edge never appear.
type FleetPattern struct {
	PatternID string      `json:"pattern_id"`
	Kind      string      `json:"kind"`
	Runs      []string    `json:"runs"`
	Edges     []FleetEdge `json:"edges"`
}

// FleetReport is the analyzer's output: the scope it read, what it
// deduplicated, and every cross-run pattern with provenance.
type FleetReport struct {
	Kind          string         `json:"kind"`
	APIVersion    string         `json:"api_version"`
	TenantID      string         `json:"tenant_id"`
	Runs          int            `json:"runs"`
	Events        int            `json:"events"`
	Deduplicated  int            `json:"deduplicated"`
	Patterns      []FleetPattern `json:"patterns"`
	Scope         string         `json:"scope"`
}

// ScopeNote travels with every report: patterns route review, they
// are not verdicts.
const fleetScopeNote = (
	"cross-session metadata patterns for one tenant; a pattern cites " +
		"its events and routes review, it is not a verdict about intent")

// FleetError reports refused input. The analyzer fails closed: mixed
// tenants or malformed events produce no report at all.
type FleetError struct{ Detail string }

func (e *FleetError) Error() string {
	return "fleet analysis refused: " + e.Detail
}

// AnalyzeFleet finds cross-run communication patterns in one tenant's
// event metadata. Delivery is at-least-once, so duplicate event ids
// are dropped and counted, never double-linked.
func AnalyzeFleet(events []FleetEvent) (*FleetReport, error) {
	if len(events) == 0 {
		return nil, &FleetError{"no events"}
	}
	seen := make(map[string]bool, len(events))
	unique := make([]FleetEvent, 0, len(events))
	for _, event := range events {
		if event.ID == "" || event.RunID == "" {
			return nil, &FleetError{fmt.Sprintf(
				"event with empty id or run id: %+v", event.ID)}
		}
		if seen[event.ID] {
			continue
		}
		seen[event.ID] = true
		unique = append(unique, event)
	}
	tenant := unique[0].TenantID
	for _, event := range unique[1:] {
		if event.TenantID != tenant {
			return nil, &FleetError{fmt.Sprintf(
				"events mix tenants %q and %q; one analysis covers " +
					"exactly one tenant", tenant, event.TenantID)}
		}
	}
	if tenant == "" {
		return nil, &FleetError{"events carry no tenant id"}
	}

	runs := make(map[string]bool)
	eventsByID := make(map[string]FleetEvent, len(unique))
	for _, event := range unique {
		runs[event.RunID] = true
		eventsByID[event.ID] = event
	}

	edges := fleetEdges(unique, eventsByID)
	patterns := fleetPatterns(edges)

	return &FleetReport{
		Kind:         "FleetReport",
		APIVersion:   "v1",
		TenantID:     tenant,
		Runs:         len(runs),
		Events:       len(unique),
		Deduplicated: len(events) - len(unique),
		Patterns:     patterns,
		Scope:        fleetScopeNote,
	}, nil
}

// fleetEdges builds every cross-run edge. Each shared-key group
// contributes one edge per unordered run pair it links.
func fleetEdges(events []FleetEvent, byID map[string]FleetEvent) []FleetEdge {
	// key -> run -> contributing event ids and trust labels
	type group struct {
		runs   map[string][]string
		labels map[string]bool
	}
	newGroup := func() *group {
		return &group{runs: map[string][]string{}, labels: map[string]bool{}}
	}
	groups := map[string]*group{}

	add := func(kind, key, run, eventID, trust string) {
		id := kind + "\x00" + key
		g := groups[id]
		if g == nil {
			g = newGroup()
			groups[id] = g
		}
		g.runs[run] = append(g.runs[run], eventID)
		g.labels[trust] = true
	}

	for _, event := range events {
		if event.DelegationID != "" {
			add(EdgeSharedDelegation, event.DelegationID,
				event.RunID, event.ID, event.TrustLabel)
		}
		if event.Payload.Digest != "" {
			add(EdgeSharedArtifact, event.Payload.Digest,
				event.RunID, event.ID, event.TrustLabel)
		}
		if event.Payload.StorageRef != "" {
			add(EdgeSharedArtifact, event.Payload.StorageRef,
				event.RunID, event.ID, event.TrustLabel)
		}
		for _, correlation := range event.CorrelationIDs {
			if correlation != "" {
				add(EdgeSharedCorrelation, correlation,
					event.RunID, event.ID, event.TrustLabel)
			}
		}
		for _, parent := range event.ParentEventIDs {
			if parent == "" {
				continue
			}
			origin, ok := byID[parent]
			if ok && origin.RunID != event.RunID {
				add(EdgeCrossRunLineage, parent,
					event.RunID, event.ID, event.TrustLabel)
				// The parent is evidence too; cite it on its own run.
				add(EdgeCrossRunLineage, parent,
					origin.RunID, origin.ID, origin.TrustLabel)
			}
		}
	}

	edges := make([]FleetEdge, 0, len(groups))
	for id, g := range groups {
		runIDs := make([]string, 0, len(g.runs))
		for run := range g.runs {
			runIDs = append(runIDs, run)
		}
		if len(runIDs) < 2 {
			// A key inside one run links nothing.
			continue
		}
		sort.Strings(runIDs)
		parts := strings.SplitN(id, "\x00", 2)
		cited := make([]string, 0)
		for _, run := range runIDs {
			cited = append(cited, g.runs[run]...)
		}
		sort.Strings(cited)
		labels := make([]string, 0, len(g.labels))
		for label := range g.labels {
			labels = append(labels, label)
		}
		sort.Strings(labels)
		edges = append(edges, FleetEdge{
			Kind:        parts[0],
			Key:         parts[1],
			Runs:        runIDs,
			Events:      cited,
			TrustLabels: labels,
		})
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Kind != edges[j].Kind {
			return edges[i].Kind < edges[j].Kind
		}
		return edges[i].Key < edges[j].Key
	})
	return edges
}

// fleetPatterns groups runs into connected components over the edges.
// A component of two or more runs is a pattern; singleton keys and
// untouched runs never appear.
func fleetPatterns(edges []FleetEdge) []FleetPattern {
	parent := map[string]string{}
	find := func(x string) string {
		for {
			root, ok := parent[x]
			if !ok || root == x {
				parent[x] = x
				return x
			}
			x = root
		}
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}
	runSet := map[string]bool{}
	for _, edge := range edges {
		for _, run := range edge.Runs {
			runSet[run] = true
		}
		for _, run := range edge.Runs[1:] {
			union(edge.Runs[0], run)
		}
	}

	members := map[string][]string{}
	for run := range runSet {
		root := find(run)
		members[root] = append(members[root], run)
	}

	patterns := make([]FleetPattern, 0, len(members))
	for _, runs := range members {
		if len(runs) < 2 {
			continue
		}
		sort.Strings(runs)
		in := map[string]bool{}
		for _, run := range runs {
			in[run] = true
		}
		component := make([]FleetEdge, 0)
		for _, edge := range edges {
			if in[edge.Runs[0]] {
				component = append(component, edge)
			}
		}
		patterns = append(patterns, FleetPattern{
			PatternID: fleetPatternID(component),
			Kind:      "cross_run_communication",
			Runs:      runs,
			Edges:     component,
		})
	}
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].PatternID < patterns[j].PatternID
	})
	if patterns == nil {
		patterns = []FleetPattern{}
	}
	return patterns
}

// fleetPatternID is deterministic over the component's identity: the
// same edges always produce the same id.
func fleetPatternID(edges []FleetEdge) string {
	parts := make([]string, 0, len(edges))
	for _, edge := range edges {
		parts = append(parts, edge.Kind+":"+edge.Key)
	}
	sort.Strings(parts)
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return "ftp_" + hex.EncodeToString(digest[:])[:16]
}

// AssertFleetProvenance checks that every cited event id exists in
// the analyzed input. A report whose provenance dangles is worthless;
// this check lets a consumer refuse one without re-running analysis.
func AssertFleetProvenance(report *FleetReport, events []FleetEvent) error {
	known := make(map[string]bool, len(events))
	for _, event := range events {
		known[event.ID] = true
	}
	for _, pattern := range report.Patterns {
		for _, edge := range pattern.Edges {
			for _, id := range edge.Events {
				if !known[id] {
					return errors.New(
						"fleet provenance dangles: edge " + edge.Kind +
							" key " + edge.Key + " cites unknown event " + id)
				}
			}
		}
	}
	return nil
}
