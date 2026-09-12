package supervisor

// Random sentinel audit sampling (spec 15.1 / T024). A nonzero uniform
// random sample of clean traffic receives deep evidence review even
// when every detector says clean. Risk-routed review is additional and
// never a substitute: the sentinel draw runs only over the clean units
// and never shrinks because risk routing already caught some.
//
// The draw is deterministic given the randomization key, the epoch,
// and the unit id: an audit can reproduce every inclusion decision
// without having watched the traffic. The key never leaves the
// sampler — records carry its key id only, so a worker cannot compute
// its own way into or out of the sample.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

// Sampling units (spec 15.1): per attempt by default, or by task
// group / deployment cluster where dependence makes per-attempt
// sampling the wrong unit.
const (
	SampleByUnit    = "unit"
	SampleByCluster = "cluster"
)

// DefaultSentinelRate is the 1% design default (spec 15.1). An
// operational hypothesis, not a demonstration of four-nines assurance.
const DefaultSentinelRate = 0.01

// SentinelConfig bounds a sampler. Rate must be nonzero: a sampler
// that can select nothing violates the nonzero-sample rule, so a zero
// rate refuses construction.
type SentinelConfig struct {
	Rate float64
	// SampleBy switches the sampling unit: every unit of a selected
	// cluster is in when SampleByCluster (cluster sampling for
	// dependent outcomes). Empty means SampleByUnit.
	SampleBy string
	// Epoch rotates the draw (a review period). Units keep one stable
	// decision within an epoch no matter when they arrive.
	Epoch string
}

// ReviewUnit is one candidate for deep review. RiskRouted units
// already receive deep review through triggered review; they are not
// part of the uniform draw.
type ReviewUnit struct {
	ID         string
	ClusterID  string
	RiskRouted bool
}

// Selection methods.
const (
	MethodSentinel   = "sentinel"
	MethodRiskRouted = "risk_routed"
	MethodNone       = "none"
)

// Selection is one unit's deep-review allocation.
type Selection struct {
	UnitID               string  `json:"unit_id"`
	ClusterID            string  `json:"cluster_id,omitempty"`
	DeepReview           bool    `json:"deep_review"`
	Method               string  `json:"method"`
	InclusionProbability float64 `json:"inclusion_probability"`
	KeyID                string  `json:"key_id"`
	Epoch                string  `json:"epoch"`
}

// SentinelSummary reports what a draw did, including the sampling
// design an auditor needs to re-derive it.
type SentinelSummary struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"api_version"`
	Units      int    `json:"units"`
	// CleanConsidered is the uniform sample's denominator: units with
	// no risk routing.
	CleanConsidered int     `json:"clean_considered"`
	Sentinels       int     `json:"sentinels"`
	RiskRouted      int     `json:"risk_routed"`
	Rate            float64 `json:"rate"`
	SampleBy        string  `json:"sample_by"`
	Epoch           string  `json:"epoch"`
	KeyID           string  `json:"key_id"`
}

// SentinelSampler assigns deep review uniformly at random over clean
// traffic, holding the randomization key outside worker access.
type SentinelSampler struct {
	rate     float64
	sampleBy string
	epoch    string
	key      []byte
	keyID    string
}

// NewSentinelSampler validates the configuration and binds the
// randomization key. The key is server-side material: only its
// sha256-derived key id is ever published.
func NewSentinelSampler(key []byte, config SentinelConfig) (*SentinelSampler, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("the randomization key must be at least 16 bytes")
	}
	if config.Rate <= 0 || config.Rate > 1 {
		return nil, fmt.Errorf("the sentinel rate must be nonzero and at most 1")
	}
	sampleBy := config.SampleBy
	if sampleBy == "" {
		sampleBy = SampleByUnit
	}
	if sampleBy != SampleByUnit && sampleBy != SampleByCluster {
		return nil, fmt.Errorf("sample_by must be %q or %q",
			SampleByUnit, SampleByCluster)
	}
	digest := sha256.Sum256(key)
	stored := make([]byte, len(key))
	copy(stored, key)
	return &SentinelSampler{
		rate:     config.Rate,
		sampleBy: sampleBy,
		epoch:    config.Epoch,
		key:      stored,
		keyID:    fmt.Sprintf("smkey_%x", digest[:8]),
	}, nil
}

// DefaultSentinelSampler is the 1% per-unit default on the given key.
func DefaultSentinelSampler(key []byte, epoch string) (*SentinelSampler, error) {
	return NewSentinelSampler(key, SentinelConfig{
		Rate: DefaultSentinelRate, SampleBy: SampleByUnit, Epoch: epoch,
	})
}

// KeyID identifies the randomization key in records without revealing
// it. An auditor with the key verifies decisions; a worker with the
// key id learns nothing about inclusion.
func (s *SentinelSampler) KeyID() string { return s.keyID }

// Assign allocates deep review across one draw's units. Every unit —
// included or not — appears exactly once, so an excluded unit is
// provable from the record instead of asserted. The draw is a pure
// function of (key, epoch, unit): call order and batching cannot
// change a unit's outcome.
func (s *SentinelSampler) Assign(units []ReviewUnit) ([]Selection, SentinelSummary) {
	summary := SentinelSummary{
		Kind: "SentinelDraw", APIVersion: "v1",
		Units: len(units), Rate: s.rate, SampleBy: s.sampleBy,
		Epoch: s.epoch, KeyID: s.keyID,
	}
	// Cluster sampling draws once per cluster; every member shares the
	// outcome, which is the point: dependence travels with the cluster.
	clusterDrawn := map[string]bool{}
	if s.sampleBy == SampleByCluster {
		seen := map[string]bool{}
		for _, unit := range units {
			if unit.ClusterID == "" || unit.RiskRouted || seen[unit.ClusterID] {
				continue
			}
			seen[unit.ClusterID] = true
			clusterDrawn[unit.ClusterID] = s.drawn(unit.ClusterID)
		}
	}

	out := make([]Selection, 0, len(units))
	for _, unit := range units {
		selection := Selection{
			UnitID: unit.ID, ClusterID: unit.ClusterID,
			KeyID: s.keyID, Epoch: s.epoch,
		}
		switch {
		case unit.RiskRouted:
			// Triggered review is additional (spec 15.1): certain, and
			// never counted against the uniform sample.
			selection.DeepReview = true
			selection.Method = MethodRiskRouted
			selection.InclusionProbability = 1
			summary.RiskRouted++
		case s.sampleBy == SampleByCluster && unit.ClusterID != "":
			summary.CleanConsidered++
			selection.InclusionProbability = s.rate
			if clusterDrawn[unit.ClusterID] {
				selection.DeepReview = true
				selection.Method = MethodSentinel
				summary.Sentinels++
			} else {
				selection.Method = MethodNone
			}
		default:
			summary.CleanConsidered++
			selection.InclusionProbability = s.rate
			if s.drawn(unit.ID) {
				selection.DeepReview = true
				selection.Method = MethodSentinel
				summary.Sentinels++
			} else {
				selection.Method = MethodNone
			}
		}
		out = append(out, selection)
	}
	return out, summary
}

// drawn is the uniform inclusion decision for one sampling id:
// HMAC-SHA256(key, epoch | id) read as a 64-bit integer, included
// when it falls below rate * 2^64. HMAC is a pseudorandom function,
// so the decision is uniform, deterministic, and unpredictable
// without the key.
func (s *SentinelSampler) drawn(id string) bool {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(s.epoch))
	mac.Write([]byte{0})
	mac.Write([]byte(id))
	sum := mac.Sum(nil)
	draw := binary.BigEndian.Uint64(sum[:8])
	limit := s.rate * math.Ldexp(1, 64)
	return float64(draw) < limit
}
