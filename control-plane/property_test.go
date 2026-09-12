package control

import (
	"math"
	"math/rand"
	"testing"
)

// Property tests for the statistics behind assurance (T040): the
// binomial upper bound must stay a bound under every input — never
// below the observed rate, never outside [0, 1], tighter with more
// clean observations, wider with more failures or more confidence.

const propertyTolerance = 1e-9

func TestPropertyBoundsStayAboveTheObservedRate(t *testing.T) {
	rng := rand.New(rand.NewSource(20260918))
	for trial := 0; trial < 300; trial++ {
		n := 1 + rng.Intn(200)
		failures := rng.Intn(n) // failures == n returns 1 by contract
		confidence := []float64{0.90, 0.95, 0.99}[rng.Intn(3)]
		bound, err := BinomialUpperBound(failures, n, confidence)
		if err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		if bound < 0 || bound > 1 {
			t.Fatalf("trial %d: bound %v left [0, 1]", trial, bound)
		}
		if bound < float64(failures)/float64(n)-propertyTolerance {
			t.Fatalf("trial %d: bound %v fell below the observed rate %v",
				trial, bound, float64(failures)/float64(n))
		}
	}
}

func TestPropertyMoreCleanObservationsTightenTheBound(t *testing.T) {
	rng := rand.New(rand.NewSource(20260919))
	for trial := 0; trial < 100; trial++ {
		confidence := 0.8 + 0.19*rng.Float64()
		previous, err := BinomialUpperBound(0, 1, confidence)
		if err != nil {
			t.Fatal(err)
		}
		for n := 2; n <= 60; n++ {
			bound, err := BinomialUpperBound(0, n, confidence)
			if err != nil {
				t.Fatal(err)
			}
			if bound > previous+propertyTolerance {
				t.Fatalf("trial %d: the bound widened from n=%d to n=%d",
					trial, n-1, n)
			}
			previous = bound
		}
	}
}

func TestPropertyMoreFailuresRaiseTheBound(t *testing.T) {
	rng := rand.New(rand.NewSource(20260920))
	for trial := 0; trial < 100; trial++ {
		n := 2 + rng.Intn(100)
		confidence := 0.8 + 0.19*rng.Float64()
		previous, err := BinomialUpperBound(0, n, confidence)
		if err != nil {
			t.Fatal(err)
		}
		for failures := 1; failures <= n; failures++ {
			bound, err := BinomialUpperBound(failures, n, confidence)
			if err != nil {
				t.Fatal(err)
			}
			if bound+propertyTolerance < previous {
				t.Fatalf("trial %d: the bound fell from %d to %d failures",
					trial, failures-1, failures)
			}
			previous = bound
		}
	}
}

func TestPropertyMoreConfidenceWidensTheBound(t *testing.T) {
	rng := rand.New(rand.NewSource(20260921))
	for trial := 0; trial < 100; trial++ {
		n := 1 + rng.Intn(100)
		failures := rng.Intn(n + 1)
		previous, err := BinomialUpperBound(failures, n, 0.80)
		if err != nil {
			t.Fatal(err)
		}
		for _, confidence := range []float64{0.85, 0.90, 0.95, 0.99} {
			bound, err := BinomialUpperBound(failures, n, confidence)
			if err != nil {
				t.Fatal(err)
			}
			if bound+propertyTolerance < previous {
				t.Fatalf("trial %d: confidence %v narrowed the bound", trial,
					confidence)
			}
			previous = bound
		}
	}
}

func TestPropertyTheBoundSolvesItsOwnEquation(t *testing.T) {
	// For 0 < failures < observations, the returned p is the quantile
	// where P(X <= failures) drops to alpha — the bound is exact, not
	// merely safe.
	rng := rand.New(rand.NewSource(20260922))
	for trial := 0; trial < 200; trial++ {
		n := 2 + rng.Intn(80)
		failures := 1 + rng.Intn(n-1)
		confidence := 0.8 + 0.19*rng.Float64()
		alpha := 1 - confidence
		bound, err := BinomialUpperBound(failures, n, confidence)
		if err != nil {
			t.Fatal(err)
		}
		cdf := binomialCDF(failures, n, bound)
		if cdf > alpha+propertyTolerance {
			t.Fatalf("trial %d: P(X<=%d) at the bound is %v, above alpha %v",
				trial, failures, cdf, alpha)
		}
		if bound > 0 && binomialCDF(failures, n,
			math.Nextafter(bound, 0)) > alpha+1e-6 {
			t.Fatalf("trial %d: the bound is looser than one ulp", trial)
		}
	}
}

func TestPropertyDegenerateCohortsReturnTheHonestAnswer(t *testing.T) {
	rng := rand.New(rand.NewSource(20260923))
	for trial := 0; trial < 100; trial++ {
		confidence := 0.8 + 0.19*rng.Float64()

		// No observations: absence of evidence is not safety.
		bound, err := BinomialUpperBound(0, 0, confidence)
		if err != nil || bound != 1 {
			t.Fatalf("trial %d: empty cohort gave (%v, %v)", trial, bound,
				err)
		}
		// Every observation failed.
		n := 1 + rng.Intn(50)
		bound, err = BinomialUpperBound(n, n, confidence)
		if err != nil || bound != 1 {
			t.Fatalf("trial %d: all-failure cohort gave (%v, %v)", trial,
				bound, err)
		}
		// Zero failures: the closed form, exactly.
		bound, err = BinomialUpperBound(0, n, confidence)
		if err != nil {
			t.Fatal(err)
		}
		expected := 1 - math.Pow(1-confidence, 1/float64(n))
		if math.Abs(bound-expected) > propertyTolerance {
			t.Fatalf("trial %d: closed form %v, got %v", trial, expected,
				bound)
		}
		// Impossible counts and confidence levels refuse.
		if _, err = BinomialUpperBound(n+1, n, confidence); err == nil {
			t.Fatalf("trial %d: failures above observations accepted", trial)
		}
		if _, err = BinomialUpperBound(-1, n, confidence); err == nil {
			t.Fatalf("trial %d: negative failures accepted", trial)
		}
		if _, err = BinomialUpperBound(0, n, 0); err == nil {
			t.Fatalf("trial %d: confidence 0 accepted", trial)
		}
		if _, err = BinomialUpperBound(0, n, 1); err == nil {
			t.Fatalf("trial %d: confidence 1 accepted", trial)
		}
	}
}
