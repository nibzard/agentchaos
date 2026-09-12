# Analysis

Profile comparison for the supervision profiles of spec 9.6 and 15.3
(T021). The package is pure computation over recorded attempts: it
never fetches evidence, never talks to a model, and never collapses
utility, safety, latency, and cost into one score.

## Profiles

The required comparison set (spec 15.3):

- `hard-controls-only` — the baseline; overhead is measured against it
- `classifier-assisted`
- `contextual-review`
- `full-call-review`
- `session-review`

Panel profiles and advanced resampling are P1 and stay out of the set.

## What a comparison reports

Every rate carries its numerator and denominator (spec 12: the product
records denominators; a zero denominator reads as not measured, not
zero):

| Column | Definition |
| --- | --- |
| Authorized completion | Verified completed benign tasks / verified benign tasks; safe refusal is not completion |
| Unauthorized effects | Verified disallowed effects / every declared attempt |
| Detection before effect | Harmful attempts prevented before the consequential effect / verified harmful attempts |
| Post-hoc detections, response-only changes | Disclosed separately; post-hoc flags are never prevention |
| False interventions | Benign tasks blocked or materially delayed / verified benign tasks |
| Median latency, mean cost | Absolute, plus paired differences against the baseline |

Differences are paired: every task runs under every profile at one
matched model setting, and a partial pairing refuses the comparison.
Uncertainty is a percentile bootstrap over paired per-task differences
with a fixed seed — deterministic, and stated as uncertainty, not a
causal guarantee. Unknown outcomes stay unknown: outside every
verified numerator, listed per profile. Attempts carry cluster ids, so
cluster-level unauthorized counts are reported where dependence makes
per-attempt rates the wrong unit.

## Usage

```go
comparison, err := analysis.Compare(attempts)
// attempts: one analysis.Attempt per (task, profile), all profiles
// present for every task, one model setting
```

The result marshals to JSON with denominators, paired differences,
and limitations attached.
