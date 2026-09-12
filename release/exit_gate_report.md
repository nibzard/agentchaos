# Controlled-beta exit gate report

Verdict: **gates unmet: B2, B3, B4, B5, B6, B7, B8, B9, B10**

Gate statuses follow spec 22.2. A gate is met only on automated evidence or a documented acceptance review; everything else names its gap. A reassuring narrative does not waive a failing gate.

## Gates

| Gate | Status | Evidence | Gaps |
|---|---|---|---|
| B1 All P0 requirements have automated evidence or a documented acceptance review | met | 28 acceptance criteria mapped to suites in release/exit_gate.py AC_MAP; suite runs in release/raw/ | none |
| B2 All 24 scenario templates trigger in reference fixtures; valid trigger coverage exceeds 95% of eligible scheduled cases, the remainder explained | partial | library holds 24 templates; the execution suite executes each through the fixture runner and asserts trigger plus nontrigger evidence per pair | fixture scope only: no scheduled campaign has run, so coverage over eligible scheduled cases is unmeasured |
| B3 No known unsupported external path is represented as mediated | partial | adapter manifests must enumerate unsupported families, and capabilities plus unsupported paths must cover all nine fault families; the conformance suite rejects a silent family and a lying capability | contract scope only: no deployed mediation surface exists to audit, so the product-wide claim is untested |
| B4 No successful hard-boundary bypass in a predeclared 10,000-case conformance/adversarial suite, plus independent review | partial | the automated half: TestExitGateAdversarialSweep runs 10,000 seeded cases (7,100 violations across 11 boundary categories, 2,900 controls) with zero allows on violations, plus the integration boundary tests | no independent review has been performed |
| B5 On a held-out benign cohort of at least 1,000 sessions, the reference control profile's one-sided 95% upper bound for material false intervention is below 1% | not met | none | no benign cohort exists: the bound calculator and its property tests exist in control-plane, but no sessions have run; requires a documented cohort with dependence assumptions before the number means anything |
| B6 Authorized task completion is no more than three percentage points below the hard-controls-only baseline on the specified solvable cohort, with paired uncertainty | not met | none | no solvable cohort and no paired baseline runs exist; paired-uncertainty reporting is specified but unexercised |
| B7 All outage and dirty-cleanup cases fail safely under the stated supported model | partial | predeclared case list in release/exit_gate.py REQUIRED_CASES; sink failures, reviewer outages, capture failures, lease loss, expired grants, and dirty cleanup each hold or fence | the hardened ephemeral execution backend is not implemented in this repository, so fail-safe behavior is verified on the local fixture model only |
| B8 Every serious finding has raw evidence and an independent outcome reference | not met | the plumbing is tested: portable reports must name their evidence chain and artifacts by digest, and outcome assertions come from outside the acting monitor | no beta campaign has run, so no serious findings exist to audit; the gate cannot be met without real operations |
| B9 Latency, cost, privacy, and operator-control targets have actual benchmark reports | partial | benchmarks/report.json covers the measurable targets in-process with conditions and raw output | areas without an honest number: ['Monitoring inference cost', 'Hosted service availability', 'Real workflow integration']; cost, privacy, and operator control have no benchmark surface yet; deployment-scale reports do not exist |
| B10 At least three design partners integrated, two intend to pay under a pilot agreement, and naming clearance is complete | not met | none | no design partners have integrated a workflow; no pilot agreements exist; the AgentChaos name conflict (spec 23.3) is unresolved |

## Evidence suites

| Suite | Result | Seconds | Log |
|---|---|---|---|
| Broker (Go) (broker-go) | pass | 1.4 | release/raw/broker-go.log |
| Evidence plane (Go) (evidence-go) | pass | 0.4 | release/raw/evidence-go.log |
| Supervisor (Go) (supervisor-go) | pass | 0.1 | release/raw/supervisor-go.log |
| Governor (Go) (governor-go) | pass | 0.4 | release/raw/governor-go.log |
| Control plane (Go) (control-plane-go) | pass | 1.1 | release/raw/control-plane-go.log |
| Analysis (Go) (analysis-go) | pass | 0.1 | release/raw/analysis-go.log |
| CLI (Go) (cli-go) | pass | 0.1 | release/raw/cli-go.log |
| Cross-component integration (Go) (integration-go) | pass | 0.3 | release/raw/integration-go.log |
| Control plane compiler (Python) (control-plane-py) | pass | 1.2 | release/raw/control-plane-py.log |
| Execution plane (Python) (execution-plane-py) | pass | 0.8 | release/raw/execution-plane-py.log |
| UI (Bun) (ui-bun) | pass | 0.0 | release/raw/ui-bun.log |

## Predeclared cases

The outage, dirty-cleanup, and adversarial cases each gate rests on are listed in REQUIRED_CASES in `release/exit_gate.py`; a renamed or deleted test fails the check rather than passing silently.

