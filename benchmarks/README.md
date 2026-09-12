# Benchmarks

Benchmarks for the beta nonfunctional targets in spec section 21.

## Run

```sh
./benchmarks/run.sh
```

The script runs every benchmark, saves the raw output under
`benchmarks/raw/`, and builds `benchmarks/report.json` and
`benchmarks/report.md`.

## What is measured

| Suite | File | Targets exercised |
|---|---|---|
| Broker | `broker/bench_test.go` | Gate p95 latency, decision throughput, expired-grant denial |
| Evidence plane | `evidence-plane/bench_test.go` | Metadata event ingest rate |
| Supervisor | `supervisor/bench_test.go` | Reviewer decision rate, deadline fallback |
| Governor | `governor/bench_test.go` | Fencing acknowledgment p99 |
| Execution plane | `execution-plane/benchmarks/runner_overhead.py` | Runner overhead share, environment lifecycle time |

Go benchmarks use bounded iteration counts (`-benchtime=Nx`) so a run
stays quick and the in-memory recorder stays small. Percentile metrics
(`gate-p95-ms`, `fence-p99-ms`) are custom `b.ReportMetric` values, not
averages.

## Honesty rules

Spec section 21 calls every figure a proposed engineering target under
measurement conditions this repository cannot reproduce: reference
deployments, network services, live models, partner integrations. The
report therefore separates three statements:

- **Measured**: the in-process number under the stated condition.
- **Covered by tests**: a behavior guarantee with no latency figure.
- **Not measured**: no honest number exists here.

The report certifies nothing. A gate p95 measured in-process does not
show the p95 of a deployed service.
