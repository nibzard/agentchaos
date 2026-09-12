# gauntlet CLI

The operator command line (spec 17.7, T029). One static binary, Go
standard library only, speaking the API monolith's HTTP contract: the
bearer principal token, one fresh idempotency key per mutation, and
the problem envelope on every failure.

## Commands

```text
gauntlet validate MANIFEST [--records FILE]   store a draft, optionally compile
gauntlet run MANIFEST --records FILE --primitive P [--output DIR]
                                        compile and start a run
gauntlet compare RUN_BASELINE RUN_TREATMENT  paired run comparison
gauntlet inspect RUN_ID [--evidence]         run state, optionally its events
gauntlet stop RUN_ID [--reason TEXT]         request fencing and cleanup
gauntlet report RUN_ID [--format text|json]  run report
gauntlet assurance explain CLAIM_ID          render the evidence card
```

`--api` (default `http://localhost:8080`) and `--token` can also come
from `GAUNTLET_API` and `GAUNTLET_TOKEN`; flags win. `--primitive` repeats and
also accepts comma-separated lists.

## Exit codes

```text
0  the operation completed and its explicit gate passed
2  a declared gate failed
3  insufficient evidence or inconclusive evaluation
4  invalid configuration
5  harness or infrastructure failure
```

The mapping is deliberate:

- **Run gates** never infer a pass from absence. `inspect`, `report`,
  and `compare` map a stopped run with terminal state `CLEAN` to 0;
  `DIRTY_QUARANTINED` or a governor fence to 2; `UNKNOWN`, a stop
  without a terminal state, or a still-active run to 3. A worker exit
  code is never evidence (spec 13).
- **Claims** map `SUPPORTED_WITHIN_SCOPE` to 0, `VIOLATED` and
  `TARGET_NOT_DEMONSTRATED` to 2, and `INSUFFICIENT_EVIDENCE` and
  `STALE` to 3. Exit 0 prints the scope sentence: it is never
  shorthand for universal safety.
- **Comparison** refuses runs from different experiments with 4 — a
  partial pair is refused, not compared (spec 15.3) — and exits on
  the treatment's gate while printing both.
- **Failures** map transport errors, 5xx replies, and authentication
  or role refusals to 5: the harness path is broken. Every other
  problem the caller could have prevented — schema, unknown ids,
  conflicts — is 4, and the problem's stable code and message print
  to stderr.

`run` exits 0 when the run starts and the step artifacts
(`experiment.json`, `run.json`) land in `--output`. The gate is
evaluated later, by `inspect`, `report`, or `compare` on the finished
run.

## Build and test

```bash
cd cli && go test ./...
go build -o gauntlet ./gauntlet
```

The tests drive `Main` against a scripted stub server and pin the
request shapes (paths, bearer token, fresh `idk_cli-` keys on
mutations only) and the full exit-code table.
