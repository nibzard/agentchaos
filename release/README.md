# Release gates

The controlled-beta exit gates B1 through B10 from spec section 22.2.

## Run

```sh
python3 release/exit_gate.py
```

The checker runs every evidence suite (Go, Python, and UI), verifies
the predeclared outage and adversarial cases still exist by name, and
writes `release/exit_gate_report.json` and `release/exit_gate_report.md`.
Raw suite output lands in `release/raw/`.

Exit codes follow the gate, not the tooling:

- `0` — every gate met.
- `3` — the report was written, but one or more gates are unmet.
- `1` — the checker itself failed.

`--skip-run` rebuilds the report from the previous suite results
without rerunning them.

## How a gate is judged

A gate is met only on automated evidence or a documented acceptance
review. Three statuses appear in the report:

- **met** — the evidence exists and passed.
- **partial** — some evidence exists; the report names what is missing.
- **not met** — no honest evidence exists yet.

Gates B5, B6, and B10 need cohorts, partners, and a naming decision
that no repository can synthesize. They stay not met until real
operations produce the evidence, and a reassuring narrative does not
waive them.

## The predeclared cases

`REQUIRED_CASES` in `release/exit_gate.py` lists the outage,
dirty-cleanup, and adversarial tests gates B4 and B7 rest on, including
the ten-thousand-case `TestExitGateAdversarialSweep` in the broker. If
a test is renamed or deleted, the check fails rather than passing
silently on a smaller suite.

## Tests

```sh
python3 -m pytest release/test_exit_gate.py -q
```
