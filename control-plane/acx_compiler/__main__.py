"""Command-line compile entry for the API monolith.

The beta API is a Go service (spec 8.1), but only the Python compiler
can authorize execution (spec 9.1). This module is the process boundary
between them: it reads one JSON request on standard input and writes one
JSON reply on standard output, so the Go side never re-implements
compilation.

Request:

    {
      "experiment": {...Experiment record...},
      "records": {
        "workloads": [...], "profiles": [...], "scenarios": [...],
        "targets": [...], "credentials": [...]
      },
      "now": "2026-09-12T10:00:00Z",
      "key_id": "key_grants-2026q3"
    }

Reply, exit 0:

    {"ok": true, "plan": {...}, "plan_document": {...}}
    {"ok": false, "errors": [{"code", "message", "path"}, ...]}

Compile failures are results, not crashes: a manifest that fails to
compile produces ok=false with exit 0. A nonzero exit means the entry
itself could not run; the caller reports a compiler outage, never a
silent pass.
"""

from __future__ import annotations

import json
import sys

from acx_compiler.compiler import compile_manifest
from acx_compiler.errors import CompileViolation
from acx_compiler.records import MemoryResourceStore
from acx_compiler.signing import Ed25519Signer

RECORD_KINDS = ("workloads", "profiles", "scenarios", "targets", "credentials")


def main() -> int:
    try:
        request = json.load(sys.stdin)
        reply = compile_request(request)
        code = 0
    except CompileViolation as violation:
        reply = {"ok": False, **violation.as_dict()}
        code = 0
    except Exception as exc:  # unreachable inputs, not compile verdicts
        reply = {"ok": False, "errors": [
            {"code": "compiler_entry_invalid", "message": str(exc), "path": "$"}
        ]}
        code = 1
    json.dump(reply, sys.stdout)
    sys.stdout.write("\n")
    return code


def compile_request(request: dict) -> dict:
    if not isinstance(request, dict):
        raise ValueError("request must be a JSON object")

    experiment = request.get("experiment")
    if not isinstance(experiment, dict):
        raise ValueError("request.experiment must be an Experiment record")

    records = request.get("records") or {}
    if not isinstance(records, dict):
        raise ValueError("request.records must be an object")
    unknown = sorted(set(records) - set(RECORD_KINDS))
    if unknown:
        raise ValueError(f"unknown record kinds: {', '.join(unknown)}")
    store = MemoryResourceStore(
        **{kind: records.get(kind) or [] for kind in RECORD_KINDS}
    )

    now = request.get("now")
    if not isinstance(now, str) or not now:
        raise ValueError("request.now must be a timestamp string")

    key_id = request.get("key_id") or "key_grants-api"
    if not isinstance(key_id, str):
        raise ValueError("request.key_id must be a string")

    result = compile_manifest(
        experiment,
        store,
        now=now,
        signer=Ed25519Signer.generate(key_id),
    )
    return {
        "ok": True,
        "plan": result.plan_block(),
        "plan_document": result.plan_document,
    }


if __name__ == "__main__":
    sys.exit(main())
