"""Path setup and shared fixtures for runner tests."""

from __future__ import annotations

import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
EXECUTION_PLANE = TESTS_DIR.parent
REPO_ROOT = EXECUTION_PLANE.parent

for path in (
    str(EXECUTION_PLANE),
    str(REPO_ROOT / "control-plane"),
    str(REPO_ROOT / "shared" / "python"),
):
    if path not in sys.path:
        sys.path.insert(0, path)

FIXTURE_DIR = REPO_ROOT / "shared" / "fixtures" / "valid"

NOW = "2026-09-11T21:00:00Z"
TENANT = "tnt_9d4c1e2a3b4f5c67"


class FixedClock:
    """A clock the test advances by hand."""

    def __init__(self, now: str = NOW):
        self.now = now

    def __call__(self) -> str:
        return self.now

    def advance_to(self, now: str) -> None:
        self.now = now


def plan_document() -> dict:
    """A compiled-plan document shaped like compile_manifest output."""
    return {
        "api_version": "v1",
        "kind": "CompiledPlan",
        "experiment_id": "exp_2e7b4d1c8a3f5092",
        "tenant_id": TENANT,
        "manifest_revision": 1,
        "mode": "isolated_reexecution",
        "workload": {
            "id": "wlv_3f9a1c2d4e5b6071",
            "name": "repo-maintainer",
            "version": "1.2.0",
            "fingerprint": "sha256:" + "1" * 64,
            "backend": "local_container",
        },
        "profiles": {
            "baseline": {
                "id": "aup_1a2b3c4d5e6f7081",
                "version": "1.0.0",
            },
            "treatment": {
                "id": "aup_5b8d2e0f1a3c4966",
                "version": "2.0.0",
            },
        },
        "scenarios": [
            {
                "id": "scn_7c1e9a0b3d5f2468",
                "template_id": "F01-101",
                "version": "1.1.0",
            }
        ],
        "selectors": [
            {
                "selected": ["tgt_4a5b6c7d8e9f0a1b"],
                "excluded": ["tgt_0f1e2d3c4b5a6978"],
                "recorded_seed": 20260911,
                "mode": "isolated_reexecution",
                "tenant_id": TENANT,
            }
        ],
    }


def grant(expires_at: str = "2026-09-11T21:05:00Z") -> dict:
    return {
        "kind": "ExperimentGrant",
        "experiment_id": "exp_2e7b4d1c8a3f5092",
        "tenant_id": TENANT,
        "plan_digest": "sha256:" + "2" * 64,
        "issued_at": NOW,
        "expires_at": expires_at,
    }
