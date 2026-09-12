"""Path setup and shared fixtures for compiler tests."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
CONTROL_PLANE = TESTS_DIR.parent
REPO_ROOT = CONTROL_PLANE.parent

for path in (str(CONTROL_PLANE), str(REPO_ROOT / "shared" / "python")):
    if path not in sys.path:
        sys.path.insert(0, path)

FIXTURE_DIR = REPO_ROOT / "shared" / "fixtures" / "valid"

NOW = "2026-09-11T21:00:00Z"
TENANT = "tnt_9d4c1e2a3b4f5c67"
OTHER_TENANT = "tnt_ffffffffffffffff"
OPERATOR = "act_platform-operator-01"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))


def _target(
    target_id: str = "tgt_4a5b6c7d8e9f0a1b",
    *,
    tenant_id: str = TENANT,
    target_class: str = "synthetic-repo",
    status: str = "enrolled",
    opt_in_modes: tuple[str, ...] = ("production_synthetic",),
) -> dict:
    """A contract-valid Target record."""
    record: dict = {
        "kind": "Target",
        "api_version": "v1",
        "id": target_id,
        "tenant_id": tenant_id,
        "class": target_class,
        "status": status,
    }
    if status in ("enrolled", "paused"):
        record["enrollment"] = {
            "enrolled_at": "2026-09-01T10:00:00Z",
            "enrolled_by": OPERATOR,
            "opt_in_modes": list(opt_in_modes),
        }
    else:
        record["unenrolled_at"] = "2026-09-10T08:00:00Z"
    return record


def _baseline_profile() -> dict:
    """A second published profile derived from the treatment fixture."""
    profile = load_fixture("autonomy-profile")
    profile["id"] = "aup_1a2b3c4d5e6f7081"
    profile["name"] = "hard-controls-only"
    profile["version"] = "1.0.0"
    profile.pop("supersedes", None)
    profile.pop("description", None)
    profile["controls"]["allowed_action_classes"] = ["A0", "A1"]
    profile["supervision"]["contextual_reviewer"]["enabled"] = False
    return profile


def _targets() -> list[dict]:
    return [
        _target("tgt_4a5b6c7d8e9f0a1b"),
        _target("tgt_0f1e2d3c4b5a6978"),
    ]


def _credentials() -> list[dict]:
    return [
        {
            "kind": "Credential",
            "id": "cred_fixture-github-token",
            "tenant_id": TENANT,
            "credential_kind": "fixture-github-token",
            "refreshed_at": "2026-09-11T20:30:00Z",
        },
        {
            "kind": "Credential",
            "id": "cred_model-gateway",
            "tenant_id": TENANT,
            "credential_kind": "model-gateway",
            "refreshed_at": "2026-09-11T20:45:00Z",
        },
    ]


def draft_experiment() -> dict:
    """The experiment fixture as draft input, ready to compile."""
    experiment = load_fixture("experiment")
    experiment["status"] = "draft"
    experiment.pop("plan", None)
    return experiment


def build_store(**overrides) -> "MemoryResourceStore":
    from acx_compiler import MemoryResourceStore

    resources = {
        "workloads": [load_fixture("workload-version")],
        "profiles": [_baseline_profile(), load_fixture("autonomy-profile")],
        "scenarios": [load_fixture("scenario-version")],
        "targets": _targets(),
        "credentials": _credentials(),
    }
    resources.update(overrides)
    return MemoryResourceStore(**resources)


def make_signer():
    from acx_compiler import Ed25519Signer

    return Ed25519Signer.generate("key_grants-2026q3")


def compile_ok(experiment=None, store=None, **kwargs):
    """Compile the happy path; returns (result, signer)."""
    from acx_compiler import compile_manifest

    experiment = copy.deepcopy(experiment or draft_experiment())
    signer = make_signer()
    result = compile_manifest(
        experiment, store or build_store(), now=NOW, signer=signer, **kwargs
    )
    return result, signer
