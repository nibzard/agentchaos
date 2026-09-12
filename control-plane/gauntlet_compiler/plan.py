"""Plan documents, artifact digests, and grants.

The plan document is the digest-covered statement of what the compiler
resolved. It contains no timestamps, so the same manifest and records
always produce the same plan digest. Time lives only in the grant.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from gauntlet_compiler.canonical import sha256_digest

ARTIFACT_SCHEMA_VERSION = "v1"

# Artifact paths must match ^[A-Za-z0-9._/-]{1,512}$ in the Experiment
# contract. Semantic versions may carry characters outside that set
# (for example build metadata), so path segments are sanitized: every
# run of disallowed characters becomes a single hyphen.
_ALLOWED_PATH_CHARS = re.compile(r"[^A-Za-z0-9._-]+")
_COLLAPSIBLE_HYPHENS = re.compile(r"-{2,}")


def _path_segment(value: str) -> str:
    sanitized = _ALLOWED_PATH_CHARS.sub("-", value)
    return _COLLAPSIBLE_HYPHENS.sub("-", sanitized).strip("-.")


def workload_artifact_path(workload: dict) -> str:
    return (
        f"workloads/{_path_segment(workload['name'])}"
        f"-{_path_segment(workload['version'])}.json"
    )


def profile_artifact_path(profile: dict) -> str:
    return (
        f"profiles/{_path_segment(profile['name'])}"
        f"-{_path_segment(profile['version'])}.json"
    )


def scenario_artifact_path(scenario: dict) -> str:
    return (
        f"scenarios/{_path_segment(scenario['template_id'])}"
        f"-{_path_segment(scenario['version'])}.json"
    )


def build_artifact_digests(
    workload: dict, baseline: dict, treatment: dict, scenarios: list[dict]
) -> list[dict]:
    """Digest every resolved artifact. Sorted for stable output.

    Two references to the same artifact (baseline and treatment arms
    that share one profile) collapse to a single entry. Two different
    records that sanitize to the same path are a collision: the caller
    must reject the manifest, because the plan could not say which
    record the path covers.
    """
    artifacts: list[tuple[str, dict]] = [
        (workload_artifact_path(workload), workload),
        (profile_artifact_path(baseline), baseline),
        (profile_artifact_path(treatment), treatment),
    ]
    artifacts.extend((scenario_artifact_path(s), s) for s in scenarios)

    by_path: dict[str, dict] = {}
    for path, record in artifacts:
        digest = sha256_digest(record)
        previous = by_path.get(path)
        if previous is not None and previous != digest:
            raise ArtifactPathCollision(path)
        by_path[path] = digest
    return [
        {"path": path, "digest": digest}
        for path, digest in sorted(by_path.items())
    ]


class ArtifactPathCollision(Exception):
    """Two different records produced the same artifact path."""

    def __init__(self, path: str):
        self.path = path
        super().__init__(
            f"two different records sanitize to artifact path {path}"
        )


@dataclass(frozen=True)
class CompiledPlan:
    """The compiler output.

    `plan_block()` returns exactly the four fields the Experiment
    contract allows in its plan block. The grant and the full plan
    document stay separate so they can never leak into the persisted
    plan block by accident.
    """

    plan_digest: str
    artifact_digests: list[dict]
    risk_classification: str
    signed_grant: dict
    grant: dict
    plan_document: dict = field(default_factory=dict)

    def plan_block(self) -> dict:
        return {
            "plan_digest": self.plan_digest,
            "artifact_digests": self.artifact_digests,
            "risk_classification": self.risk_classification,
            "signed_grant": self.signed_grant,
        }


def build_plan_document(
    experiment: dict,
    workload: dict,
    baseline: dict,
    treatment: dict,
    scenarios: list[dict],
    selector_results: list[dict],
) -> dict:
    """Return the digest-covered plan document for a resolved manifest."""
    manifest = experiment["manifest"]
    return {
        "api_version": ARTIFACT_SCHEMA_VERSION,
        "kind": "CompiledPlan",
        "experiment_id": experiment["id"],
        "manifest_revision": experiment.get("revision", 1),
        "mode": manifest["mode"],
        "workload": {
            "id": workload["id"],
            "name": workload["name"],
            "version": workload["version"],
            "fingerprint": workload["fingerprint"],
            "backend": workload["environment"]["backend"],
        },
        "profiles": {
            "baseline": _profile_ref(baseline),
            "treatment": _profile_ref(treatment),
        },
        "scenarios": [
            {
                "id": s["id"],
                "template_id": s["template_id"],
                "version": s["version"],
            }
            for s in sorted(scenarios, key=lambda s: s["id"])
        ],
        "selectors": selector_results,
        "budgets": manifest["budgets"],
        "identities": manifest["identities"],
        "recording": manifest["recording"],
        "stop_rules": manifest["stop_rules"],
        "rollback": manifest["rollback"],
        "credentials": {
            "required_kinds": manifest["credentials"]["required_kinds"],
            "freshness_max_age_s": manifest["credentials"]["freshness_max_age_s"],
        },
        "effect_sinks": manifest["effect_sinks"],
    }


def _profile_ref(profile: dict) -> dict:
    return {
        "id": profile["id"],
        "name": profile["name"],
        "version": profile["version"],
    }


def build_grant_payload(
    experiment: dict,
    plan_digest: str,
    issued_at: str,
    expires_at: str,
) -> dict:
    """Return the short-lived grant payload covered by the signature."""
    manifest = experiment["manifest"]
    return {
        "api_version": ARTIFACT_SCHEMA_VERSION,
        "kind": "ExperimentGrant",
        "experiment_id": experiment["id"],
        "tenant_id": experiment["tenant_id"],
        "plan_digest": plan_digest,
        "max_duration_s": manifest["budgets"]["max_duration_s"],
        "issued_at": issued_at,
        "expires_at": expires_at,
    }
