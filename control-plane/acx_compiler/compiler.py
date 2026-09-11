"""The deterministic experiment manifest compiler (spec 9.1, 13.1).

The compiler resolves every reference in a manifest, rejects unsafe or
inconsistent input, classifies risk, and produces a signed plan. An LLM
may draft a manifest; only this module can authorize execution.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from acx_schemas import ContractViolation, validate

from acx_compiler.canonical import sha256_digest
from acx_compiler.errors import CompileErrorEntry, CompileViolation
from acx_compiler.plan import (
    ArtifactPathCollision,
    CompiledPlan,
    build_artifact_digests,
    build_grant_payload,
    build_plan_document,
)
from acx_compiler.records import ResourceStore
from acx_compiler.risk import RISK_ORDER, RiskPolicy, classify_risk

DEFAULT_GRANT_TTL_S = 300
DEFAULT_POLICY = RiskPolicy()


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def compile_manifest(
    experiment: dict,
    store: ResourceStore,
    *,
    now: str,
    signer,
    policy: RiskPolicy | None = None,
    grant_ttl_s: int = DEFAULT_GRANT_TTL_S,
) -> dict:
    """Compile a manifest into the plan block of an Experiment.

    Returns the schema-shaped plan object (plan_digest,
    artifact_digests, risk_classification, signed_grant). Raises
    CompileViolation with every failure when the manifest cannot
    compile. Failures are never warnings (spec 9.1).
    """
    policy = policy or DEFAULT_POLICY
    entries: list[CompileErrorEntry] = []

    _check_experiment_contract(experiment, entries)
    if entries:
        # The manifest shape cannot be trusted; do not resolve further.
        raise CompileViolation(entries)

    manifest = experiment["manifest"]
    tenant_id = experiment["tenant_id"]
    mode = manifest["mode"]

    workload = _resolve_workload(store, manifest, mode, tenant_id, policy, entries)
    baseline = _resolve_profile(
        store, manifest["baseline_profile_id"], "baseline", tenant_id, entries
    )
    treatment = _resolve_profile(
        store, manifest["treatment_profile_id"], "treatment", tenant_id, entries
    )
    scenarios = _resolve_scenarios(store, manifest, tenant_id, entries)
    selector_results, target_classes = _expand_selectors(
        store, manifest, tenant_id, entries
    )
    _check_credentials(store, manifest, tenant_id, now, entries)
    _check_budgets(manifest, entries)
    _check_stop_rules(manifest, entries)
    _check_rollback(manifest, entries)
    _check_effect_sinks(manifest, mode, policy, entries)
    _check_recording(manifest, policy, entries)
    if scenarios and target_classes:
        _check_scenario_eligibility(scenarios, mode, target_classes, entries)
    _check_assertion_recording(scenarios, manifest, entries)

    def _arm_classes(profile: dict | None) -> list[str]:
        if not profile:
            return []
        return profile.get("controls", {}).get("allowed_action_classes") or []

    risk = classify_risk(
        mode,
        [_arm_classes(baseline), _arm_classes(treatment)],
        manifest["identities"]["kind"],
        [sink["kind"] for sink in manifest["effect_sinks"]],
    )
    if RISK_ORDER[risk] > RISK_ORDER[policy.max_risk]:
        entries.append(
            CompileErrorEntry(
                "risk_exceeds_policy",
                f"risk classification {risk} exceeds accepted {policy.max_risk}",
                "$.manifest",
            )
        )

    if entries:
        raise CompileViolation(entries)

    plan_document = build_plan_document(
        experiment, workload, baseline, treatment, scenarios, selector_results
    )
    plan_digest = sha256_digest(plan_document)
    try:
        artifact_digests = build_artifact_digests(
            workload, baseline, treatment, scenarios
        )
    except ArtifactPathCollision as collision:
        entries.append(
            CompileErrorEntry(
                "artifact_path_collision",
                collision.args[0],
                "$.plan.artifact_digests",
            )
        )
        raise CompileViolation(entries) from collision

    issued = _parse_utc(now)
    expires = issued + timedelta(seconds=grant_ttl_s)
    grant_payload = build_grant_payload(
        experiment,
        plan_digest,
        issued_at=issued.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        expires_at=expires.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    )
    signature = signer.sign_document(grant_payload)

    return CompiledPlan(
        plan_digest=plan_digest,
        artifact_digests=artifact_digests,
        risk_classification=risk,
        signed_grant={
            "algorithm": signer.key_algorithm,
            "key_id": signer.key_id,
            "value": signature,
        },
        grant=grant_payload,
        plan_document=plan_document,
    )


def _check_experiment_contract(
    experiment: dict, entries: list[CompileErrorEntry]
) -> None:
    try:
        validate(experiment, "Experiment")
    except ContractViolation as exc:
        for error in exc.as_dict()["errors"]:
            entries.append(
                CompileErrorEntry(
                    "experiment_schema",
                    error["message"],
                    error["path"],
                )
            )


def _check_record(
    record: dict, kind: str, path: str, entries: list[CompileErrorEntry]
) -> bool:
    """Validate a resolved record; report and keep going on failure."""
    try:
        validate(record, kind)
        return True
    except ContractViolation as exc:
        first = exc.as_dict()["errors"][0]
        entries.append(
            CompileErrorEntry(
                "record_schema_invalid",
                f"{kind} record invalid: {first['message']}",
                path,
            )
        )
        return False


def _resolve_workload(
    store: ResourceStore,
    manifest: dict,
    mode: str,
    tenant_id: str,
    policy: RiskPolicy,
    entries: list[CompileErrorEntry],
) -> dict | None:
    workload_id = manifest["workload_version_id"]
    path = "$.manifest.workload_version_id"
    workload = store.get_workload(workload_id)
    if workload is None:
        entries.append(
            CompileErrorEntry(
                "unknown_reference",
                f"workload version {workload_id} not found",
                path,
            )
        )
        return None
    _check_record(workload, "WorkloadVersion", path, entries)
    if workload.get("tenant_id") != tenant_id:
        entries.append(
            CompileErrorEntry(
                "tenant_mismatch",
                f"workload {workload_id} belongs to tenant "
                f"{workload.get('tenant_id')}, experiment belongs to "
                f"{tenant_id}",
                path,
            )
        )
    if mode not in workload.get("supported_modes", []):
        entries.append(
            CompileErrorEntry(
                "mode_not_supported",
                f"workload {workload_id} does not support mode {mode}",
                "$.manifest.mode",
            )
        )
    backend = workload.get("environment", {}).get("backend")
    if mode in policy.hardened_only_modes and backend != "hardened_microvm":
        entries.append(
            CompileErrorEntry(
                "backend_not_supported",
                f"mode {mode} requires backend hardened_microvm, "
                f"workload declares {backend}",
                path,
            )
        )
    return workload


def _resolve_profile(
    store: ResourceStore,
    profile_id: str,
    role: str,
    tenant_id: str,
    entries: list[CompileErrorEntry],
) -> dict | None:
    profile = store.get_profile(profile_id)
    path = f"$.manifest.{role}_profile_id"
    if profile is None:
        entries.append(
            CompileErrorEntry(
                "unknown_reference",
                f"{role} profile {profile_id} not found",
                path,
            )
        )
        return None
    _check_record(profile, "AutonomyProfile", path, entries)
    if profile.get("tenant_id") != tenant_id:
        entries.append(
            CompileErrorEntry(
                "tenant_mismatch",
                f"{role} profile {profile_id} belongs to tenant "
                f"{profile.get('tenant_id')}, experiment belongs to {tenant_id}",
                path,
            )
        )
    if profile.get("status") != "published":
        entries.append(
            CompileErrorEntry(
                "profile_not_published",
                f"{role} profile {profile_id} has status "
                f"{profile.get('status')}, only published profiles may run",
                path,
            )
        )
    return profile


def _resolve_scenarios(
    store: ResourceStore,
    manifest: dict,
    tenant_id: str,
    entries: list[CompileErrorEntry],
) -> list[dict]:
    scenarios: list[dict] = []
    for index, scenario_id in enumerate(manifest["scenario_version_ids"]):
        path = f"$.manifest.scenario_version_ids[{index}]"
        scenario = store.get_scenario(scenario_id)
        if scenario is None:
            entries.append(
                CompileErrorEntry(
                    "unknown_reference",
                    f"scenario version {scenario_id} not found",
                    path,
                )
            )
            continue
        _check_record(scenario, "ScenarioVersion", path, entries)
        if scenario.get("tenant_id") != tenant_id:
            entries.append(
                CompileErrorEntry(
                    "tenant_mismatch",
                    f"scenario {scenario_id} belongs to tenant "
                    f"{scenario.get('tenant_id')}, experiment belongs to "
                    f"{tenant_id}",
                    path,
                )
            )
        if scenario.get("status") != "released":
            entries.append(
                CompileErrorEntry(
                    "scenario_not_released",
                    f"scenario {scenario_id} has status "
                    f"{scenario.get('status')}, only released scenarios may run",
                    path,
                )
            )
        scenarios.append(scenario)
    return scenarios


def _expand_selectors(
    store: ResourceStore,
    manifest: dict,
    tenant_id: str,
    entries: list[CompileErrorEntry],
) -> tuple[list[dict], set[str]]:
    """Expand selectors into explicit target lists.

    Returns one result per selector plus the set of selected target
    classes. Wildcards are not representable in the contract, so every
    selection is an explicit enrolled set (spec 7, 13.1, AC-002).
    """
    results: list[dict] = []
    seen: dict[str, str] = {}
    classes: set[str] = set()
    for index, selector in enumerate(manifest["selectors"]):
        path = f"$.manifest.selectors[{index}]"
        exclusions = set(selector.get("exclusions", []))
        selected: list[str] = []
        selected_classes: set[str] = set()
        for position, target_id in enumerate(selector.get("target_ids") or []):
            target_path = f"{path}.target_ids[{position}]"
            target = store.get_target(target_id)
            if target is None:
                entries.append(
                    CompileErrorEntry(
                        "unknown_reference",
                        f"target {target_id} not found",
                        target_path,
                    )
                )
                continue
            if target.get("tenant_id") != tenant_id:
                entries.append(
                    CompileErrorEntry(
                        "tenant_mismatch",
                        f"target {target_id} belongs to tenant "
                        f"{target.get('tenant_id')}, experiment belongs to "
                        f"{tenant_id}",
                        target_path,
                    )
                )
                continue
            if target.get("status") != "enrolled":
                entries.append(
                    CompileErrorEntry(
                        "target_not_enrolled",
                        f"target {target_id} has status "
                        f"{target.get('status')}, only enrolled targets may "
                        "be selected",
                        target_path,
                    )
                )
                continue
            if target_id in exclusions:
                continue
            if target_id in seen:
                entries.append(
                    CompileErrorEntry(
                        "duplicate_target",
                        f"target {target_id} selected by {seen[target_id]} "
                        f"and selector {index}",
                        target_path,
                    )
                )
                continue
            seen[target_id] = f"selector {index}"
            selected.append(target_id)
            selected_classes.add(target.get("class", ""))
        if not selected:
            entries.append(
                CompileErrorEntry(
                    "empty_selection",
                    "selector expands to an empty enrolled set; selectors "
                    "must resolve to an explicit enrolled set and empty "
                    "expansions fail closed",
                    path,
                )
            )
        classes.update(selected_classes)
        results.append(
            {
                "selected": sorted(selected),
                "excluded": sorted(exclusions),
                "recorded_seed": selector["recorded_seed"],
            }
        )
    return results, classes


def _check_credentials(
    store: ResourceStore,
    manifest: dict,
    tenant_id: str,
    now: str,
    entries: list[CompileErrorEntry],
) -> None:
    spec = manifest["credentials"]
    now_dt = _parse_utc(now)
    max_age = timedelta(seconds=spec["freshness_max_age_s"])
    for index, kind in enumerate(spec["required_kinds"]):
        path = f"$.manifest.credentials.required_kinds[{index}]"
        credential = store.get_credential(kind)
        if credential is None:
            entries.append(
                CompileErrorEntry(
                    "unknown_reference",
                    f"credential kind {kind} not found",
                    path,
                )
            )
            continue
        if credential.get("tenant_id") != tenant_id:
            entries.append(
                CompileErrorEntry(
                    "tenant_mismatch",
                    f"credential {kind} belongs to tenant "
                    f"{credential.get('tenant_id')}, experiment belongs to "
                    f"{tenant_id}",
                    path,
                )
            )
            continue
        refreshed_at = credential.get("refreshed_at")
        if refreshed_at is None:
            entries.append(
                CompileErrorEntry(
                    "record_schema_invalid",
                    f"credential {kind} has no refreshed_at stamp",
                    path,
                )
            )
            continue
        # Compare timedeltas directly: truncating to whole seconds would
        # let an age of 3600.9 s pass a 3600 s limit.
        age = now_dt - _parse_utc(refreshed_at)
        if age > max_age:
            entries.append(
                CompileErrorEntry(
                    "stale_credential",
                    f"credential {kind} is older than "
                    f"{spec['freshness_max_age_s']} s",
                    path,
                )
            )


def _check_budgets(manifest: dict, entries: list[CompileErrorEntry]) -> None:
    budgets = manifest["budgets"]
    per_session = budgets["per_session_cost_max"]
    aggregate = budgets["aggregate_cost_max"]
    if per_session["currency"] != aggregate["currency"]:
        entries.append(
            CompileErrorEntry(
                "budget_contradiction",
                "per-session and aggregate budgets use different currencies",
                "$.manifest.budgets",
            )
        )
        return
    if per_session["micros"] > aggregate["micros"]:
        entries.append(
            CompileErrorEntry(
                "budget_contradiction",
                "per-session budget exceeds the aggregate budget; no session "
                "could ever run to completion",
                "$.manifest.budgets.per_session_cost_max",
            )
        )


def _check_stop_rules(manifest: dict, entries: list[CompileErrorEntry]) -> None:
    for index, rule in enumerate(manifest["stop_rules"]):
        if rule["condition"] == "service_health_threshold" and not (
            "threshold" in rule
        ):
            entries.append(
                CompileErrorEntry(
                    "missing_threshold",
                    "service_health_threshold requires a numeric threshold",
                    f"$.manifest.stop_rules[{index}]",
                )
            )


def _check_rollback(manifest: dict, entries: list[CompileErrorEntry]) -> None:
    rollback = manifest["rollback"]
    strategy = rollback["strategy"]
    ids = rollback.get("compensation_effect_ids", [])
    if strategy == "none" and ids:
        entries.append(
            CompileErrorEntry(
                "unsupported_rollback",
                "strategy none cannot carry compensation operations",
                "$.manifest.rollback.compensation_effect_ids",
            )
        )
    if strategy == "preapproved_compensation" and not ids:
        entries.append(
            CompileErrorEntry(
                "unsupported_rollback",
                "strategy preapproved_compensation requires at least one "
                "preapproved operation",
                "$.manifest.rollback",
            )
        )


def _check_effect_sinks(
    manifest: dict,
    mode: str,
    policy: RiskPolicy,
    entries: list[CompileErrorEntry],
) -> None:
    for index, sink in enumerate(manifest["effect_sinks"]):
        if mode in policy.synthetic_sink_modes and sink["kind"] != "synthetic":
            entries.append(
                CompileErrorEntry(
                    "sink_kind_forbidden",
                    f"mode {mode} writes only to synthetic sinks; sink "
                    f"{sink['destination']} is {sink['kind']}",
                    f"$.manifest.effect_sinks[{index}]",
                )
            )


def _check_recording(
    manifest: dict, policy: RiskPolicy, entries: list[CompileErrorEntry]
) -> None:
    required = set(manifest["recording"]["required_event_kinds"])
    for kind in sorted(policy.mandatory_event_kinds - required):
        entries.append(
            CompileErrorEntry(
                "recording_missing_required_kind",
                f"recording must require event kind {kind}",
                "$.manifest.recording.required_event_kinds",
            )
        )


def _check_scenario_eligibility(
    scenarios: list[dict],
    mode: str,
    target_classes: set[str],
    entries: list[CompileErrorEntry],
) -> None:
    """Every scenario must be eligible for this mode and target class.

    Production-safe classification is a reviewed property of a
    primitive version and a target class (spec 12.1).
    """
    for scenario in scenarios:
        eligibility = {
            (entry["mode"], entry["target_class"]): entry
            for entry in scenario.get("mode_eligibility", [])
        }
        for target_class in sorted(target_classes):
            entry = eligibility.get((mode, target_class))
            if entry is None:
                entries.append(
                    CompileErrorEntry(
                        "scenario_not_eligible",
                        f"scenario {scenario['id']} has no eligibility entry "
                        f"for mode {mode} and target class {target_class}",
                        f"scenarios/{scenario['template_id']}",
                    )
                )
            elif entry["eligible"] is not True:
                entries.append(
                    CompileErrorEntry(
                        "scenario_not_eligible",
                        f"scenario {scenario['id']} is not eligible for mode "
                        f"{mode} and target class {target_class}",
                        f"scenarios/{scenario['template_id']}",
                    )
                )


def _check_assertion_recording(
    scenarios: list[dict],
    manifest: dict,
    entries: list[CompileErrorEntry],
) -> None:
    """Every outcome assertion needs its evidence kind recorded.

    An assertion verified against an event kind the run does not
    capture can never be verified: it stays unknown forever. The
    compiler resolves outcome assertions against recording
    requirements, so the mismatch is a failure (spec 9.1, 9.5).
    """
    required = set(manifest["recording"]["required_event_kinds"])
    for scenario in scenarios:
        for assertion in scenario.get("outcome_assertions", []):
            kind = assertion.get("evidence_event_kind")
            if kind is not None and kind not in required:
                entries.append(
                    CompileErrorEntry(
                        "assertion_not_recorded",
                        f"assertion {assertion['id']} of scenario "
                        f"{scenario['id']} verifies against evidence kind "
                        f"{kind}, which the manifest does not require",
                        f"scenarios/{scenario['template_id']}",
                    )
                )
