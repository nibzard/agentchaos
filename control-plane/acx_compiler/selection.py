"""Target selection: explicit, enrolled, and rechecked (spec 7, 13.1, 13.2).

Selectors must resolve to an explicit enrolled set. Wildcard public
destinations are not representable in the Experiment contract, and this
module still treats every gap in the explicit set as a failure:

- a selector without target_ids compiles nothing and fails closed;
- every referenced target must be a contract-valid Target record;
- every referenced target must belong to the experiment tenant and be
  enrolled at expansion time;
- every exclusion must name a target visible in the tenant, so a typo
  cannot silently widen the selection;
- production modes additionally require the mode in the target's
  recorded opt-in list (spec 13.4), because an unrecorded opt-in makes
  production selection ambiguous rather than merely risky;
- one target may not be selected by two selectors.

`revalidate_selection` re-runs the same expansion immediately before
each injection and compares it with the compiled snapshot. Any drift,
and especially any growth of the set, fails closed as an
`unexpected_target_expansion` trip condition (spec 13.2).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from acx_schemas import ContractViolation, validate

from acx_compiler.errors import CompileErrorEntry, CompileViolation

PRODUCTION_MODES = frozenset({"production_synthetic", "customer_canary"})


@dataclass(frozen=True)
class SelectionPolicy:
    """What selection requires beyond the contract.

    The server owns the policy; callers cannot widen it through a
    manifest. `production_modes` is the set of modes that require a
    recorded per-target opt-in.
    """

    production_modes: frozenset[str] = PRODUCTION_MODES


DEFAULT_SELECTION_POLICY = SelectionPolicy()


@dataclass(frozen=True)
class SelectionOutcome:
    """The result of expanding every selector in a manifest.

    `selectors` carries one audit entry per selector: the explicit
    selected ids, the excluded ids, and the recorded seed (spec 13.1).
    `entries` is empty exactly when the selection is sound.
    """

    selectors: list[dict] = field(default_factory=list)
    target_classes: frozenset[str] = frozenset()
    entries: tuple[CompileErrorEntry, ...] = ()


def expand_selectors(
    selectors: list[dict],
    store,
    *,
    tenant_id: str,
    mode: str,
    policy: SelectionPolicy | None = None,
) -> SelectionOutcome:
    """Expand selectors into explicit enrolled target lists.

    Collects every failure instead of stopping at the first, so callers
    can report the whole picture. Partial results accompany failures;
    callers must treat a non-empty `entries` as a refusal to select.
    """
    policy = policy or DEFAULT_SELECTION_POLICY
    entries: list[CompileErrorEntry] = []
    results: list[dict] = []
    seen: dict[str, str] = {}
    classes: set[str] = set()

    for index, selector in enumerate(selectors):
        path = f"$.manifest.selectors[{index}]"
        kind = selector.get("kind")
        if kind != "enrolled_targets":
            entries.append(
                CompileErrorEntry(
                    "selector_kind_forbidden",
                    f"selector kind {kind!r} is not supported; selectors "
                    "must resolve to an explicit enrolled set",
                    f"{path}.kind",
                )
            )
            continue

        exclusions = set(selector.get("exclusions") or [])
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
            if not _check_target_record(target, target_path, entries):
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
            if mode in policy.production_modes and mode not in (
                target.get("enrollment", {}).get("opt_in_modes") or []
            ):
                entries.append(
                    CompileErrorEntry(
                        "target_not_opted_in",
                        f"target {target_id} has no recorded opt-in for "
                        f"production mode {mode}; production selection "
                        "without a recorded opt-in is ambiguous and fails "
                        "closed",
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

        for position, excluded_id in enumerate(sorted(exclusions)):
            excluded_path = f"{path}.exclusions[{position}]"
            record = store.get_target(excluded_id)
            if record is None or record.get("tenant_id") != tenant_id:
                entries.append(
                    CompileErrorEntry(
                        "unknown_reference",
                        f"excluded target {excluded_id} not found in "
                        f"tenant {tenant_id}; an exclusion that names "
                        "nothing cannot be verified to exclude anything",
                        excluded_path,
                    )
                )

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
                "recorded_seed": selector.get("recorded_seed", 0),
                # Binding to the compile-time mode and tenant lets the
                # pre-injection recheck refuse a lowered mode, which
                # would otherwise skip the production opt-in recheck.
                "mode": mode,
                "tenant_id": tenant_id,
            }
        )

    return SelectionOutcome(
        selectors=results,
        target_classes=frozenset(classes),
        entries=tuple(entries),
    )


def resolve_selectors(
    selectors: list[dict],
    store,
    *,
    tenant_id: str,
    mode: str,
    policy: SelectionPolicy | None = None,
) -> SelectionOutcome:
    """Fail-closed wrapper around `expand_selectors`.

    Raises CompileViolation when anything is wrong. Use this outside the
    compiler, where there is no other check whose failures should
    accumulate with these.
    """
    outcome = expand_selectors(
        selectors, store, tenant_id=tenant_id, mode=mode, policy=policy
    )
    if outcome.entries:
        raise CompileViolation(list(outcome.entries))
    return outcome


def revalidate_selection(
    selectors: list[dict],
    snapshot: list[dict],
    store,
    *,
    tenant_id: str,
    mode: str,
    policy: SelectionPolicy | None = None,
) -> None:
    """Re-check a compiled selection immediately before an injection.

    Spec 7 requires the enrolled set to be checked again immediately
    before each injection; spec 13.2 makes unexpected target expansion a
    trip condition. The check re-expands the manifest selectors against
    the live store and compares the result with the snapshot recorded in
    the compiled plan. Any difference fails closed: a target that left
    enrollment, a revoked opt-in, a changed seed or exclusion list, or a
    set that grew beyond the compiled snapshot.
    """
    entries: list[CompileErrorEntry] = []
    if not isinstance(snapshot, list) or len(snapshot) != len(selectors):
        entries.append(
            CompileErrorEntry(
                "selection_drift",
                "compiled selection does not have one entry per manifest "
                "selector",
                "$.plan.selectors",
            )
        )
        raise CompileViolation(entries)

    outcome = expand_selectors(
        selectors, store, tenant_id=tenant_id, mode=mode, policy=policy
    )
    if outcome.entries:
        # The live store no longer supports this selection at all.
        raise CompileViolation(list(outcome.entries))

    for index, (fresh, recorded) in enumerate(zip(outcome.selectors, snapshot)):
        path = f"$.plan.selectors[{index}]"
        if not isinstance(recorded, dict):
            entries.append(
                CompileErrorEntry(
                    "selection_drift",
                    "compiled selection entry is malformed",
                    path,
                )
            )
            continue
        if recorded.get("mode") != fresh["mode"]:
            entries.append(
                CompileErrorEntry(
                    "selection_mode_mismatch",
                    f"compiled selection was made for mode "
                    f"{recorded.get('mode')!r}, revalidation ran for "
                    f"{fresh['mode']!r}; a changed mode voids the opt-in "
                    "recheck and fails closed",
                    f"{path}.mode",
                )
            )
        if recorded.get("tenant_id") != fresh["tenant_id"]:
            entries.append(
                CompileErrorEntry(
                    "selection_tenant_mismatch",
                    f"compiled selection belongs to tenant "
                    f"{recorded.get('tenant_id')!r}, revalidation ran for "
                    f"{fresh['tenant_id']!r}",
                    f"{path}.tenant_id",
                )
            )
        recorded_ids = _recorded_ids(recorded, path, entries)
        fresh_ids = set(fresh["selected"])
        for target_id in sorted(fresh_ids - recorded_ids):
            entries.append(
                CompileErrorEntry(
                    "unexpected_target_expansion",
                    f"selection now includes target {target_id}, which the "
                    "compiled plan does not; this is a trip condition "
                    "(spec 13.2)",
                    f"{path}.selected",
                )
            )
        for target_id in sorted(recorded_ids - fresh_ids):
            entries.append(
                CompileErrorEntry(
                    "selection_drift",
                    f"compiled selection includes target {target_id}, which "
                    "the selectors no longer resolve to",
                    f"{path}.selected",
                )
            )
        if recorded.get("recorded_seed") != fresh["recorded_seed"]:
            entries.append(
                CompileErrorEntry(
                    "selection_drift",
                    "recorded seed no longer matches the manifest selector",
                    f"{path}.recorded_seed",
                )
            )
        if set(recorded.get("excluded") or []) != set(fresh["excluded"]):
            entries.append(
                CompileErrorEntry(
                    "selection_drift",
                    "exclusion list no longer matches the manifest selector",
                    f"{path}.excluded",
                )
            )

    if entries:
        raise CompileViolation(entries)


def _recorded_ids(
    recorded, path: str, entries: list[CompileErrorEntry]
) -> set[str]:
    """Read the snapshot's selected ids without trusting its shape."""
    if not isinstance(recorded, dict) or not isinstance(
        recorded.get("selected"), list
    ):
        entries.append(
            CompileErrorEntry(
                "selection_drift",
                "compiled selection entry is malformed",
                path,
            )
        )
        return set()
    ids = recorded["selected"]
    if not all(isinstance(value, str) for value in ids):
        entries.append(
            CompileErrorEntry(
                "selection_drift",
                "compiled selection entry contains a non-string target id",
                f"{path}.selected",
            )
        )
        return set()
    return set(ids)


def _check_target_record(
    target: dict, path: str, entries: list[CompileErrorEntry]
) -> bool:
    """Validate a target record against the Target contract."""
    try:
        validate(target, "Target")
        return True
    except ContractViolation as exc:
        first = exc.as_dict()["errors"][0]
        entries.append(
            CompileErrorEntry(
                "record_schema_invalid",
                f"Target record invalid: {first['message']}",
                path,
            )
        )
        return False
