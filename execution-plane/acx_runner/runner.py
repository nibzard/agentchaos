"""The local fixture runner (spec 9.2).

For every scenario in a compiled plan, the runner executes one baseline
variant and one treatment variant. Each variant gets a fresh disposable
environment with an identical installed baseline, runs under a
short-lived grant, and records which injections actually triggered.

The workload execution itself is pluggable. A `VariantExecutor`
receives everything a variant needs — arm, scenario, profile,
workload, seed, and workspace — and returns observations, injection
reports, or an error. The shipped executors are deterministic fixture
scripts; real workload adapters arrive with the adapter tasks.

The runner emits Run contract documents for provisioned variants.
Observations stay out of the Run document (its shape is closed); they
travel on the pair record and into the export.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol

from acx_runner.environments import (
    Environment,
    InstallError,
    LocalFixtureEnvironments,
)
from acx_runner.ids import mint_run_id
from acx_runner.outcomes import (
    normalize_injections,
    provisional_outcome,
    terminal_state_for,
)

Clock = Callable[[], str]


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class GrantExpired(Exception):
    """The compiled grant no longer authorizes new variant work."""


@dataclass(frozen=True)
class VariantSpec:
    """Everything one variant execution receives."""

    experiment_id: str
    tenant_id: str
    arm: str  # baseline or treatment
    scenario: dict
    profile: dict
    workload: dict
    target_selection_seed: int
    workspace: Path
    now: str


@dataclass
class VariantOutcome:
    """What an executor reports back for one variant."""

    observations: list[dict] = field(default_factory=list)
    injections: list[dict] = field(default_factory=list)
    error_code: str | None = None
    error: str | None = None

    @property
    def failed(self) -> bool:
        return self.error is not None


class VariantExecutor(Protocol):
    def execute(self, spec: VariantSpec) -> VariantOutcome: ...


@dataclass
class _VariantRecord:
    """Internal per-variant result."""

    run_document: dict | None  # None when nothing was provisioned
    install_digest: str | None
    observations: list[dict]
    downgraded: list[str]
    error: str | None = None


@dataclass
class PairedRun:
    """One baseline/treatment pair over one scenario."""

    pair_id: str
    scenario_version_id: str
    baseline: dict | None = None  # Run document, when provisioned
    treatment: dict | None = None
    baseline_observations: list[dict] = field(default_factory=list)
    treatment_observations: list[dict] = field(default_factory=list)
    injection_triggered: bool | None = None  # None while undetermined
    install_digest: str | None = None
    identical_baseline: bool = False
    downgraded_injections: list[str] = field(default_factory=list)
    error: str | None = None  # pair-level failure (grant, install)


class FixtureRunner:
    """Run baseline and treatment variants from a compiled plan.

    `plan_document` and `grant` come from `compile_manifest` (control
    plane). The grant is checked before every pair; an expired grant
    stops new work with a pair-level error, never a silent skip.
    """

    def __init__(
        self,
        environments: LocalFixtureEnvironments | None = None,
        *,
        clock: Clock = utc_now,
        run_id_factory=mint_run_id,
    ):
        self._environments = environments or LocalFixtureEnvironments()
        self._clock = clock
        self._run_id_factory = run_id_factory

    def run(
        self,
        plan_document: dict,
        grant: dict,
        executor: VariantExecutor,
        *,
        bundle: dict[str, str | bytes] | None = None,
        repetitions: int = 1,
        plan_digest: str | None = None,
    ) -> list[PairedRun]:
        """Execute every scenario pair, `repetitions` times over.

        `plan_digest` is the digest of `plan_document` as computed at
        compile time (`CompiledPlan.plan_digest`). When supplied, it is
        checked against the digest the grant authorizes; a mismatch
        fails every pair closed. Without it the caller vouches for the
        binding.
        """
        if repetitions < 1:
            raise ValueError("repetitions must be at least 1")
        _check_seed_consistency(plan_document)
        plan_error = _grant_plan_error(grant, plan_digest)
        bundle = bundle or {}
        pairs: list[PairedRun] = []
        scenarios = plan_document.get("scenarios", [])
        for repetition in range(repetitions):
            for index, scenario in enumerate(scenarios):
                if plan_error is not None:
                    pairs.append(
                        PairedRun(
                            pair_id=f"pair-{repetition}-{index}",
                            scenario_version_id=scenario.get("id", ""),
                            error=plan_error,
                        )
                    )
                    continue
                pairs.append(
                    self._run_pair(
                        plan_document,
                        grant,
                        executor,
                        bundle,
                        scenario,
                        pair_id=f"pair-{repetition}-{index}",
                    )
                )
        return pairs

    # Internals

    def _run_pair(
        self,
        plan_document: dict,
        grant: dict,
        executor: VariantExecutor,
        bundle: dict,
        scenario: dict,
        pair_id: str,
    ) -> PairedRun:
        pair = PairedRun(
            pair_id=pair_id,
            scenario_version_id=scenario.get("id", ""),
        )
        try:
            self._check_grant(grant)
        except GrantExpired as expired:
            pair.error = f"grant_expired: {expired}"
            return pair

        records = {
            arm: self._run_variant(
                plan_document, grant, executor, bundle, scenario, arm
            )
            for arm in ("baseline", "treatment")
        }
        pair.baseline = records["baseline"].run_document
        pair.treatment = records["treatment"].run_document
        pair.baseline_observations = records["baseline"].observations
        pair.treatment_observations = records["treatment"].observations
        for arm, record in records.items():
            pair.downgraded_injections.extend(record.downgraded)
            if (
                record.run_document is None
                and record.error
                and pair.error is None
            ):
                # A variant that never provisioned produced no Run
                # document; the pair is the only place its failure can
                # be reported (spec 14.2: harness errors are never
                # omitted). The first failure is kept.
                pair.error = f"variant_failed: {arm}: {record.error}"

        digests = [record.install_digest for record in records.values()]
        if digests[0] is not None and digests[0] == digests[1]:
            pair.identical_baseline = True
            pair.install_digest = digests[0]

        treatment_injections = (
            pair.treatment or {}
        ).get("injections", [])
        states = [
            entry.get("trigger_state") for entry in treatment_injections
        ]
        if "triggered" in states:
            pair.injection_triggered = True
        elif states and all(
            state == "not_triggered" for state in states
        ):
            pair.injection_triggered = False
        return pair

    def _run_variant(
        self,
        plan_document: dict,
        grant: dict,
        executor: VariantExecutor,
        bundle: dict,
        scenario: dict,
        arm: str,
    ) -> _VariantRecord:
        try:
            environment = self._environments.provision()
        except OSError as failure:
            return _VariantRecord(
                run_document=None,
                install_digest=None,
                observations=[],
                downgraded=[],
                error=f"provision_failed: {failure}",
            )
        released_clean = False
        try:
            record = self._execute(
                plan_document, grant, executor, bundle, scenario, arm,
                environment,
            )
        finally:
            # Disposal runs even when execution blew up; a surviving
            # workspace is reported, never hidden (spec 13.3).
            released_clean = environment.release()
        if record.run_document is None:
            return record
        record.run_document["terminal_state"] = terminal_state_for(
            executor_error=record.error, released_clean=released_clean
        )
        return record

    def _execute(
        self,
        plan_document: dict,
        grant: dict,
        executor: VariantExecutor,
        bundle: dict,
        scenario: dict,
        arm: str,
        environment: Environment,
    ) -> _VariantRecord:
        now = self._clock()
        install_digest: str | None
        try:
            install_digest = environment.install(bundle)
        except (InstallError, OSError) as failure:
            # InstallError: a bundle path tried to escape. OSError:
            # the filesystem refused (for example two bundle paths
            # claim the same file and directory).
            return _VariantRecord(
                run_document=None,
                install_digest=None,
                observations=[],
                downgraded=[],
                error=str(failure),
            )

        spec = VariantSpec(
            experiment_id=grant.get("experiment_id")
            or plan_document.get("experiment_id", ""),
            # The plan document carries no tenant binding; the signed
            # grant is where compilation pinned it (spec 18.3).
            tenant_id=grant.get("tenant_id")
            or plan_document.get("tenant_id", ""),
            arm=arm,
            scenario=dict(scenario),
            profile=dict(plan_document.get("profiles", {}).get(arm, {})),
            workload=dict(plan_document.get("workload", {})),
            target_selection_seed=_selection_seed(plan_document),
            workspace=environment.root,
            now=now,
        )
        try:
            outcome = executor.execute(spec)
        except Exception as failure:  # noqa: BLE001
            # An executor is the untrusted edge of the runner. A raise
            # is a harness failure to record, not a crash to propagate:
            # the pair survives, the workspace is still released, and
            # the remaining scenarios still run.
            outcome = VariantOutcome(
                error_code="executor_crashed",
                error=f"{type(failure).__name__}: {failure}",
            )
        if not isinstance(outcome, VariantOutcome):
            outcome = VariantOutcome(
                error_code="executor_protocol",
                error=(
                    f"executor returned {type(outcome).__name__}, not "
                    "VariantOutcome"
                ),
            )

        entries, downgraded = normalize_injections(outcome.injections)
        run_document = {
            "kind": "Run",
            "api_version": "v1",
            "id": self._run_id_factory(),
            "tenant_id": spec.tenant_id,
            "experiment_id": spec.experiment_id,
            "variant": spec.arm,
            "autonomy_profile_id": spec.profile.get("id"),
            "workload_version_id": spec.workload.get("id"),
            "state": "terminal",
            "environment": {
                "backend": spec.workload.get("backend", "local_container"),
                "instance_id": environment.instance_id,
                "fresh": True,
            },
            "randomization": {
                "target_selection_seed": spec.target_selection_seed,
            },
            "injections": entries,
            "outcome": provisional_outcome(
                executor_error=outcome.failed, injections=entries
            ),
            "created_at": spec.now,
            "finished_at": self._clock(),
        }
        if outcome.error_code is not None:
            run_document["stopped_reason"] = _stopped_reason(outcome)
        return _VariantRecord(
            run_document=run_document,
            install_digest=install_digest,
            observations=[dict(item) for item in outcome.observations],
            downgraded=downgraded,
            error=outcome.error,
        )

    def _check_grant(self, grant: dict) -> None:
        expires_at = grant.get("expires_at")
        if not isinstance(expires_at, str):
            raise GrantExpired("grant carries no expires_at")
        try:
            expiry = _parse_utc(expires_at)
        except ValueError as failure:
            raise GrantExpired(
                f"unparseable expires_at: {failure}"
            ) from None
        if expiry.tzinfo is None:
            # Offset-less timestamps parse but are ambiguous; an
            # ambiguous expiry authorizes nothing.
            raise GrantExpired(
                f"expires_at {expires_at!r} carries no UTC offset"
            )
        if expiry <= _parse_utc(self._clock()):
            raise GrantExpired(f"grant expired at {expires_at}")


def _selection_seed(plan_document: dict) -> int:
    selectors = plan_document.get("selectors", [])
    if selectors and isinstance(selectors[0].get("recorded_seed"), int):
        return selectors[0]["recorded_seed"]
    return 0


def _stopped_reason(outcome: VariantOutcome) -> str:
    """Shape an executor error into the Run stopped_reason pattern."""

    code = outcome.error_code or "executor_error"
    kept = "".join(
        character if character.isascii() and character.isalnum() else "_"
        for character in code.lower()
    ).strip("_")
    if not kept or not kept[0].isalpha():
        kept = f"e{kept}"
    # The contract pattern caps the whole field at 64 characters, so
    # truncate after the prefix, not before it.
    return kept[:64]


def _check_seed_consistency(plan_document: dict) -> None:
    """The Run contract records one target selection seed per run."""
    seeds = {
        selector.get("recorded_seed")
        for selector in plan_document.get("selectors", [])
        if isinstance(selector, dict)
        and isinstance(selector.get("recorded_seed"), int)
    }
    if len(seeds) > 1:
        raise ValueError(
            "plan selectors record conflicting target_selection_seed "
            f"values {sorted(seeds)}; the Run contract carries one"
        )


def _grant_plan_error(grant: dict, plan_digest: str | None) -> str | None:
    """Fail closed when the grant authorizes a different plan."""
    if plan_digest is None:
        return None
    grant_digest = grant.get("plan_digest")
    if grant_digest == plan_digest:
        return None
    return (
        "grant_plan_mismatch: grant authorizes plan "
        f"{grant_digest!r}, not {plan_digest!r}"
    )
