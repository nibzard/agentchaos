"""Generated long-horizon scenarios (T054, spec 12, AC-036).

Spec line 339 states the whole rule this module enforces: generated
scenarios MUST be stored, reproducible as artifacts, and evaluated for
containment before scheduling; public suites and private holdouts are
separate; and candidate failures can be minimized into regression
fixtures, but they do not become training data or public examples
without explicit data authorization.

Each rule is a gate, not a convention:

- Generation runs inside a sandbox workspace only. A workspace path
  outside the sandbox root is refused before anything is built.
- A spec is a pure function input: the same family, seed, count, and
  horizon always produce the same scenarios, ids and digests included.
  Reproduction regenerates from the spec and compares digests.
- Every scenario is a long horizon by construction: the fault fires
  near the first third and its observable effect lands near the end,
  so a bounded evidence window cannot connect cause to effect.
- Containment is evaluated before scheduling. A scenario whose steps
  name any destination outside the allowed sinks never schedules.
- Suite membership is exclusive: one scenario id cannot be both a
  public suite member and a private holdout.
- A minimized fixture carries use restrictions by default. Training
  data and public example use need an explicit authorization record
  bound to the fixture's origin digest.

Honest scope: the generator is a seeded constructor, not a model. The
deliverable is the pipeline discipline — sandbox-only generation,
stored reproducible artifacts, containment gating, suite separation,
and authorization-gated reuse — that a model-driven generator plugs
into.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from gauntlet_scenarios.lifecycle import canonical_bytes
from gauntlet_scenarios.templates import (
    BUDGET,
    DELEGATION,
    HEARTBEAT,
    PROPOSED,
    RECEIPT,
    RECOVERY,
    RESOURCE,
    TOOL_REQUEST,
    TOOL_RESPONSE,
)

# A horizon below this floor is not long-horizon: a bounded window
# could still hold the whole cause-to-effect span.
MIN_HORIZON = 64
MAX_COUNT = 256

SUITE_PUBLIC = "public"
SUITE_PRIVATE_HOLDOUT = "private_holdout"
SUITES = (SUITE_PUBLIC, SUITE_PRIVATE_HOLDOUT)

USE_TRAINING_DATA = "training_data"
USE_PUBLIC_EXAMPLE = "public_example"
RESTRICTED_USES = (USE_TRAINING_DATA, USE_PUBLIC_EXAMPLE)

CONTAINED = "contained"
ESCAPE = "escape"

FAMILY_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
PRIMITIVE_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
SINK_PATTERN = re.compile(r"^sink://[a-z0-9][a-z0-9.-]{2,127}$")
WORKSPACE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
AUTHORIZER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._@-]{2,127}$")
SCENARIO_ID_PATTERN = re.compile(r"^gsc_[0-9a-f]{16}$")

# The step pool generated horizons draw from. Kinds are the evidence
# event kinds, so a generated scenario reads like the collector stream
# it would produce.
STEP_KINDS = (
    PROPOSED,
    TOOL_REQUEST,
    TOOL_RESPONSE,
    RESOURCE,
    RECEIPT,
    HEARTBEAT,
    RECOVERY,
    BUDGET,
    DELEGATION,
)


class GeneratedScenarioError(Exception):
    """A generation, containment, suite, or use gate refused."""


def _hex(seed: str, length: int = 16) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:length]


def _byte(seed: str) -> int:
    return hashlib.sha256(seed.encode("utf-8")).digest()[0]


def scenario_digest(scenario: dict) -> str:
    """Digest over a generated scenario's canonical bytes."""
    return "sha256:" + hashlib.sha256(
        canonical_bytes(scenario)
    ).hexdigest()


def _spec_payload(spec: "GenerationSpec") -> dict:
    return {
        "family": spec.family,
        "seed": spec.seed,
        "count": spec.count,
        "horizon": spec.horizon,
        "fault_primitive": spec.fault_primitive,
        "allowed_sinks": sorted(spec.allowed_sinks),
    }


@dataclass(frozen=True)
class GenerationSpec:
    """The pure input to generation: same spec, same scenarios.

    The allowed sinks do double duty: they shape the generated receipt
    destinations and they are the allowlist containment evaluates
    against.
    """

    family: str
    seed: str
    count: int
    horizon: int
    fault_primitive: str
    allowed_sinks: tuple[str, ...]

    def validate(self) -> None:
        if not FAMILY_PATTERN.match(self.family):
            raise GeneratedScenarioError(
                f"family {self.family!r} must match "
                "^[a-z][a-z0-9-]{2,63}$"
            )
        if not self.seed:
            raise GeneratedScenarioError("the spec seed is empty")
        if not 1 <= self.count <= MAX_COUNT:
            raise GeneratedScenarioError(
                f"count {self.count} is not in 1..{MAX_COUNT}"
            )
        if self.horizon < MIN_HORIZON:
            raise GeneratedScenarioError(
                f"horizon {self.horizon} is under the floor of "
                f"{MIN_HORIZON}; a short horizon is not a long-horizon "
                "scenario"
            )
        if not PRIMITIVE_PATTERN.match(self.fault_primitive):
            raise GeneratedScenarioError(
                f"fault primitive {self.fault_primitive!r} must match "
                "^[a-z][a-z0-9_]{1,63}$"
            )
        if not self.allowed_sinks:
            raise GeneratedScenarioError(
                "the spec names no allowed sinks; containment has no "
                "allowlist to evaluate against"
            )
        for sink in self.allowed_sinks:
            if not SINK_PATTERN.match(sink):
                raise GeneratedScenarioError(
                    f"allowed sink {sink!r} must match "
                    "^sink://[a-z0-9][a-z0-9.-]{2,127}$"
                )

    def digest(self) -> str:
        """Digest over the spec's canonical payload."""
        return "sha256:" + hashlib.sha256(
            canonical_bytes(_spec_payload(self))
        ).hexdigest()


class SandboxGenerator:
    """Generates scenarios inside one sandbox root only.

    The root is fixed at construction. Every workspace name is a plain
    relative segment; a path that tries to leave the root is refused
    before any scenario is built (spec 12: generation is sandbox-only).
    """

    def __init__(self, sandbox_root: Path):
        self.root = Path(sandbox_root).resolve()

    def generate(self, spec: GenerationSpec, *, workspace: str) -> list[dict]:
        """Build the spec's scenarios inside one sandbox workspace."""
        spec.validate()
        self._require_workspace(workspace)
        return [
            self._scenario(spec, index) for index in range(spec.count)
        ]

    def store(
        self, workspace: str, scenario: dict, containment: dict
    ) -> Path:
        """Write one scenario's artifact under the sandbox root.

        The artifact carries the scenario, the containment report, and
        the digests binding them, in canonical JSON (spec 12: generated
        scenarios are stored).
        """
        self._require_workspace(workspace)
        directory = self.root / workspace
        directory.mkdir(parents=True, exist_ok=True)
        artifact = {
            "kind": "GeneratedScenarioArtifact",
            "api_version": "v1",
            "workspace": workspace,
            "spec_digest": scenario["spec_digest"],
            "scenario_digest": scenario_digest(scenario),
            "scenario": scenario,
            "containment": containment,
        }
        path = directory / f"{scenario['id']}.json"
        path.write_bytes(canonical_bytes(artifact) + b"\n")
        return path

    def reproduces(self, spec: GenerationSpec, artifact: dict) -> bool:
        """Regenerate from the spec and compare digests.

        This is the reproducibility claim made checkable: the stored
        artifact is reproducible as an artifact exactly when the spec
        regenerates the same content (spec 12).
        """
        spec.validate()
        scenarios = self.generate(
            spec, workspace=artifact.get("workspace", "reproduction")
        )
        wanted = artifact["scenario"]["id"]
        for scenario in scenarios:
            if scenario["id"] == wanted:
                return (
                    scenario_digest(scenario)
                    == artifact["scenario_digest"]
                )
        return False

    def _require_workspace(self, workspace: str) -> None:
        if not WORKSPACE_PATTERN.match(workspace):
            raise GeneratedScenarioError(
                f"workspace {workspace!r} is not a plain sandbox "
                "segment; generation runs inside the sandbox "
                "evaluation environment only (spec 12)"
            )
        resolved = (self.root / workspace).resolve()
        if resolved != self.root and self.root not in resolved.parents:
            raise GeneratedScenarioError(
                f"workspace {workspace!r} resolves outside the sandbox "
                f"root {self.root}; generation is sandbox-only"
            )

    def _scenario(self, spec: GenerationSpec, index: int) -> dict:
        scenario_id = "gsc_" + _hex(
            f"generated:{spec.family}:{spec.seed}:{index}"
        )
        fires_at = spec.horizon // 3
        lands_at = spec.horizon - 2
        steps = []
        for position in range(spec.horizon):
            if position == lands_at:
                # The fault's effect lands as a receipt at the far end
                # of the horizon: that is where containment looks.
                kind = RECEIPT
            else:
                kind = STEP_KINDS[
                    _byte(
                        f"step:{spec.family}:{spec.seed}:{index}:{position}"
                    )
                    % len(STEP_KINDS)
                ]
            step = {
                "position": position,
                "kind": kind,
                "detail": f"{spec.family} step {position} ({kind})",
            }
            if kind == RECEIPT:
                step["destination"] = self._destination(
                    spec, index, position, lands_at
                )
            steps.append(step)
        return {
            "kind": "GeneratedScenario",
            "api_version": "v1",
            "id": scenario_id,
            "family": spec.family,
            "spec_digest": spec.digest(),
            "horizon": spec.horizon,
            "fault": {
                "primitive": spec.fault_primitive,
                "fires_at_step": fires_at,
                "effect_lands_at_step": lands_at,
            },
            "steps": steps,
        }

    def _destination(
        self, spec: GenerationSpec, index: int, position: int, lands_at: int
    ) -> str:
        # Some scenarios deterministically plant one destination outside
        # the allowlist at the landing step. Containment evaluation must
        # have escapes to catch; a generator that could only produce
        # contained scenarios would prove nothing about the gate.
        if position == lands_at and _byte(
            f"escape:{spec.family}:{spec.seed}:{index}"
        ) % 5 == 0:
            return (
                "https://external-"
                + _hex(f"external:{spec.family}:{spec.seed}:{index}", 8)
                + ".example"
            )
        sink = spec.allowed_sinks[
            _byte(f"sink:{spec.family}:{spec.seed}:{index}:{position}")
            % len(spec.allowed_sinks)
        ]
        return f"{sink}/run-{index}/step-{position}"


def load_artifact(path: Path) -> dict:
    """Load and verify one stored artifact.

    The recorded scenario digest must match the stored scenario's
    canonical bytes; any edit after storage fails loudly (spec 12:
    stored artifacts are the record, not a copy the caller may fix up).
    """
    artifact = json.loads(Path(path).read_text(encoding="utf-8"))
    if artifact.get("kind") != "GeneratedScenarioArtifact":
        raise GeneratedScenarioError(
            f"{path} is not a generated scenario artifact"
        )
    scenario = artifact.get("scenario")
    if not isinstance(scenario, dict) or not SCENARIO_ID_PATTERN.match(
        scenario.get("id", "")
    ):
        raise GeneratedScenarioError(
            f"{path} carries no well-formed generated scenario"
        )
    if scenario_digest(scenario) != artifact.get("scenario_digest"):
        raise GeneratedScenarioError(
            f"{path} was edited after storage: the scenario digest no "
            "longer matches the stored scenario"
        )
    return artifact


def evaluate_containment(scenario: dict, allowed_sinks: tuple[str, ...]):
    """Evaluate one scenario against the sink allowlist.

    Containment holds when every destination in the scenario's steps
    targets an allowed sink, and only receipt steps carry destinations
    at all. The report binds to the scenario by digest, so a containment
    verdict cannot be replayed against different content.
    """
    if not allowed_sinks:
        raise GeneratedScenarioError(
            "containment evaluates against a non-empty allowlist"
        )
    violations = []
    for step in scenario["steps"]:
        destination = step.get("destination")
        if destination is None:
            continue
        if step["kind"] != RECEIPT:
            violations.append(
                {
                    "position": step["position"],
                    "violation": "destination_on_non_receipt_step",
                    "destination": destination,
                }
            )
            continue
        if not any(
            destination == sink or destination.startswith(sink + "/")
            for sink in allowed_sinks
        ):
            violations.append(
                {
                    "position": step["position"],
                    "violation": "destination_outside_allowed_sinks",
                    "destination": destination,
                }
            )
    return {
        "kind": "ContainmentReport",
        "api_version": "v1",
        "scenario_id": scenario["id"],
        "scenario_digest": scenario_digest(scenario),
        "verdict": ESCAPE if violations else CONTAINED,
        "violations": violations,
        "allowed_sinks": sorted(allowed_sinks),
    }


class SuiteRegistry:
    """Suite membership, exclusive by construction.

    One scenario id belongs to one suite: a public suite member cannot
    also be a private holdout, and reclassifying the same id under
    different content is refused (spec 12: public suites and private
    holdouts are separate).
    """

    def __init__(self) -> None:
        self._members: dict[str, dict] = {}

    def classify(self, scenario: dict, suite: str) -> None:
        if suite not in SUITES:
            raise GeneratedScenarioError(
                f"suite {suite!r} is not one of {SUITES}"
            )
        scenario_id = scenario["id"]
        digest = scenario_digest(scenario)
        existing = self._members.get(scenario_id)
        if existing is not None:
            if existing["suite"] != suite:
                raise GeneratedScenarioError(
                    f"scenario {scenario_id} is already in the "
                    f"{existing['suite']} suite; public suites and "
                    "private holdouts are separate (spec 12)"
                )
            if existing["scenario_digest"] != digest:
                raise GeneratedScenarioError(
                    f"scenario {scenario_id} was classified under "
                    "different content; publish a new id instead"
                )
            return
        self._members[scenario_id] = {
            "suite": suite,
            "scenario_digest": digest,
        }

    def suite_of(self, scenario_id: str) -> str | None:
        member = self._members.get(scenario_id)
        return member["suite"] if member else None

    def public_suite(self) -> list[str]:
        return sorted(
            scenario_id
            for scenario_id, member in self._members.items()
            if member["suite"] == SUITE_PUBLIC
        )

    def private_holdouts(self) -> list[str]:
        return sorted(
            scenario_id
            for scenario_id, member in self._members.items()
            if member["suite"] == SUITE_PRIVATE_HOLDOUT
        )


def minimize_to_fixture(
    scenario: dict, *, failure_note: str
) -> dict:
    """Minimize a failing scenario into a regression fixture.

    The fixture keeps the fault window and the landing window, not the
    whole horizon, and it carries both restricted uses as unauthorized
    by default (spec 12: candidate failures become regression fixtures,
    not training data or public examples, without explicit data
    authorization).
    """
    if not failure_note:
        raise GeneratedScenarioError(
            "a minimized fixture records what failed; the failure note "
            "is empty"
        )
    fires_at = scenario["fault"]["fires_at_step"]
    lands_at = scenario["fault"]["effect_lands_at_step"]
    window = sorted(
        set(range(max(0, fires_at - 4), min(scenario["horizon"], fires_at + 5)))
        | set(
            range(max(0, lands_at - 4), min(scenario["horizon"], lands_at + 5))
        )
    )
    return {
        "kind": "RegressionFixture",
        "api_version": "v1",
        "id": "fix_" + _hex(f"fixture:{scenario['id']}:{failure_note}"),
        "origin": {
            "scenario_id": scenario["id"],
            "scenario_digest": scenario_digest(scenario),
        },
        "failure_note": failure_note,
        "minimized_window": window,
        "horizon": scenario["horizon"],
        "use_restrictions": {
            use: "unauthorized" for use in RESTRICTED_USES
        },
        "authorizations": [],
    }


def authorize_use(
    fixture: dict, *, use: str, authorized_by: str
) -> dict:
    """Record one explicit data authorization on a fixture.

    The authorization binds to the fixture's origin digest, so it cannot
    be carried over to a fixture minimized from different content.
    """
    if use not in RESTRICTED_USES:
        raise GeneratedScenarioError(
            f"use {use!r} is not one of {RESTRICTED_USES}"
        )
    if not AUTHORIZER_PATTERN.match(authorized_by):
        raise GeneratedScenarioError(
            f"authorizer {authorized_by!r} is not a principal id"
        )
    authorization = {
        "use": use,
        "authorized_by": authorized_by,
        "authorized_for_digest": fixture["origin"]["scenario_digest"],
    }
    fixture["authorizations"].append(authorization)
    return authorization


def check_use(fixture: dict, use: str) -> dict:
    """Return the authorization permitting this use, or refuse.

    An unauthorized use fails closed: the default state of a minimized
    fixture is regression-only (spec 12).
    """
    if use not in RESTRICTED_USES:
        raise GeneratedScenarioError(
            f"use {use!r} is not one of {RESTRICTED_USES}"
        )
    digest = fixture["origin"]["scenario_digest"]
    for authorization in fixture["authorizations"]:
        if (
            authorization["use"] == use
            and authorization["authorized_for_digest"] == digest
        ):
            return authorization
    raise GeneratedScenarioError(
        f"fixture {fixture['id']} is not authorized for {use}; "
        "minimized failures do not become training data or public "
        "examples without explicit data authorization (spec 12)"
    )


def schedule(
    artifact: dict, registry: SuiteRegistry, *, suite: str
) -> dict:
    """The scheduling gate: stored, contained, and suite-classified.

    Every problem is collected before the refusal. A scenario schedules
    only when the artifact's scenario digest verifies, the containment
    report is bound to that same digest and says contained, and the
    suite registry has the scenario in exactly the requested suite
    (spec 12: evaluated for containment before scheduling).
    """
    problems: list[str] = []
    scenario = artifact["scenario"]
    if scenario_digest(scenario) != artifact.get("scenario_digest"):
        problems.append(
            "the artifact's scenario digest does not match its content"
        )
    containment = artifact.get("containment", {})
    if containment.get("scenario_digest") != artifact.get("scenario_digest"):
        problems.append(
            "the containment report is not bound to this scenario's digest"
        )
    if containment.get("verdict") != CONTAINED:
        problems.append(
            f"containment verdict is {containment.get('verdict')!r}, not "
            f"{CONTAINED!r}; a scenario that has not passed containment "
            "never schedules"
        )
    classified = registry.suite_of(scenario["id"])
    if classified is None:
        problems.append(
            f"scenario {scenario['id']} belongs to no suite; "
            "unclassified scenarios never schedule"
        )
    elif classified != suite:
        problems.append(
            f"scenario {scenario['id']} is in the {classified} suite, "
            f"not {suite}"
        )
    if problems:
        raise GeneratedScenarioError(
            "scheduling refused: " + "; ".join(problems)
        )
    return {
        "kind": "SchedulingDecision",
        "api_version": "v1",
        "scenario_id": scenario["id"],
        "scenario_digest": artifact["scenario_digest"],
        "suite": suite,
        "containment_verdict": containment["verdict"],
    }
