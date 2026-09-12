"""Real-customer canary support, designed (T055, spec 7, AC-035).

The spec is explicit that customer canaries come later and earn their
own gate: "opt-in, narrowly reversible changes to real workload
behavior" that demonstrate "limited live operating evidence within an
approved experiment class" (spec 7). The risk table says production
impact stays "synthetic only until separate canary gate" (spec 17).
AC-035 names the two hard requirements: explicit opt-in primitive
classes, and independently verified effect limits.

This module is that gate as code. Six rules, each checkable:

- **Opt-in primitive classes.** A closed registry of narrow classes.
  Nothing canaries until its class is registered, and consent is
  recorded per tenant per class.
- **Reversible semantics.** Every class declares how it reverses and
  every application carries a reverse deadline. Reversal is verified
  against independently read state, never against the canary's own
  claim — an unverified reversal fences the class for the tenant.
- **Target selection.** Explicit enrolled targets only. A target is
  re-checked immediately before every application; consent scope binds
  which targets a consent covers.
- **Automatic stop rules.** Numeric, preregistered at admission, and
  mechanical in evaluation. An unauthorized effect stops and fences
  without a threshold debate.
- **Tested containment.** A class admits only with containment
  evidence that passed, bound by digest to the class definition and
  the primitive version, carrying the exact effect limits the tests
  verified.
- **Residual-risk documentation.** Admission builds the residual risk
  document: worst-case blast radius, what reversal verification cannot
  prove, and the statement that a canary result is not a production
  assurance certificate. An operator must acknowledge it by name.

Honest scope: nothing here touches a real customer workload. The
paths are recording stand-ins. The deliverable is the opt-in
contract, the reversal verification, the stop rules, and the gates a
real path plugs into.
"""

from __future__ import annotations

import hashlib
import re
from typing import Callable

# --- identifiers -----------------------------------------------------------

TENANT_ID = re.compile(r"^tnt_[a-z0-9]{8,64}$")
TARGET_ID = re.compile(r"^tgt_[a-z0-9]{8,64}$")
CLASS_ID = re.compile(r"^cpc_[a-z0-9][a-z0-9-]{2,63}$")
PRINCIPAL = re.compile(r"^[a-z0-9][a-z0-9._@-]{2,127}$")
PRIMITIVE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

REQUEST_FIELDS = frozenset(
    {
        "kind",
        "api_version",
        "tenant_id",
        "primitive_class",
        "primitive_version",
        "targets",
        "duration_seconds",
        "max_applications",
        "stop_rules",
        "containment_evidence",
        "residual_risk_acknowledged_by",
    }
)

STOP_RULE_FIELDS = frozenset(
    {
        "max_error_rate_delta",
        "max_latency_delta_ms",
        "reversal_grace_seconds",
    }
)

# Reversal kinds. Stateless reversals need only the application to
# stop; state-carrying reversals are verified against the state they
# changed.
STATELESS = "stateless_stop"
FLAG_REVERT = "flag_registry_revert"
ROUTE_SHIFT_BACK = "route_shift_back"
REVERSAL_KINDS = (STATELESS, FLAG_REVERT, ROUTE_SHIFT_BACK)


class CanaryRefusal(Exception):
    """A canary gate refused; nothing changed."""


# --- opt-in primitive classes ----------------------------------------------


class CanaryPrimitiveClass:
    """One narrow, reversible, opt-in canary class.

    `effect_limit` carries the numeric caps an operator consents to and
    containment tests must verify: the independently verified effect
    limits of AC-035.
    """

    def __init__(
        self,
        class_id: str,
        *,
        description: str,
        reversal_kind: str,
        effect_limit: dict[str, int | float],
        max_targets: int,
        max_duration_seconds: int,
        max_applications: int,
    ):
        self.class_id = class_id
        self.description = description
        self.reversal_kind = reversal_kind
        self.effect_limit = dict(effect_limit)
        self.max_targets = max_targets
        self.max_duration_seconds = max_duration_seconds
        self.max_applications = max_applications
        problems = self._shape_problems()
        if problems:
            raise CanaryRefusal(
                f"canary class {class_id!r} is not registrable: "
                + "; ".join(problems)
            )

    def _shape_problems(self) -> list[str]:
        problems: list[str] = []
        if not CLASS_ID.match(self.class_id or ""):
            problems.append(
                "class id must match cpc_[a-z0-9][a-z0-9-]{2,63}"
            )
        if self.reversal_kind not in REVERSAL_KINDS:
            problems.append(
                f"reversal kind {self.reversal_kind!r} is not one of "
                f"{REVERSAL_KINDS}"
            )
        if not self.description:
            problems.append("the class carries no description")
        if not self.effect_limit:
            problems.append(
                "the class declares no effect limits; canary effects "
                "are bounded by declaration and verified by test "
                "(AC-035)"
            )
        for field in ("max_targets", "max_duration_seconds",
                      "max_applications"):
            value = getattr(self, field)
            if not isinstance(value, int) or value < 1:
                problems.append(f"{field} must be a positive bound")
        return problems

    def limits_digest(self) -> str:
        """Digest over the limits a consent and tests bind to."""
        payload = {
            "class_id": self.class_id,
            "reversal_kind": self.reversal_kind,
            "effect_limit": dict(sorted(self.effect_limit.items())),
            "max_targets": self.max_targets,
            "max_duration_seconds": self.max_duration_seconds,
            "max_applications": self.max_applications,
        }
        return "sha256:" + hashlib.sha256(
            repr(sorted(payload.items())).encode("utf-8")
        ).hexdigest()


# The closed initial registry. Every class is narrow, bounded, and
# reverses by design, not by cleanup effort.
RESPONSE_DELAY = CanaryPrimitiveClass(
    "cpc_response-delay",
    description=(
        "Add bounded latency to one enrolled tool response. The change "
        "is stateless: it disappears when the application stops."
    ),
    reversal_kind=STATELESS,
    effect_limit={"max_added_latency_ms": 500},
    max_targets=5,
    max_duration_seconds=900,
    max_applications=200,
)
TRANSIENT_ERROR = CanaryPrimitiveClass(
    "cpc_transient-error",
    description=(
        "Return one typed transient error from an enrolled endpoint, "
        "rate-capped. The change is stateless."
    ),
    reversal_kind=STATELESS,
    effect_limit={"max_error_rate": 0.05},
    max_targets=3,
    max_duration_seconds=600,
    max_applications=100,
)
FLAG_FLIP = CanaryPrimitiveClass(
    "cpc_flag-flip",
    description=(
        "Flip one enrolled reversible feature flag. Reversal flips it "
        "back and is verified against the flag registry."
    ),
    reversal_kind=FLAG_REVERT,
    effect_limit={"max_flags": 2},
    max_targets=2,
    max_duration_seconds=1800,
    max_applications=2,
)
TRAFFIC_SHIFT = CanaryPrimitiveClass(
    "cpc_traffic-shift",
    description=(
        "Shift a bounded fraction of enrolled traffic between two "
        "enrolled variants of the tenant's own service. Reversal "
        "shifts back and is verified against routing state."
    ),
    reversal_kind=ROUTE_SHIFT_BACK,
    effect_limit={"max_shift_fraction": 0.05},
    max_targets=1,
    max_duration_seconds=3600,
    max_applications=1,
)


class CanaryClassRegistry:
    """The closed set of classes a deployment permits."""

    def __init__(self, *classes: CanaryPrimitiveClass):
        self._classes: dict[str, CanaryPrimitiveClass] = {}
        for canary_class in classes:
            if canary_class.class_id in self._classes:
                raise CanaryRefusal(
                    f"canary class {canary_class.class_id!r} is "
                    "registered twice"
                )
            self._classes[canary_class.class_id] = canary_class

    def get(self, class_id: str) -> CanaryPrimitiveClass | None:
        return self._classes.get(class_id)

    def class_ids(self) -> list[str]:
        return sorted(self._classes)


# --- consent ---------------------------------------------------------------


class ConsentLedger:
    """Per-tenant, per-class opt-in (spec 7: opt-in canaries).

    A consent binds to the digest of the class limits as consented to.
    When a class's limits change, the digest changes and the old
    consent reads stale: limit drift needs fresh consent, not silence.
    """

    def __init__(self) -> None:
        self._consents: dict[tuple[str, str], dict] = {}

    def record(
        self,
        tenant_id: str,
        canary_class: CanaryPrimitiveClass,
        *,
        consented_by: str,
        scope_targets: list[str],
    ) -> dict:
        if not TENANT_ID.match(tenant_id or ""):
            raise CanaryRefusal(f"tenant {tenant_id!r} is not a tenant id")
        if not PRINCIPAL.match(consented_by or ""):
            raise CanaryRefusal(
                f"consenter {consented_by!r} is not a principal id"
            )
        scope = sorted(set(scope_targets))
        if not scope:
            raise CanaryRefusal(
                "consent covers an explicit target scope; an empty "
                "scope consents to nothing and is refused"
            )
        for target in scope:
            if not TARGET_ID.match(target):
                raise CanaryRefusal(
                    f"scope target {target!r} is not a target id; "
                    "wildcards are not consent"
                )
        record = {
            "kind": "CanaryConsent",
            "tenant_id": tenant_id,
            "primitive_class": canary_class.class_id,
            "consented_by": consented_by,
            "scope_targets": scope,
            "limits_digest": canary_class.limits_digest(),
            "revoked": False,
        }
        self._consents[(tenant_id, canary_class.class_id)] = record
        return dict(record)

    def revoke(self, tenant_id: str, class_id: str) -> None:
        record = self._consents.get((tenant_id, class_id))
        if record is not None:
            record["revoked"] = True

    def active_consent(
        self, tenant_id: str, canary_class: CanaryPrimitiveClass
    ) -> dict | None:
        record = self._consents.get(
            (tenant_id, canary_class.class_id)
        )
        if record is None or record["revoked"]:
            return None
        if record["limits_digest"] != canary_class.limits_digest():
            # Stale consent: the class limits moved after consent was
            # recorded. Silence is not re-consent.
            return None
        return dict(record)


# --- target enrollment -----------------------------------------------------


class CanaryTargets:
    """Explicit enrollment of canary-eligible targets (spec 7).

    A production environment is not automatically an eligible target.
    Revoke here and the next application authorization fails closed.
    """

    def __init__(self) -> None:
        self._targets: dict[str, dict] = {}

    def enroll(
        self,
        target: str,
        *,
        tenant_id: str,
        initial_state: dict | None = None,
    ) -> dict:
        if not TARGET_ID.match(target or ""):
            raise CanaryRefusal(
                f"target {target!r} is not a target id (tgt_ plus 8-64 "
                "[a-z0-9]); selectors must resolve to an explicit "
                "enrolled set"
            )
        record = {
            "target": target,
            "tenant_id": tenant_id,
            "initial_state": dict(initial_state or {}),
        }
        self._targets[target] = record
        return dict(record)

    def revoke(self, target: str) -> None:
        self._targets.pop(target, None)

    def target(self, target: str) -> dict | None:
        record = self._targets.get(target)
        return dict(record) if record else None


# --- containment evidence --------------------------------------------------


def containment_digest(
    canary_class: CanaryPrimitiveClass, primitive_version: str
) -> str:
    """Digest binding containment evidence to what was tested."""
    payload = {
        "class_id": canary_class.class_id,
        "limits_digest": canary_class.limits_digest(),
        "primitive_version": primitive_version,
    }
    return "sha256:" + hashlib.sha256(
        repr(sorted(payload.items())).encode("utf-8")
    ).hexdigest()


def containment_problems(
    canary_class: CanaryPrimitiveClass,
    primitive_version: str,
    evidence: object,
) -> list[str]:
    """Check tested containment (AC-035: verified effect limits).

    Evidence must have passed, be bound to this class's limits and
    primitive version by digest, and carry the exact effect limits the
    tests verified.
    """
    if not isinstance(evidence, dict):
        return ["containment evidence must be an object"]
    problems: list[str] = []
    if evidence.get("passed") is not True:
        problems.append(
            "the containment tests for this class have not passed; "
            "untested classes never touch customer traffic"
        )
    expected = containment_digest(canary_class, primitive_version)
    if evidence.get("digest") != expected:
        problems.append(
            "the containment evidence is not bound to this class "
            "definition and primitive version; evidence for other "
            "limits or versions does not carry (AC-035)"
        )
    verified = evidence.get("verified_limits")
    if verified != canary_class.effect_limit:
        problems.append(
            "the containment evidence verified "
            f"{verified!r}, not the declared limits "
            f"{canary_class.effect_limit!r}; effect limits are "
            "independently verified, not asserted"
        )
    return problems


# --- automatic stop rules --------------------------------------------------


def stop_rule_problems(stop_rules: object) -> list[str]:
    """Stop rules are declared numbers, not judgment calls."""
    if not isinstance(stop_rules, dict):
        return ["stop_rules must be an object"]
    problems: list[str] = []
    unknown = sorted(set(stop_rules) - STOP_RULE_FIELDS)
    missing = sorted(STOP_RULE_FIELDS - set(stop_rules))
    if unknown:
        problems.append(f"stop rules carry unknown fields {unknown}")
    if missing:
        problems.append(f"stop rules are missing {missing}")
    if problems:
        return problems
    for field in ("max_error_rate_delta", "max_latency_delta_ms",
                  "reversal_grace_seconds"):
        value = stop_rules[field]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            problems.append(f"stop rule {field!r} must be a number")
        elif value <= 0:
            problems.append(
                f"stop rule {field!r} must be positive; a canary without "
                "a stop threshold is not an automatic-stop canary"
            )
    if (
        isinstance(stop_rules["max_error_rate_delta"], (int, float))
        and not isinstance(stop_rules["max_error_rate_delta"], bool)
        and stop_rules["max_error_rate_delta"] > 1
    ):
        problems.append("an error-rate delta above 1 is not a rate")
    return problems


def evaluate_stop(stop_rules: dict, observation: dict) -> dict:
    """Evaluate one observation against the preregistered rules.

    An unauthorized effect or a late reversal stops and fences at any
    threshold: those are not statistics. Threshold breaches stop the
    canary without fencing — the class stays eligible once the cause
    is understood.
    """
    reasons: list[str] = []
    fence = False
    unauthorized = observation.get("unauthorized_effects", 0)
    if unauthorized:
        reasons.append(
            f"{unauthorized} unauthorized effects observed; stopping "
            "and fencing with no threshold debate"
        )
        fence = True
    if observation.get("reversal_past_grace"):
        reasons.append(
            "a reversal was not verified inside its grace window; "
            "stopping and fencing the class"
        )
        fence = True
    error_delta = observation.get("error_rate_delta", 0.0)
    if error_delta > stop_rules["max_error_rate_delta"]:
        reasons.append(
            f"error-rate delta {error_delta} exceeds the preregistered "
            f"stop threshold {stop_rules['max_error_rate_delta']}"
        )
    latency_delta = observation.get("latency_delta_ms", 0)
    if latency_delta > stop_rules["max_latency_delta_ms"]:
        reasons.append(
            f"latency delta {latency_delta} ms exceeds the "
            "preregistered stop threshold "
            f"{stop_rules['max_latency_delta_ms']} ms"
        )
    return {
        "kind": "CanaryStopDecision",
        "stop": bool(reasons),
        "fence": fence,
        "reasons": reasons,
    }


# --- residual-risk documentation -------------------------------------------


def residual_risk_document(
    canary_class: CanaryPrimitiveClass,
    *,
    duration_seconds: int,
    targets: int,
    acknowledged_by: str,
) -> dict:
    """Build the residual-risk document admission requires.

    The document states the worst case the caps allow, what reversal
    verification cannot prove, and that a canary result is not a
    production assurance certificate. The residual list is never
    empty: a canary design with no named residual risk has not been
    thought through.
    """
    return {
        "kind": "ResidualRiskDocument",
        "api_version": "v1",
        "primitive_class": canary_class.class_id,
        "worst_case": {
            "targets": targets,
            "duration_seconds": duration_seconds,
            "effect_limit": dict(canary_class.effect_limit),
            "max_applications": canary_class.max_applications,
        },
        "reversal": {
            "kind": canary_class.reversal_kind,
            "verified_by": "independent_state_read",
            "note": (
                "reversal is verified against independently read state, "
                "never against the canary's own claim"
            ),
        },
        "residual": [
            "effects in flight before reversal can still land after "
            "verification reads state",
            "a bounded canary population cannot rule out rare failure "
            "modes outside the observed sample",
            "monitor coverage during the canary may be unknown; no "
            "finding is not assurance",
            "a canary result is not a production assurance certificate",
        ],
        "acknowledged_by": acknowledged_by,
    }


# --- the mode --------------------------------------------------------------


class CustomerCanaryMode:
    """Admission, application, reversal, and gates for one deployment."""

    def __init__(
        self,
        *,
        classes: CanaryClassRegistry,
        consents: ConsentLedger,
        targets: CanaryTargets,
        clock: Callable[[], float],
    ) -> None:
        self.classes = classes
        self.consents = consents
        self.targets = targets
        self.clock = clock
        self._canaries: dict[str, dict] = {}
        self._applications: dict[str, list[dict]] = {}
        self._stopped: dict[str, str] = {}
        self._fenced: dict[tuple[str, str], str] = {}
        self._sequence = 0

    # --- admission ------------------------------------------------------

    def admit(self, request: dict) -> dict:
        problems = self._admission_problems(request)
        if problems:
            raise CanaryRefusal(
                "customer canary admission refused: " + "; ".join(problems)
            )
        self._sequence += 1
        canary_class = self.classes.get(request["primitive_class"])
        canary_id = (
            "cnr_"
            + hashlib.sha256(
                (
                    f"{request['tenant_id']}:"
                    f"{request['primitive_class']}:{self._sequence}"
                ).encode("utf-8")
            ).hexdigest()[:16]
        )
        record = {
            "kind": "CustomerCanaryRecord",
            "api_version": "v1",
            "canary_id": canary_id,
            "tenant_id": request["tenant_id"],
            "primitive_class": request["primitive_class"],
            "primitive_version": request["primitive_version"],
            "targets": list(request["targets"]),
            "duration_seconds": request["duration_seconds"],
            "max_applications": request["max_applications"],
            "stop_rules": dict(request["stop_rules"]),
            "containment_evidence": dict(request["containment_evidence"]),
            "admitted_at": self.clock(),
            "residual_risk": residual_risk_document(
                canary_class,
                duration_seconds=request["duration_seconds"],
                targets=len(request["targets"]),
                acknowledged_by=request["residual_risk_acknowledged_by"],
            ),
        }
        self._canaries[canary_id] = record
        self._applications[canary_id] = []
        return dict(record)

    def _admission_problems(self, request: object) -> list[str]:
        if not isinstance(request, dict):
            return ["the request must be an object"]
        problems: list[str] = []
        unknown = sorted(set(request) - REQUEST_FIELDS)
        missing = sorted(REQUEST_FIELDS - set(request))
        if unknown:
            problems.append(f"request carries unknown fields {unknown}")
        if missing:
            problems.append(f"request is missing {missing}")
        if problems:
            return problems
        if request["kind"] != "CustomerCanaryRequest":
            problems.append("kind must be CustomerCanaryRequest")
        if request["api_version"] != "v1":
            problems.append("api_version must be v1")
        if not TENANT_ID.match(request["tenant_id"] or ""):
            problems.append(
                f"tenant {request['tenant_id']!r} is not a tenant id"
            )
        if not PRIMITIVE_VERSION.match(request["primitive_version"] or ""):
            problems.append(
                "primitive_version must be semver without a v prefix"
            )
        if not PRINCIPAL.match(
            request["residual_risk_acknowledged_by"] or ""
        ):
            problems.append(
                "a named operator must acknowledge the residual-risk "
                "document before admission (spec 7, AC-035)"
            )

        canary_class = self.classes.get(request["primitive_class"])
        if canary_class is None:
            problems.append(
                f"primitive class {request['primitive_class']!r} is not "
                "in the registry; canary classes are an explicit "
                "opt-in closed set (AC-035)"
            )
        else:
            fence_reason = self._fenced.get(
                (request["tenant_id"], canary_class.class_id)
            )
            if fence_reason is not None:
                problems.append(
                    f"this tenant's {canary_class.class_id} canaries are "
                    f"fenced ({fence_reason})"
                )
            consent = self.consents.active_consent(
                request["tenant_id"], canary_class
            )
            if consent is None:
                problems.append(
                    f"no active consent for {canary_class.class_id} "
                    "covers this tenant under the current class limits; "
                    "canaries are opt-in per class (spec 7)"
                )
            else:
                outside = [
                    target
                    for target in request["targets"]
                    if target not in consent["scope_targets"]
                ]
                if outside:
                    problems.append(
                        f"targets {outside} are outside the consented "
                        "scope; consent names its targets explicitly"
                    )
            problems.extend(
                containment_problems(
                    canary_class,
                    request["primitive_version"],
                    request["containment_evidence"],
                )
            )

        problems.extend(stop_rule_problems(request["stop_rules"]))

        targets = request["targets"]
        if not isinstance(targets, list) or not targets:
            problems.append(
                "the request needs at least one explicit enrolled "
                "target (spec 7)"
            )
        else:
            if len(set(targets)) != len(targets):
                problems.append("a target is listed twice")
            if (
                canary_class is not None
                and len(set(targets)) > canary_class.max_targets
            ):
                problems.append(
                    f"{len(set(targets))} targets exceed the class cap "
                    f"of {canary_class.max_targets}"
                )
            for target in targets:
                record = self.targets.target(target)
                if record is None:
                    problems.append(
                        f"target {target!r} is not enrolled; selectors "
                        "resolve to an explicit enrolled set (spec 7)"
                    )
                elif record["tenant_id"] != request["tenant_id"]:
                    problems.append(
                        f"target {target!r} belongs to another tenant"
                    )

        if canary_class is not None:
            if (
                not isinstance(request["duration_seconds"], int)
                or request["duration_seconds"] < 1
                or request["duration_seconds"]
                > canary_class.max_duration_seconds
            ):
                problems.append(
                    f"duration must be a positive bound at or under the "
                    f"class cap of {canary_class.max_duration_seconds} "
                    "seconds"
                )
            if (
                not isinstance(request["max_applications"], int)
                or request["max_applications"] < 1
                or request["max_applications"]
                > canary_class.max_applications
            ):
                problems.append(
                    f"max_applications must be a positive bound at or "
                    "under the class cap of "
                    f"{canary_class.max_applications}"
                )
        return problems

    # --- per-application authorization ---------------------------------

    def apply(self, canary_id: str, target_id: str) -> dict:
        """Authorize one application, re-checking everything now.

        Spec 7: consent and enrollment are checked again immediately
        before each application. A consent revoked since admission
        fails closed here.
        """
        problems = self._application_problems(canary_id, target_id)
        if problems:
            raise CanaryRefusal(
                "canary application refused: " + "; ".join(problems)
            )
        record = self._canaries[canary_id]
        canary_class = self.classes.get(record["primitive_class"])
        self._sequence += 1
        applied_at = self.clock()
        application = {
            "kind": "CanaryApplication",
            "application_id": (
                "cap_"
                + hashlib.sha256(
                    f"{canary_id}:{target_id}:{self._sequence}".encode(
                        "utf-8"
                    )
                ).hexdigest()[:16]
            ),
            "canary_id": canary_id,
            "target": target_id,
            "sequence": self._sequence,
            "applied_at": applied_at,
            "reverse_deadline": applied_at + record["duration_seconds"],
            "reversal_kind": canary_class.reversal_kind,
            "reversed": False,
        }
        self._applications[canary_id].append(application)
        return dict(application)

    def _application_problems(
        self, canary_id: str, target_id: str
    ) -> list[str]:
        record = self._canaries.get(canary_id)
        if record is None:
            return [f"unknown canary {canary_id!r}"]
        problems: list[str] = []
        if canary_id in self._stopped:
            problems.append(
                f"the canary is stopped ({self._stopped[canary_id]})"
            )
        canary_class = self.classes.get(record["primitive_class"])
        if canary_class is None:
            problems.append("the class left the registry")
            return problems
        fence_reason = self._fenced.get(
            (record["tenant_id"], canary_class.class_id)
        )
        if fence_reason is not None:
            problems.append(
                f"this tenant's {canary_class.class_id} canaries are "
                f"fenced ({fence_reason})"
            )
        if (
            self.consents.active_consent(record["tenant_id"], canary_class)
            is None
        ):
            problems.append(
                "the consent for this class was revoked or went stale; "
                "refusing the application"
            )
        target = self.targets.target(target_id)
        if target is None:
            problems.append(
                f"target {target_id!r} is no longer enrolled; refusing "
                "the application"
            )
        elif target_id not in record["targets"]:
            problems.append(
                f"target {target_id!r} is outside the admitted set; "
                "selector expansion is refused"
            )
        if len(self._applications[canary_id]) >= record["max_applications"]:
            problems.append("the application budget is exhausted")
        if self.clock() >= record["admitted_at"] + record["duration_seconds"]:
            problems.append("the canary's duration is exhausted")
        return problems

    # --- observation-driven automatic stop -------------------------------

    def observe(self, canary_id: str, observation: dict) -> dict:
        """Evaluate one observation against the stop rules.

        Stopping reverses every application. A fenced stop fences the
        class for the tenant until an operator clears it with a reason.
        """
        record = self._canaries.get(canary_id)
        if record is None:
            raise CanaryRefusal(f"unknown canary {canary_id!r}")
        decision = evaluate_stop(record["stop_rules"], observation)
        if decision["stop"]:
            canary_class = self.classes.get(record["primitive_class"])
            if decision["fence"] and canary_class is not None:
                self._fenced[(record["tenant_id"], canary_class.class_id)] = (
                    "; ".join(decision["reasons"])
                )
            self.stop(canary_id, "; ".join(decision["reasons"]))
        return dict(decision)

    # --- reversal --------------------------------------------------------

    def stop(self, canary_id: str, reason: str) -> dict:
        if canary_id not in self._canaries:
            raise CanaryRefusal(f"unknown canary {canary_id!r}")
        if canary_id not in self._stopped:
            self._stopped[canary_id] = reason
            self._reverse_all(canary_id)
        return self.report(canary_id)

    def _reverse_all(self, canary_id: str) -> None:
        for application in self._applications[canary_id]:
            application["reversed"] = True

    def verify_reversal(
        self, canary_id: str, state_readings: dict[str, dict]
    ) -> dict:
        """Independently verify reversal from state readings.

        The readings come from outside the canary: the flag registry,
        the routing table, or the observed next call. A missing reading
        or a reading that still shows the injected state is an
        unverified reversal: the result is UNKNOWN and the class fences.
        """
        record = self._canaries.get(canary_id)
        if record is None:
            raise CanaryRefusal(f"unknown canary {canary_id!r}")
        canary_class = self.classes.get(record["primitive_class"])
        if canary_class is None:
            raise CanaryRefusal("the class left the registry")
        unverified: list[str] = []
        for application in self._applications[canary_id]:
            target = application["target"]
            reading = state_readings.get(target)
            if reading is None:
                unverified.append(target)
                continue
            if not _reading_shows_reversed(
                canary_class, application, reading
            ):
                unverified.append(target)
        verified = not unverified and bool(self._applications[canary_id])
        result = {
            "kind": "ReversalVerification",
            "canary_id": canary_id,
            "verified_by": "independent_state_read",
            "applications": len(self._applications[canary_id]),
            "unverified_targets": sorted(set(unverified)),
            "verified": verified,
        }
        if not verified:
            self._fenced[(record["tenant_id"], canary_class.class_id)] = (
                "reversal was not verified against independently read "
                f"state: {sorted(set(unverified)) or 'no applications'}"
            )
        return result

    # --- fencing ----------------------------------------------------------

    def unfence(self, tenant_id: str, class_id: str, reason: str) -> None:
        if not reason:
            raise CanaryRefusal(
                "clearing a fence records its reason; a silent unfence "
                "is a silent limit change"
            )
        self._fenced.pop((tenant_id, class_id), None)

    def fenced(self, tenant_id: str, class_id: str) -> str | None:
        return self._fenced.get((tenant_id, class_id))

    # --- reporting and gates ----------------------------------------------

    def report(self, canary_id: str) -> dict:
        record = self._canaries.get(canary_id)
        if record is None:
            raise CanaryRefusal(f"unknown canary {canary_id!r}")
        return {
            "kind": "CanaryStopReport",
            "api_version": "v1",
            "canary_id": canary_id,
            "stopped": canary_id in self._stopped,
            "reason": self._stopped.get(canary_id),
            "applications": len(self._applications[canary_id]),
            "residual_risk": dict(record["residual_risk"]),
        }

    def opt_in_gate(self, canary_id: str) -> dict:
        """Consent is active and covers every admitted target."""
        record = self._canaries.get(canary_id)
        if record is None:
            return _gate("opt_in", False, f"unknown canary {canary_id!r}")
        canary_class = self.classes.get(record["primitive_class"])
        consent = (
            self.consents.active_consent(record["tenant_id"], canary_class)
            if canary_class
            else None
        )
        problems: list[str] = []
        if consent is None:
            problems.append(
                "no active consent under the current class limits"
            )
        else:
            outside = [
                target
                for target in record["targets"]
                if target not in consent["scope_targets"]
            ]
            if outside:
                problems.append(f"targets {outside} left the consent scope")
        if self._fenced.get((record["tenant_id"], record["primitive_class"])):
            problems.append("the class is fenced for this tenant")
        if problems:
            return _gate("opt_in", False, "; ".join(problems))
        return _gate(
            "opt_in", True,
            f"consent by {consent['consented_by']} covers "
            f"{consent['scope_targets']} under limits "
            f"{consent['limits_digest'][:16]}",
        )

    def containment_gate(self, canary_id: str) -> dict:
        """The admitted containment evidence still binds."""
        record = self._canaries.get(canary_id)
        if record is None:
            return _gate(
                "containment", False, f"unknown canary {canary_id!r}"
            )
        canary_class = self.classes.get(record["primitive_class"])
        if canary_class is None:
            return _gate("containment", False, "the class left the registry")
        problems = containment_problems(
            canary_class,
            record["primitive_version"],
            record["containment_evidence"],
        )
        if problems:
            return _gate("containment", False, "; ".join(problems))
        return _gate(
            "containment", True,
            f"containment evidence bound to {canary_class.class_id} at "
            f"{record['primitive_version']} with verified limits "
            f"{canary_class.effect_limit}",
        )

    def reversal_gate(self, canary_id: str) -> dict:
        """Every application reversed and verified independently."""
        record = self._canaries.get(canary_id)
        if record is None:
            return _gate("reversal", False, f"unknown canary {canary_id!r}")
        applications = self._applications[canary_id]
        if not applications:
            return _gate(
                "reversal", False, "no applications ran, nothing verified"
            )
        outstanding = [
            application["target"]
            for application in applications
            if not application["reversed"]
        ]
        if outstanding:
            return _gate(
                "reversal", False,
                f"applications on {outstanding} never reversed",
            )
        if canary_id not in self._stopped:
            return _gate(
                "reversal", False, "the canary has not stopped yet"
            )
        return _gate(
            "reversal", True,
            f"{len(applications)} applications reversed; verification "
            "against independently read state is reported separately "
            "by verify_reversal",
        )

    def assess(self, canary_id: str) -> dict:
        """Run the three canary gates; passed means all three."""
        gates = {
            gate["gate"]: gate
            for gate in (
                self.opt_in_gate(canary_id),
                self.containment_gate(canary_id),
                self.reversal_gate(canary_id),
            )
        }
        return {
            "kind": "CanaryGateAssessment",
            "api_version": "v1",
            "canary_id": canary_id,
            "gates": gates,
            "passed": all(gate["passed"] for gate in gates.values()),
        }


def _gate(name: str, passed: bool, detail: str) -> dict:
    return {"gate": name, "passed": passed, "detail": detail}


def _reading_shows_reversed(
    canary_class: CanaryPrimitiveClass,
    application: dict,
    reading: dict,
) -> bool:
    """One state reading, judged against the class's reversal kind.

    The reading comes from the system the class changed — never from
    the canary — so a lying canary cannot verify its own reversal.
    """
    if canary_class.reversal_kind == STATELESS:
        # A stateless change is reversed when the observed behavior no
        # longer shows the injected shape.
        observed = reading.get("observed_effect_magnitude", None)
        return observed == 0
    if canary_class.reversal_kind == FLAG_REVERT:
        return reading.get("flag_value") == reading.get("original_value")
    if canary_class.reversal_kind == ROUTE_SHIFT_BACK:
        shift = reading.get("current_shift_fraction", None)
        return shift == 0
    return False
