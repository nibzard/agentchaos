"""Production synthetic mode (T049, spec 7 and 13.4, AC-031).

The spec permits enrolled synthetic sessions through production-path
services "only after the isolated and integration gates pass," and
demands five things of every such experiment: verified enrollment, an
independent kill path, cost limits, known effect sinks, and cleanup
evidence. Synthetic sessions carry dedicated identities, stay out of
ordinary customer outcome statistics, and get measured separately for
shared-resource impact.

This module is the gatekeeper. `ProductionSyntheticMode.admit` checks
every requirement and fails closed with the whole problem list.
Authorization happens again immediately before each injection, so a
target revoked after admission still blocks. `kill` actuates a kill
path that never calls into the session, so a dead or hostile session
cannot block it. `stop` runs cleanup and hands the result to an
independent verifier. Three gates — isolation, kill, cleanup — decide
whether the session passed (AC-031).

Honest scope: the production path here is a recording stand-in. No
production-path service exists in this repository. The deliverable is
the admission contract, the per-injection re-checks, the independent
kill, the cleanup verdicts, and the statistical separation — the parts
a real path plugs into.
"""

from __future__ import annotations

import hashlib
import re
from typing import Protocol

from gauntlet_scenarios.lifecycle import RELEASED, classification_status

# Dedicated synthetic identities (spec 13.4): never a customer or
# worker identity.
SYNTHETIC_IDENTITY = re.compile(r"^syn_[a-z0-9]{8,64}$")
TARGET_ID = re.compile(r"^tgt_[a-z0-9]{8,64}$")
SINK_ID = re.compile(r"^sink_[a-z0-9]{8,64}$")

# Destinations an enrolled target may carry. No wildcard and no open
# public destination is permitted (spec 7).
DESTINATION_SCHEMES = ("queue://", "topic://", "bucket://")
WILDCARD = re.compile(r"[*?\[\]]")

REQUEST_FIELDS = frozenset(
    {
        "kind",
        "api_version",
        "tenant_id",
        "scenario",
        "identity",
        "targets",
        "sinks",
        "primitive_version",
        "workload_fingerprint",
        "integration_evidence",
        "cost_limit",
    }
)

# Synthetic sessions are their own statistical population (spec 13.4).
POPULATION = "production_synthetic"

CLEAN = "CLEAN"
DIRTY_QUARANTINED = "DIRTY_QUARANTINED"
UNKNOWN = "UNKNOWN"


class ProductionRefusal(Exception):
    """The production mode refused; nothing changed."""


# --- enrollment ---------------------------------------------------------


class Enrollment:
    """Explicit enrollment of synthetic identities and targets (spec 7).

    A production environment is not automatically an eligible target.
    Admission resolves against this registry, and so does every single
    injection: revoke here and the next authorization fails closed.
    """

    def __init__(self) -> None:
        self._identities: dict[str, dict] = {}
        self._targets: dict[str, dict] = {}

    def enroll_identity(
        self, identity: str, *, tenant_id: str, budget_effects: int
    ) -> dict:
        if not SYNTHETIC_IDENTITY.match(identity or ""):
            raise ProductionRefusal(
                f"identity {identity!r} is not a dedicated synthetic "
                "identity (syn_ plus 8-64 [a-z0-9])"
            )
        if not isinstance(budget_effects, int) or budget_effects < 1:
            raise ProductionRefusal(
                "a synthetic identity needs a bounded effect budget"
            )
        record = {
            "identity": identity,
            "tenant_id": tenant_id,
            "budget_effects": budget_effects,
        }
        self._identities[identity] = record
        return dict(record)

    def revoke_identity(self, identity: str) -> None:
        self._identities.pop(identity, None)

    def identity(self, identity: str) -> dict | None:
        record = self._identities.get(identity)
        return dict(record) if record else None

    def enroll_target(
        self,
        target: str,
        *,
        tenant_id: str,
        destination: str,
        sink: str,
        target_class: str,
    ) -> dict:
        if not TARGET_ID.match(target or ""):
            raise ProductionRefusal(
                f"target {target!r} is not a target id (tgt_ plus 8-64 "
                "[a-z0-9])"
            )
        problems = _destination_problems(destination)
        if not SINK_ID.match(sink or ""):
            problems.append(
                f"sink {sink!r} is not a sink id (sink_ plus 8-64 [a-z0-9])"
            )
        if problems:
            raise ProductionRefusal("; ".join(problems))
        record = {
            "target": target,
            "tenant_id": tenant_id,
            "destination": destination,
            "sink": sink,
            "target_class": target_class,
        }
        self._targets[target] = record
        return dict(record)

    def revoke_target(self, target: str) -> None:
        self._targets.pop(target, None)

    def target(self, target: str) -> dict | None:
        record = self._targets.get(target)
        return dict(record) if record else None


def _destination_problems(destination: str) -> list[str]:
    problems: list[str] = []
    if not isinstance(destination, str) or not destination:
        return ["a target needs a destination"]
    if WILDCARD.search(destination):
        problems.append(
            f"destination {destination!r} carries a wildcard; wildcard "
            "public destinations are not permitted (spec 7)"
        )
    if not destination.startswith(DESTINATION_SCHEMES):
        problems.append(
            f"destination {destination!r} does not use a known scheme "
            f"({', '.join(DESTINATION_SCHEMES)})"
        )
    return problems


class PrimitiveRegistry:
    """Registered production fault primitives (spec 8.1).

    Production synthetic mode permits only registered primitives.
    Generated injection code stays in isolated evaluation environments
    until it is reviewed into this registry.
    """

    def __init__(self) -> None:
        self._registered: set[tuple[str, str]] = set()

    def register(self, fault_kind: str, primitive_version: str) -> None:
        self._registered.add((fault_kind, primitive_version))

    def registered(self, fault_kind: str, primitive_version: str) -> bool:
        return (fault_kind, primitive_version) in self._registered


# --- the production path stand-in ---------------------------------------


class ProductionPath(Protocol):
    """What production-path services must provide for the mode."""

    def deliver(self, session_id: str, sink: str, payload: dict) -> dict:
        """Land one effect in a sink; return the effect record."""
        ...

    def inventory(self, session_id: str) -> list[dict]:
        """Every effect record for one session."""
        ...

    def drain(self, effect_id: str) -> bool:
        """Compensate one effect; False when it cannot be undone."""
        ...

    def quarantine(self, effect_id: str) -> None:
        """Fence one effect: it stays, but nothing may reuse it."""
        ...


class RecordingProductionPath:
    """An in-process recording stand-in for production-path services.

    Every effect is recorded with the sink it landed in. `drain`
    removes an effect (the preapproved compensation); `quarantine`
    fences one in place — a quarantined effect can never be drained or
    reassigned, only left dirty (spec 13.3).
    """

    def __init__(self) -> None:
        self._by_session: dict[str, list[dict]] = {}
        self._by_id: dict[str, dict] = {}
        self._sequence = 0

    def deliver(self, session_id: str, sink: str, payload: dict) -> dict:
        self._sequence += 1
        effect_id = "eff_" + hashlib.sha256(
            f"{session_id}:{sink}:{self._sequence}".encode("utf-8")
        ).hexdigest()[:16]
        effect = {
            "effect_id": effect_id,
            "session_id": session_id,
            "sink": sink,
            "payload": dict(payload or {}),
            "state": "landed",
            "sequence": self._sequence,
        }
        self._by_session.setdefault(session_id, []).append(effect)
        self._by_id[effect_id] = effect
        return dict(effect)

    def inventory(self, session_id: str) -> list[dict]:
        return [
            dict(effect)
            for effect in self._by_session.get(session_id, [])
        ]

    def drain(self, effect_id: str) -> bool:
        effect = self._by_id.get(effect_id)
        if effect is None or effect["state"] != "landed":
            return False
        effect["state"] = "drained"
        return True

    def quarantine(self, effect_id: str) -> None:
        effect = self._by_id.get(effect_id)
        if effect is not None:
            effect["state"] = "quarantined"


class SinkCleanupVerifier:
    """The independent cleanup verifier (spec 13.3).

    Walks the path's own records. Never asks the session, the worker,
    or the executor: cleanup is never proven by the thing that ran.
    """

    name = "sink-cleanup-verifier"

    def verify(self, path: ProductionPath, session_id: str) -> dict:
        inventory = path.inventory(session_id)
        remaining = sorted(
            effect["effect_id"] for effect in inventory
            if effect["state"] == "landed"
        )
        quarantined = sorted(
            effect["effect_id"] for effect in inventory
            if effect["state"] == "quarantined"
        )
        if remaining:
            verdict = UNKNOWN
        elif quarantined:
            verdict = DIRTY_QUARANTINED
        else:
            verdict = CLEAN
        return {
            "verifier": self.name,
            "verdict": verdict,
            "remaining": remaining,
            "quarantined": quarantined,
            "effects_total": len(inventory),
        }


# --- the independent kill path ------------------------------------------


class IndependentKillPath:
    """The kill authority, outside the session's call stack.

    Independence is structural (spec 7, AC-031): actuation touches
    this object and the mode's own state only. The session is never
    called, so a dead, hung, or hostile session cannot prevent the
    kill.
    """

    def __init__(self) -> None:
        self._armed = True
        self._actuations: list[dict] = []

    def disarm(self) -> None:
        self._armed = False

    def arm(self) -> None:
        self._armed = True

    def verify(self) -> dict:
        return {
            "armed": self._armed,
            "actuations": len(self._actuations),
        }

    def actuate(
        self, session_id: str, reason: str, sequence: int
    ) -> dict:
        record = {
            "kind": "KillRecord",
            "session_id": session_id,
            "reason": reason,
            "sequence": sequence,
        }
        self._actuations.append(record)
        return dict(record)


# --- the mode ------------------------------------------------------------


class ProductionSyntheticMode:
    """Admission, authorization, kill, and cleanup for one deployment."""

    def __init__(
        self,
        *,
        enrollment: Enrollment,
        primitives: PrimitiveRegistry,
        path: ProductionPath,
        verifier: SinkCleanupVerifier | None = None,
        kill_path: IndependentKillPath | None = None,
    ) -> None:
        self.enrollment = enrollment
        self.primitives = primitives
        self.path = path
        self.verifier = verifier or SinkCleanupVerifier()
        self.kill_path = kill_path or IndependentKillPath()
        self._sessions: dict[str, dict] = {}
        self._authorizations: dict[str, list[dict]] = {}
        self._kills: dict[str, dict] = {}
        self._stopped: dict[str, str] = {}
        self._reports: dict[str, dict] = {}
        self._sequence = 0

    # --- admission (spec 7: verified enrollment, gates, cost, sinks) ---

    def admit(self, request: dict) -> "ProductionSession":
        problems = self._admission_problems(request)
        if problems:
            raise ProductionRefusal(
                "production synthetic admission refused: "
                + "; ".join(problems)
            )
        scenario = request["scenario"]
        self._sequence += 1
        session_id = "sxn_" + hashlib.sha256(
            f"{request['identity']}:{scenario['id']}:{self._sequence}"
            .encode("utf-8")
        ).hexdigest()[:16]
        self._sessions[session_id] = {
            "kind": "ProductionSessionRecord",
            "api_version": "v1",
            "session_id": session_id,
            "population": POPULATION,
            "tenant_id": request["tenant_id"],
            "scenario_version_id": scenario["id"],
            "template_id": scenario.get("template_id"),
            "fault_kind": scenario["fault"]["kind"],
            "identity": request["identity"],
            "targets": list(request["targets"]),
            "sinks": list(request["sinks"]),
            "primitive_version": request["primitive_version"],
            "workload_fingerprint": request["workload_fingerprint"],
            "integration_evidence": dict(request["integration_evidence"]),
            "cost_limit": dict(request["cost_limit"]),
        }
        self._authorizations[session_id] = []
        return ProductionSession(self, session_id)

    def _admission_problems(self, request: dict) -> list[str]:
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
        if request["kind"] != "ProductionSyntheticRequest":
            problems.append("kind must be ProductionSyntheticRequest")
        if request["api_version"] != "v1":
            problems.append("api_version must be v1")
        if problems:
            return problems

        scenario = request["scenario"]
        if not isinstance(scenario, dict):
            return ["the scenario must be a document"]
        if scenario.get("status") != RELEASED:
            problems.append(
                "only a released scenario may enter production synthetic "
                f"mode; this one is {scenario.get('status')!r}"
            )
        fault_kind = (scenario.get("fault") or {}).get("kind")
        primitive_version = request["primitive_version"]
        if not self.primitives.registered(fault_kind, primitive_version):
            problems.append(
                f"fault kind {fault_kind!r} with primitive "
                f"{primitive_version!r} is not a registered production "
                "primitive (spec 8.1)"
            )

        identity_record = self.enrollment.identity(request["identity"])
        if not SYNTHETIC_IDENTITY.match(request["identity"] or ""):
            problems.append(
                f"identity {request['identity']!r} is not a dedicated "
                "synthetic identity"
            )
        elif identity_record is None:
            problems.append(
                f"identity {request['identity']!r} is not enrolled"
            )
        else:
            if identity_record["tenant_id"] != request["tenant_id"]:
                problems.append(
                    "the synthetic identity belongs to another tenant"
                )

        targets = request["targets"]
        if not isinstance(targets, list) or not targets:
            problems.append(
                "the request needs at least one explicit target"
            )
            targets = []
        seen: set[str] = set()
        for target_id in targets:
            if target_id in seen:
                problems.append(f"target {target_id!r} is listed twice")
            seen.add(target_id)
            record = self.enrollment.target(target_id)
            if record is None:
                problems.append(f"target {target_id!r} is not enrolled")
                continue
            if record["tenant_id"] != request["tenant_id"]:
                problems.append(
                    f"target {target_id!r} belongs to another tenant"
                )
            if record["sink"] not in request["sinks"]:
                problems.append(
                    f"target {target_id!r} delivers to sink "
                    f"{record['sink']!r} which the session did not declare"
                )
            if scenario.get("status") == RELEASED:
                entry, status = classification_status(
                    scenario,
                    mode=POPULATION,
                    target_class=record["target_class"],
                    primitive_version=primitive_version,
                )
                if status != "valid":
                    problems.append(
                        f"the scenario classification for target class "
                        f"{record['target_class']!r} is {status!r} for "
                        "production synthetic mode"
                    )

        evidence = request["integration_evidence"]
        if not isinstance(evidence, dict):
            problems.append("integration evidence must be an object")
        else:
            if evidence.get("passed") is not True:
                problems.append(
                    "the integration gate has not passed (spec 13.4)"
                )
            if not evidence.get("suite"):
                problems.append("integration evidence names no suite")
            if (
                evidence.get("workload_fingerprint")
                != request["workload_fingerprint"]
            ):
                problems.append(
                    "integration evidence is bound to a different "
                    "workload fingerprint"
                )

        cost = request["cost_limit"]
        if not isinstance(cost, dict):
            problems.append("cost_limit must be an object")
        else:
            for field in ("max_injections", "max_effects"):
                limit = cost.get(field)
                if not isinstance(limit, int) or limit < 1:
                    problems.append(
                        f"cost limit {field!r} must be a positive bound; "
                        "unlimited sessions are not permitted"
                    )
            if (
                identity_record is not None
                and isinstance(cost.get("max_effects"), int)
                and cost["max_effects"] > identity_record["budget_effects"]
            ):
                problems.append(
                    "the session asks for more effects than its identity "
                    f"budget ({identity_record['budget_effects']})"
                )

        sinks = request["sinks"]
        if not isinstance(sinks, list) or not sinks:
            problems.append(
                "a production session needs declared effect sinks "
                "(spec 7)"
            )
        else:
            for sink in sinks:
                if not SINK_ID.match(sink or ""):
                    problems.append(f"sink {sink!r} is not a sink id")
        return problems

    # --- per-injection authorization -----------------------------------

    def authorize(self, session_id: str, target_id: str) -> dict:
        """Authorize one injection, re-checking everything now.

        Spec 7: enrollment is checked again immediately before each
        injection. A target revoked since admission fails closed here.
        """
        problems = self._authorization_problems(session_id, target_id)
        if problems:
            raise ProductionRefusal(
                "injection authorization refused: " + "; ".join(problems)
            )
        record = self._sessions[session_id]
        target = self.enrollment.target(target_id)
        self._sequence += 1
        authorization = {
            "kind": "InjectionAuthorization",
            "session_id": session_id,
            "sequence": self._sequence,
            "identity": record["identity"],
            "target": target_id,
            "destination": target["destination"],
            "sink": target["sink"],
        }
        self._authorizations[session_id].append(authorization)
        return dict(authorization)

    def _authorization_problems(
        self, session_id: str, target_id: str
    ) -> list[str]:
        record = self._sessions.get(session_id)
        if record is None:
            return [f"unknown session {session_id!r}"]
        problems: list[str] = []
        kill = self._kills.get(session_id)
        if kill is not None:
            problems.append(
                f"the session was killed ({kill['reason']})"
            )
        if session_id in self._stopped:
            problems.append(
                f"the session is stopped ({self._stopped[session_id]})"
            )
        if self.enrollment.identity(record["identity"]) is None:
            problems.append(
                f"identity {record['identity']!r} is no longer enrolled; "
                "refusing the injection"
            )
        target = self.enrollment.target(target_id)
        if target is None:
            problems.append(
                f"target {target_id!r} is no longer enrolled; refusing "
                "the injection"
            )
        elif target_id not in record["targets"]:
            problems.append(
                f"target {target_id!r} is outside the admitted set; "
                "selector expansion is refused"
            )
        cost = record["cost_limit"]
        if len(self._authorizations[session_id]) >= cost["max_injections"]:
            problems.append("the injection budget is exhausted")
        if self._landed_count(session_id) >= cost["max_effects"]:
            problems.append("the effect budget is exhausted")
        return problems

    def _landed_count(self, session_id: str) -> int:
        # Every effect the session caused, whatever its final state:
        # compensation frees the sink, not the budget.
        return len(self.path.inventory(session_id))

    # --- effects ---------------------------------------------------------

    def deliver(
        self,
        session_id: str,
        authorization: dict,
        payload: dict | None = None,
        *,
        sink: str | None = None,
    ) -> dict:
        """Deliver one fault effect through the production path.

        Containment is checked on the sink the effect actually landed
        in, not the one that was promised. An effect outside the
        declared sinks quarantines itself and kills the session.
        """
        record = self._sessions[session_id]
        if authorization.get("session_id") != session_id:
            raise ProductionRefusal(
                "the authorization belongs to another session"
            )
        if authorization not in self._authorizations[session_id]:
            raise ProductionRefusal("unknown authorization")
        target = self.enrollment.target(authorization["target"])
        landing_sink = sink if sink is not None else target["sink"]
        effect = self.path.deliver(
            session_id, landing_sink,
            payload or {
                "scenario_version_id": record["scenario_version_id"],
                "fault_kind": record["fault_kind"],
            },
        )
        if effect["sink"] not in record["sinks"]:
            self.path.quarantine(effect["effect_id"])
            self.kill(
                session_id,
                f"effect landed outside the declared sinks "
                f"({effect['sink']})",
            )
            raise ProductionRefusal(
                f"containment breach: the effect landed in "
                f"{effect['sink']!r}, outside the declared sinks"
            )
        return effect

    # --- kill and stop ----------------------------------------------------

    def kill(self, session_id: str, reason: str) -> dict:
        """Actuate the independent kill path for one session.

        The session is never called. State the mode owns is flipped,
        and the stop report assembles from mode and path records, so a
        session that is gone, hung, or lying cannot change the outcome.
        """
        if session_id not in self._sessions:
            raise ProductionRefusal(f"unknown session {session_id!r}")
        self._sequence += 1
        record = self.kill_path.actuate(session_id, reason, self._sequence)
        self._kills[session_id] = record
        return self._stop(session_id, f"killed: {reason}")

    def stop(self, session_id: str, reason: str = "completed") -> dict:
        if session_id not in self._sessions:
            raise ProductionRefusal(f"unknown session {session_id!r}")
        return self._stop(session_id, reason)

    def _stop(self, session_id: str, reason: str) -> dict:
        if session_id in self._stopped and session_id in self._reports:
            return self.report(session_id)
        self._stopped[session_id] = reason
        # Preapproved compensation: drain what can be drained. What
        # cannot be undone is fenced where it sits.
        drained = sorted(
            effect["effect_id"]
            for effect in self.path.inventory(session_id)
            if effect["state"] == "landed"
            and self.path.drain(effect["effect_id"])
        )
        report = self._render_report(session_id, reason, drained)
        self._reports[session_id] = report
        return dict(report)

    def _render_report(
        self, session_id: str, reason: str, drained: list[str]
    ) -> dict:
        record = self._sessions[session_id]
        cleanup = self.verifier.verify(self.path, session_id)
        inventory = [
            {
                "effect_id": effect["effect_id"],
                "sink": effect["sink"],
                "state": effect["state"],
            }
            for effect in self.path.inventory(session_id)
        ]
        verdict = cleanup["verdict"]
        if verdict == CLEAN:
            terminal = CLEAN
        elif verdict == DIRTY_QUARANTINED:
            terminal = DIRTY_QUARANTINED
        else:
            terminal = UNKNOWN
        return {
            "kind": "ProductionStopReport",
            "api_version": "v1",
            "session_id": session_id,
            "population": POPULATION,
            "scenario_version_id": record["scenario_version_id"],
            "reason": reason,
            "killed": session_id in self._kills,
            "injections_authorized":
                len(self._authorizations[session_id]),
            "effects": inventory,
            "drained": drained,
            "cleanup": cleanup,
            "terminal_state": terminal,
            "reopened_by_late_effect": False,
        }

    def report(self, session_id: str) -> dict:
        """The stop report, re-rendered against current path state.

        A late effect that appears after the session stopped reopens
        the result: the terminal state becomes UNKNOWN and prior
        assurance is stale (spec 13.3).
        """
        frozen = self._reports.get(session_id)
        if frozen is None:
            raise ProductionRefusal(
                f"session {session_id!r} has no stop report yet"
            )
        rendered = self._render_report(
            session_id, frozen["reason"], frozen["drained"]
        )
        if len(rendered["effects"]) != len(frozen["effects"]):
            rendered["reopened_by_late_effect"] = True
            rendered["terminal_state"] = UNKNOWN
        return rendered

    # --- the AC-031 gates --------------------------------------------------

    def isolation_gate(self, session_id: str) -> dict:
        """The session touched only synthetic, enrolled, declared things."""
        record = self._sessions.get(session_id)
        if record is None:
            return _gate(
                "isolation", False, f"unknown session {session_id!r}"
            )
        problems: list[str] = []
        if not SYNTHETIC_IDENTITY.match(record["identity"]):
            problems.append(
                f"identity {record['identity']!r} is not synthetic"
            )
        for authorization in self._authorizations[session_id]:
            destination = authorization["destination"]
            problems.extend(_destination_problems(destination))
        for effect in self.path.inventory(session_id):
            if effect["sink"] not in record["sinks"]:
                problems.append(
                    f"an effect landed in undeclared sink "
                    f"{effect['sink']!r}"
                )
        if problems:
            return _gate("isolation", False, "; ".join(problems))
        return _gate(
            "isolation", True,
            f"identity {record['identity']} synthetic; every destination "
            "explicit and every effect inside the declared sinks",
        )

    def kill_gate(self, session_id: str) -> dict:
        """The kill path is armed, independent, and obeyed."""
        record = self._sessions.get(session_id)
        if record is None:
            return _gate("kill", False, f"unknown session {session_id!r}")
        problems: list[str] = []
        state = self.kill_path.verify()
        if state["armed"] is not True:
            problems.append("the kill path is not armed")
        kill = self._kills.get(session_id)
        if kill is not None:
            later = [
                authorization
                for authorization in self._authorizations[session_id]
                if authorization["sequence"] > kill["sequence"]
            ]
            if later:
                problems.append(
                    f"{len(later)} injections were authorized after the "
                    "kill"
                )
        if problems:
            return _gate("kill", False, "; ".join(problems))
        detail = "the kill path is armed outside every session"
        if kill is not None:
            detail += f"; this session was killed ({kill['reason']})"
        return _gate("kill", True, detail)

    def cleanup_gate(self, session_id: str) -> dict:
        """Cleanup was verified independently and came out clean."""
        report = self._reports.get(session_id)
        if report is None:
            return _gate(
                "cleanup", False,
                f"session {session_id!r} has no stop report",
            )
        rendered = self.report(session_id)
        if rendered["terminal_state"] != CLEAN:
            return _gate(
                "cleanup", False,
                f"terminal state is {rendered['terminal_state']} "
                f"(verifier {rendered['cleanup']['verifier']}); "
                f"remaining {rendered['cleanup']['remaining']}, "
                f"quarantined {rendered['cleanup']['quarantined']}",
            )
        return _gate(
            "cleanup", True,
            f"verifier {rendered['cleanup']['verifier']} verified "
            f"{rendered['cleanup']['effects_total']} effects clean",
        )

    def assess(self, session_id: str) -> dict:
        """Run the three AC-031 gates; passed means all three."""
        gates = {
            gate["gate"]: gate
            for gate in (
                self.isolation_gate(session_id),
                self.kill_gate(session_id),
                self.cleanup_gate(session_id),
            )
        }
        return {
            "kind": "ProductionGateAssessment",
            "api_version": "v1",
            "session_id": session_id,
            "gates": gates,
            "passed": all(gate["passed"] for gate in gates.values()),
        }


def _gate(name: str, passed: bool, detail: str) -> dict:
    return {"gate": name, "passed": passed, "detail": detail}


class ProductionSession:
    """A handle over mode state. It holds no authority of its own."""

    def __init__(self, mode: ProductionSyntheticMode, session_id: str):
        self._mode = mode
        self.session_id = session_id

    @property
    def record(self) -> dict:
        return dict(self._mode._sessions[self.session_id])

    def begin_injection(self, target_id: str) -> dict:
        return self._mode.authorize(self.session_id, target_id)

    def deliver_fault(
        self, authorization: dict, payload: dict | None = None,
        *, sink: str | None = None,
    ) -> dict:
        return self._mode.deliver(
            self.session_id, authorization, payload, sink=sink
        )

    def stop(self, reason: str = "completed") -> dict:
        return self._mode.stop(self.session_id, reason)


# --- statistical separation ----------------------------------------------


def separate_statistics(
    session_reports: list[dict], customer_events: list[dict]
) -> dict:
    """Keep synthetic sessions out of customer statistics (spec 13.4).

    Synthetic sessions are counted on their own population and
    reported separately as shared-resource impact. A synthetic session
    that appears inside a customer population is refused, not merged.
    """
    problems: list[str] = []
    synthetic: list[dict] = []
    for report in session_reports:
        if report.get("population") != POPULATION:
            problems.append(
                f"report {report.get('session_id')!r} is not marked as "
                f"the {POPULATION} population"
            )
        else:
            synthetic.append(report)
    customer_ids = {
        event.get("session_id") for event in customer_events
    }
    overlap = sorted(
        report["session_id"]
        for report in synthetic
        if report["session_id"] in customer_ids
    )
    if overlap:
        problems.append(
            f"synthetic sessions {overlap} appear in the customer "
            "population; the populations must stay separate"
        )
    if problems:
        raise ProductionRefusal("; ".join(problems))
    return {
        "kind": "PopulationSeparation",
        "api_version": "v1",
        "synthetic": {
            "sessions": len(synthetic),
            "injections_authorized": sum(
                report["injections_authorized"] for report in synthetic
            ),
            "effects_landed": sum(
                len(report["effects"]) for report in synthetic
            ),
        },
        "customer": {"events": len(customer_events)},
        "shared_resource_impact": {
            "population": POPULATION,
            "measured_separately": True,
            "note": (
                "synthetic sessions are excluded from ordinary customer "
                "outcome statistics and reported on their own"
            ),
        },
    }
