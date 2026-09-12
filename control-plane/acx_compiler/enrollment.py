"""Explicit target enrollment (spec 7, 13.1, 13.4, AC-002).

Enrollment is a human-owned decision recorded as a Target contract
document. This module owns the lifecycle:

- a target becomes enrolled only through an explicit `enroll` call that
  names the enrolling principal and stamps the time; nothing enrolls
  implicitly, and the registry never backdates;
- `pause` suspends selection while keeping the enrollment record and
  its recorded opt-ins; selection of a paused target fails closed;
- `resume` restores an enrolled status from paused;
- `unenroll` removes the enrollment record entirely, so every recorded
  opt-in lapses with it.

Every operation is tenant-scoped. A lookup from the wrong tenant reports
`not_found`, never `tenant_mismatch`, so the registry does not confirm
that another tenant's target exists. Every state change appends to an
audit log kept outside worker access (spec 13.1 auditability).
"""

from __future__ import annotations

import copy

from acx_schemas import ContractViolation, validate

# Allowed status transitions. Anything not listed fails closed.
# Re-enrolling an unenrolled target is a fresh `enroll` call with its own
# record, not a transition, so it has no row here.
TRANSITIONS: dict[tuple[str, str], str] = {
    ("enrolled", "paused"): "pause",
    ("paused", "enrolled"): "resume",
    ("enrolled", "unenrolled"): "unenroll",
    ("paused", "unenrolled"): "unenroll",
}


class EnrollmentError(Exception):
    """One enrollment failure with a stable code."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class EnrollmentRegistry:
    """Tenant-scoped in-memory target lifecycle store.

    Replace the backing dictionary with a database for production use;
    the transition rules and the audit log stay the same. Loading
    existing records revalidates them against the Target contract, so a
    corrupted record fails the registry rather than silently widening
    who may be selected.
    """

    def __init__(self, targets: list[dict] | None = None):
        self._targets: dict[tuple[str, str], dict] = {}
        self.audit_log: list[dict] = []
        for target in targets or []:
            self._load(target)

    # Enrollment lifecycle

    def enroll(
        self,
        *,
        target_id: str,
        tenant_id: str,
        target_class: str,
        enrolled_by: str,
        now: str,
        opt_in_modes: tuple[str, ...] | list[str] = (),
    ) -> dict:
        """Enroll a target explicitly. The registry stamps the time.

        Re-enrolling a paused target is refused; use `resume`. A target
        that left enrollment may enroll again with a fresh record.
        """
        record = {
            "kind": "Target",
            "api_version": "v1",
            "id": target_id,
            "tenant_id": tenant_id,
            "class": target_class,
            "status": "enrolled",
            "enrollment": {
                "enrolled_at": now,
                "enrolled_by": enrolled_by,
                "opt_in_modes": sorted(set(opt_in_modes)),
            },
        }
        self._check_record(record)
        existing = self._targets.get((tenant_id, target_id))
        if existing is not None and existing["status"] != "unenrolled":
            if existing["status"] == "enrolled":
                raise EnrollmentError(
                    "already_enrolled",
                    f"target {target_id} is already enrolled",
                )
            raise EnrollmentError(
                "invalid_transition",
                f"target {target_id} is {existing['status']}; resume it "
                "instead of enrolling again",
            )
        self._targets[(tenant_id, target_id)] = record
        self._log("enroll", record, at=now, by=enrolled_by)
        return copy.deepcopy(record)

    def pause(self, tenant_id: str, target_id: str, *, now: str) -> dict:
        return self._transition(tenant_id, target_id, "paused", now=now)

    def resume(self, tenant_id: str, target_id: str, *, now: str) -> dict:
        return self._transition(tenant_id, target_id, "enrolled", now=now)

    def unenroll(self, tenant_id: str, target_id: str, *, now: str) -> dict:
        current = self._get(tenant_id, target_id)
        if TRANSITIONS.get((current["status"], "unenrolled")) is None:
            raise EnrollmentError(
                "invalid_transition",
                f"cannot move target {target_id} from "
                f"{current['status']} to unenrolled",
            )
        record = {
            key: value
            for key, value in current.items()
            if key != "enrollment"
        }
        record["status"] = "unenrolled"
        record["unenrolled_at"] = now
        self._check_record(record)
        self._targets[(tenant_id, target_id)] = record
        self._log("unenroll", record, at=now, by=None)
        return copy.deepcopy(record)

    # Reads

    def get(self, tenant_id: str, target_id: str) -> dict | None:
        """Tenant-scoped read. Cross-tenant lookups see nothing.

        Returns a copy: callers cannot mutate registry state through a
        read.
        """
        record = self._targets.get((tenant_id, target_id))
        return copy.deepcopy(record) if record is not None else None

    def snapshot(self) -> list[dict]:
        """All target records, for feeding a ResourceStore."""
        return [copy.deepcopy(record) for record in self._targets.values()]

    # Internals

    def _transition(
        self, tenant_id: str, target_id: str, new_status: str, *, now: str
    ) -> dict:
        current = self._get(tenant_id, target_id)
        action = TRANSITIONS.get((current["status"], new_status))
        if action is None:
            raise EnrollmentError(
                "invalid_transition",
                f"cannot move target {target_id} from "
                f"{current['status']} to {new_status}",
            )
        record = dict(current)
        record["status"] = new_status
        self._check_record(record)
        self._targets[(tenant_id, target_id)] = record
        self._log(action, record, at=now, by=None)
        return copy.deepcopy(record)

    def _get(self, tenant_id: str, target_id: str) -> dict:
        record = self._targets.get((tenant_id, target_id))
        if record is None:
            raise EnrollmentError(
                "not_found", f"target {target_id} not found in tenant"
            )
        return record

    def _load(self, target: dict) -> None:
        self._check_record(target)
        self._targets[(target["tenant_id"], target["id"])] = copy.deepcopy(
            target
        )

    def _log(
        self, action: str, record: dict, *, at: str, by: str | None
    ) -> None:
        self.audit_log.append(
            {
                "action": action,
                "target_id": record["id"],
                "tenant_id": record["tenant_id"],
                "status": record["status"],
                "at": at,
                "by": by,
            }
        )

    @staticmethod
    def _check_record(record: dict) -> None:
        try:
            validate(record, "Target")
        except ContractViolation as exc:
            first = exc.as_dict()["errors"][0]
            raise EnrollmentError(
                "record_schema_invalid",
                f"Target record invalid: {first['message']}",
            ) from exc
