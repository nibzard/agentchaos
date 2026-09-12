"""Resource records the compiler resolves.

The compiler never loads storage itself. Callers supply a store; the
compiler treats a missing record as a failure. This keeps compilation
deterministic and testable.

Targets validate against the Target contract in shared/schemas; the
EnrollmentRegistry produces records that satisfy it. Credentials have no
schema yet; their records carry the fields below and are checked in
code. Every other record must validate against its contract in
shared/schemas/.
"""

from __future__ import annotations

from typing import Protocol


class ResourceStore(Protocol):
    """Read access to the definitions a manifest references."""

    def get_workload(self, workload_version_id: str) -> dict | None: ...

    def get_profile(self, profile_id: str) -> dict | None: ...

    def get_scenario(self, scenario_version_id: str) -> dict | None: ...

    def get_target(self, target_id: str) -> dict | None: ...

    def get_credential(self, credential_kind: str) -> dict | None: ...


class MemoryResourceStore:
    """In-memory store for tests and examples.

    Records are dicts:
    - workload, profile, scenario, target: contract documents from
      shared/schemas.
    - credential: {"kind": "Credential", "id", "tenant_id", "credential_kind",
      "refreshed_at"}.
    """

    def __init__(
        self,
        workloads: list[dict] | None = None,
        profiles: list[dict] | None = None,
        scenarios: list[dict] | None = None,
        targets: list[dict] | None = None,
        credentials: list[dict] | None = None,
    ):
        def index(records: list[dict] | None, key: str) -> dict:
            indexed: dict = {}
            for record in records or []:
                if record[key] in indexed:
                    raise ValueError(
                        f"duplicate {key} {record[key]!r} in store; ids and "
                        "credential kinds are unique across tenants, so a "
                        "collision is ambiguous and fails closed"
                    )
                indexed[record[key]] = record
            return indexed

        self._workloads = index(workloads, "id")
        self._profiles = index(profiles, "id")
        self._scenarios = index(scenarios, "id")
        self._targets = index(targets, "id")
        self._credentials = index(credentials, "credential_kind")

    def get_workload(self, workload_version_id: str) -> dict | None:
        return self._workloads.get(workload_version_id)

    def get_profile(self, profile_id: str) -> dict | None:
        return self._profiles.get(profile_id)

    def get_scenario(self, scenario_version_id: str) -> dict | None:
        return self._scenarios.get(scenario_version_id)

    def get_target(self, target_id: str) -> dict | None:
        return self._targets.get(target_id)

    def get_credential(self, credential_kind: str) -> dict | None:
        return self._credentials.get(credential_kind)
