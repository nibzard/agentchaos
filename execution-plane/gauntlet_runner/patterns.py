"""Contract patterns the runner validates without importing schemas."""

from __future__ import annotations

import re

# From shared/schemas/common.schema.json.
RUN_ID = re.compile(r"^run_[a-z0-9]{8,64}$")
EVIDENCE_EVENT_ID = re.compile(r"^evt_[a-z0-9]{8,64}$")
SCENARIO_VERSION_ID = re.compile(r"^scn_[a-z0-9]{8,64}$")
UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$"
)


def is_utc_timestamp(value: str) -> bool:
    return isinstance(value, str) and UTC_TIMESTAMP.match(value) is not None
