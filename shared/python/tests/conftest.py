import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from gauntlet_schemas import ContractRegistry, default_registry  # noqa: E402

REPO_ROOT = PACKAGE_ROOT.parent.parent
FIXTURE_DIR = REPO_ROOT / "shared" / "fixtures" / "valid"

# One fixture file per registered resource kind.
KIND_TO_FIXTURE = {
    "WorkloadVersion": "workload-version.json",
    "AutonomyProfile": "autonomy-profile.json",
    "ScenarioVersion": "scenario-version.json",
    "Experiment": "experiment.json",
    "Run": "run.json",
    "Delegation": "delegation.json",
    "Effect": "effect.json",
    "EvidenceEvent": "evidence-event.json",
    "Finding": "finding.json",
    "AssuranceClaim": "assurance-claim.json",
    "Target": "target.json",
}


@pytest.fixture(scope="session")
def registry() -> ContractRegistry:
    return default_registry()


@pytest.fixture(scope="session")
def valid_instances() -> dict:
    return {
        kind: __import__("json").loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))
        for kind, name in KIND_TO_FIXTURE.items()
    }
