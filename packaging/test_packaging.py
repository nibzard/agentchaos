"""Tests for the open-core packaging (T045, spec 23.1)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PACKAGING = Path(__file__).resolve().parent
ROOT = PACKAGING.parent
sys.path.insert(0, str(PACKAGING))

from build_open_core import (  # noqa: E402
    SKIP_NAMES,
    build,
    check_paths,
    copy_tree,
    excluded_present,
    load_manifest,
)

# The spec 23.1 promise, one promise per component id.
PROMISED_IDS = {
    "scenario-specification",
    "schemas",
    "cli",
    "local-runner",
    "reference-fixture-environments",
    "synthetic-scenario-pack",
    "adapter-interface",
    "core-evidence-format",
    "comparison-and-statistics",
    "local-ui",
    "essential-safety-controls",
}

# Markers a distribution cannot ship without: one per promised
# component, checked as a file that must exist in the built tree.
PROMISED_MARKERS = {
    "scenario-specification":
        "execution-plane/gauntlet_scenarios/templates.py",
    "schemas": "shared/schemas/effect.schema.json",
    "cli": "cli/gauntlet/main.go",
    "local-runner": "execution-plane/gauntlet_runner/runner.py",
    "reference-fixture-environments":
        "execution-plane/gauntlet_runner/environments.py",
    "synthetic-scenario-pack":
        "execution-plane/gauntlet_scenarios/templates.py",
    "adapter-interface": "execution-plane/gauntlet_adapters/contract.py",
    "core-evidence-format": "evidence-plane/contract.go",
    "comparison-and-statistics": "control-plane/assurance.go",
    "local-ui": "ui/src/main.ts",
    "essential-safety-controls": "broker/broker.go",
}


def test_the_manifest_validates_against_its_schema():
    load_manifest()


def test_every_spec_23_1_promise_has_a_component():
    manifest = load_manifest()
    ids = {component["id"] for component in manifest["components"]}
    assert ids == PROMISED_IDS


def test_every_manifest_path_exists():
    manifest = load_manifest()
    assert check_paths(manifest) == []


def test_an_exclusion_covering_a_promise_is_refused():
    manifest = load_manifest()
    manifest["excluded"].append(
        {"path": "broker", "reason": "an impossible exclusion"}
    )
    problems = check_paths(manifest)
    assert any("broker" in problem for problem in problems)


def test_a_missing_promise_path_is_refused():
    manifest = load_manifest()
    manifest["components"][0]["paths"].append("execution-plane/absent")
    problems = check_paths(manifest)
    assert any("absent" in problem for problem in problems)


def build_into(tmp_path: Path) -> Path:
    manifest = load_manifest()
    tree = tmp_path / "gauntlet-open-core"
    summary = build(tree, manifest)
    assert summary["files"] > 0
    return tree


def test_the_tree_carries_every_promised_component(tmp_path):
    tree = build_into(tmp_path)
    for component_id, marker in PROMISED_MARKERS.items():
        assert (tree / marker).exists(), component_id


def test_the_tree_carries_license_and_version(tmp_path):
    tree = build_into(tmp_path)
    assert (tree / "LICENSE").exists()
    assert (tree / "THIRD_PARTY.md").exists()
    assert (tree / "VERSION").exists()
    assert "Apache-2.0" in (tree / "VERSION").read_text()


def test_commercial_and_internal_paths_stay_out(tmp_path):
    tree = build_into(tmp_path)
    for leak in ("api", "keycustody", "release", "benchmarks",
                 "integration", "ui/dist", "ui/node_modules",
                 "to-do.json"):
        assert not (tree / leak).exists(), leak
    assert excluded_present(load_manifest(), tree) == []


def test_no_caches_ship(tmp_path):
    tree = build_into(tmp_path)
    shipped = {
        part for path in tree.rglob("*")
        for part in path.relative_to(tree).parts
    }
    assert not (shipped & SKIP_NAMES)


def test_two_builds_agree_on_the_file_list(tmp_path):
    manifest = load_manifest()
    first = build(tmp_path / "one", manifest)
    second = build(tmp_path / "two", manifest)
    files_one = sorted(
        str(p.relative_to(tmp_path / "one"))
        for p in (tmp_path / "one").rglob("*") if p.is_file()
    )
    files_two = sorted(
        str(p.relative_to(tmp_path / "two"))
        for p in (tmp_path / "two").rglob("*") if p.is_file()
    )
    assert files_one == files_two
    assert first["files"] == second["files"]


def test_copy_tree_skips_caches(tmp_path):
    source = tmp_path / "src"
    (source / "pkg" / "__pycache__").mkdir(parents=True)
    (source / "pkg" / "code.py").write_text("x = 1\n")
    (source / "pkg" / "__pycache__" / "code.pyc").write_text("")
    copied = copy_tree(source, tmp_path / "out")
    assert copied == 1
    assert (tmp_path / "out" / "pkg" / "code.py").exists()
    assert not (tmp_path / "out" / "pkg" / "__pycache__").exists()


def test_local_users_keep_the_safety_controls(tmp_path):
    """Spec 23.3: the emergency brake never sits behind a pay wall."""
    tree = build_into(tmp_path)
    for control in (
        "broker/broker.go",            # the gate every effect crosses
        "governor/governor.go",        # grant expiry and fencing
        "supervisor/degradation.go",   # timeout holds, never a silent allow
    ):
        assert (tree / control).exists(), control


def test_the_version_names_the_commit_and_the_naming_caveat(tmp_path):
    tree = build_into(tmp_path)
    version = (tree / "VERSION").read_text()
    assert "commit" in version
    assert "working name" in version
