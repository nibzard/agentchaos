"""Build the open-core distribution from the manifest (T045, spec 23).

Reads packaging/manifest.json, validates it against
packaging/manifest.schema.json, and assembles the distribution tree
under dist/. The copy step skips caches and build output so the tree
contains only source and documents.

Every included path must exist in the repository, every excluded path
must stay absent from the tree, and two builds from the same commit
must produce the same file list. A build that violates any of these
fails rather than shipping a partial distribution.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging"

# Never shipped, regardless of the manifest: caches, dependency
# installs, editor residue, and the loop's own state.
SKIP_NAMES = {
    "__pycache__", "node_modules", ".pytest_cache", ".claude",
    ".git", ".gitignore",
}


def load_manifest() -> dict:
    manifest = json.loads(
        (PACKAGING / "manifest.json").read_text()
    )
    schema = json.loads(
        (PACKAGING / "manifest.schema.json").read_text()
    )
    jsonschema.validate(manifest, schema)
    return manifest


def git_commit() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if completed.returncode != 0:
        return "unknown"
    return completed.stdout.strip()


def check_paths(manifest: dict) -> list[str]:
    """Every included path must exist; exclusions must not overlap."""
    problems = []
    included: set[str] = set()
    for component in manifest["components"]:
        for path in component["paths"]:
            included.add(path)
            if not (ROOT / path).exists():
                problems.append(
                    f"component {component['id']} lists missing path "
                    f"{path}"
                )
    for group in manifest["supporting"]:
        for path in group["paths"]:
            included.add(path)
            if not (ROOT / path).exists():
                problems.append(f"supporting path {path} is missing")
    for entry in manifest["excluded"]:
        excluded = entry["path"]
        for path in included:
            # An exclusion is a problem only when it covers an
            # included path, which would silently drop promised
            # content. An included directory that contains an
            # excluded subpath is the normal case (ui minus ui/dist).
            if path == excluded or path.startswith(excluded + "/"):
                problems.append(
                    f"excluded path {excluded} covers included {path}"
                )
    return problems


def copy_tree(
    source: Path, target: Path, repo_prefix: str = "",
    excluded: set[str] | None = None,
) -> int:
    """Copy a file or directory, skipping caches and excluded paths.

    repo_prefix is the repository-relative path of source, so that
    exclusions stated against the repository (ui/dist) also apply
    inside the copy.
    """
    excluded = excluded or set()
    copied = 0

    def is_excluded(relative: Path) -> bool:
        repo_relative = (
            f"{repo_prefix}/{relative}" if repo_prefix else str(relative)
        )
        return any(
            repo_relative == entry
            or repo_relative.startswith(entry + "/")
            for entry in excluded
        )

    if source.is_file():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        return 1
    for item in sorted(source.rglob("*")):
        if SKIP_NAMES & set(item.relative_to(source).parts):
            continue
        if is_excluded(item.relative_to(source)):
            continue
        if item.is_dir():
            continue
        relative = item.relative_to(source)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, destination)
        copied += 1
    return copied


def excluded_present(manifest: dict, tree: Path) -> list[str]:
    """Report excluded paths that leaked into the built tree."""
    return [
        f"{entry['path']} is in the tree"
        for entry in manifest["excluded"]
        if (tree / entry["path"]).exists()
    ]


def build(output: Path, manifest: dict) -> dict:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    excluded = {entry["path"] for entry in manifest["excluded"]}
    counts: dict[str, int] = {}
    for component in manifest["components"]:
        total = 0
        for path in component["paths"]:
            total += copy_tree(
                ROOT / path, output / path, repo_prefix=path,
                excluded=excluded,
            )
        counts[component["id"]] = total
    for group in manifest["supporting"]:
        for path in group["paths"]:
            copy_tree(
                ROOT / path, output / path, repo_prefix=path,
                excluded=excluded,
            )

    leaks = excluded_present(manifest, output)
    if leaks:
        raise SystemExit(
            "excluded material leaked into the tree: "
            + "; ".join(leaks)
        )
    empty = [
        component_id for component_id, count in counts.items()
        if count == 0
    ]
    if empty:
        raise SystemExit(f"components copied nothing: {empty}")

    (output / "VERSION").write_text(
        f"{manifest['name']} {manifest['version']} "
        f"(Apache-2.0) from commit {git_commit()}\n"
        f"{manifest['name_note']}\n"
    )
    try:
        path_field = str(output.relative_to(ROOT))
    except ValueError:
        path_field = str(output)
    return {
        "kind": "OpenCoreDistribution",
        "api_version": "v1",
        "name": manifest["name"],
        "version": manifest["version"],
        "commit": git_commit(),
        "files": sum(counts.values()),
        "component_files": counts,
        "path": path_field,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path,
        default=ROOT / "dist" / "gauntlet-open-core",
    )
    args = parser.parse_args()

    manifest = load_manifest()
    problems = check_paths(manifest)
    if problems:
        for problem in problems:
            print(f"manifest problem: {problem}", file=sys.stderr)
        return 1

    summary = build(args.out, manifest)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
