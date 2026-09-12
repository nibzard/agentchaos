"""Fresh disposable environments for local fixture runs (spec 9.2).

Every variant executes in its own environment. The local fixture
environment is a private workspace directory: created empty, populated
from an explicit file bundle, and removed on release. Nothing is shared
between variants and nothing survives disposal.

The install step records a manifest digest over the installed files.
The runner compares the baseline and treatment digests to prove the
baseline really was identical (spec 9.2, AC-003).
"""

from __future__ import annotations

import hashlib
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from acx_runner.ids import mint_environment_id

_FORBIDDEN_PATH = re.compile(r"(?:^|/)\.\.?(?:/|$)|^[A-Za-z]:|^/")


class InstallError(Exception):
    """A bundle path tried to escape the workspace."""


@dataclass(frozen=True)
class Environment:
    """One disposable workspace.

    `instance_id` follows the Run contract pattern. `install` writes a
    bundle of relative paths into the workspace and returns the digest
    of the installed manifest. `release` removes the workspace; the
    return value is the local cleanup verdict: True means removal was
    verified, False means the workspace survived and stays on disk for
    inspection (spec 13.3).
    """

    instance_id: str
    root: Path

    def install(self, bundle: dict[str, str | bytes]) -> str:
        """Write the bundle; return the manifest digest.

        Paths are relative and stay inside the workspace. A path that
        tries to escape, or any non-file entry, fails the install.
        """
        manifest: dict[str, str] = {}
        for relative in sorted(bundle):
            _check_relative(relative)
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            content = bundle[relative]
            data = (
                content.encode("utf-8")
                if isinstance(content, str)
                else content
            )
            target.write_bytes(data)
            manifest[relative] = hashlib.sha256(data).hexdigest()
        return _manifest_digest(manifest)

    def release(self) -> bool:
        """Remove the workspace and verify removal."""
        shutil.rmtree(self.root, ignore_errors=True)
        return not self.root.exists()


class LocalFixtureEnvironments:
    """Provision environments under the system temporary directory.

    `id_factory` and `root_factory` exist for tests; production code
    uses the defaults, which mint random instance ids.
    """

    def __init__(self, id_factory=mint_environment_id, root_factory=None):
        self._id_factory = id_factory
        self._root_factory = root_factory or tempfile.mkdtemp

    def provision(self) -> Environment:
        root = Path(self._root_factory(prefix="acx-run-"))
        root.mkdir(parents=True, exist_ok=True)
        return Environment(instance_id=self._id_factory(), root=root)


def _check_relative(relative: str) -> None:
    if not isinstance(relative, str) or not relative:
        raise InstallError(f"bundle path {relative!r} is empty")
    if relative.startswith("/") or _FORBIDDEN_PATH.search(relative):
        raise InstallError(
            f"bundle path {relative!r} must be relative and stay inside "
            "the workspace"
        )
    if "\x00" in relative:
        raise InstallError(f"bundle path {relative!r} contains a NUL byte")


def _manifest_digest(manifest: dict[str, str]) -> str:
    """Digest over path/content pairs, independent of bundle order."""
    document = "\n".join(
        f"{path}\n{digest}" for path, digest in sorted(manifest.items())
    )
    return "sha256:" + hashlib.sha256(document.encode("utf-8")).hexdigest()
