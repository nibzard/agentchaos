"""Fresh disposable environments."""

import pytest

from gauntlet_runner import Environment, InstallError, LocalFixtureEnvironments


def _environments(tmp_path):
    state = {"n": 0}

    def id_factory():
        state["n"] += 1
        return f"env_lfx-{state['n']:012d}"

    def root_factory(prefix=None, dir=None):  # noqa: ARG001
        state["n"] += 1
        return str(tmp_path / f"ws-{state['n']:012d}")

    return LocalFixtureEnvironments(
        id_factory=id_factory, root_factory=root_factory
    )


def test_provision_creates_distinct_workspaces(tmp_path):
    factory = _environments(tmp_path)
    first = factory.provision()
    second = factory.provision()
    assert first.instance_id != second.instance_id
    assert first.root != second.root
    assert first.root.is_dir()


def test_install_writes_files_and_returns_stable_digest(tmp_path):
    environment = _environments(tmp_path).provision()
    bundle = {
        "task.md": "close issue #7",
        "src/main.py": "print('ok')",
    }
    first = environment.install(bundle)
    second = _environments(tmp_path).provision().install(
        dict(reversed(list(bundle.items())))
    )
    assert first == second  # digest independent of bundle order
    assert (environment.root / "task.md").read_text() == "close issue #7"
    assert (environment.root / "src" / "main.py").exists()


def test_install_rejects_escaping_paths(tmp_path):
    environment = _environments(tmp_path).provision()
    for bad in ("../escape.txt", "/etc/passwd", "a/../../b", ".", ""):
        with pytest.raises(InstallError):
            environment.install({bad: "x"})


def test_release_removes_the_workspace(tmp_path):
    environment = _environments(tmp_path).provision()
    (environment.root / "leftover.txt").write_text("dirty")
    assert environment.release() is True
    assert not environment.root.exists()


def test_release_survives_missing_root(tmp_path):
    environment = Environment(
        instance_id="env_lfx-gone", root=tmp_path / "never-existed"
    )
    assert environment.release() is True
