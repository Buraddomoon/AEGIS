"""Complementary pytest selection and workflow coverage, independent of lab infrastructure."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_ci_tests as runner  # noqa: E402


def select(root, items, index):
    rejected = []
    config = SimpleNamespace(
        hook=SimpleNamespace(pytest_deselected=lambda **kw: rejected.extend(kw["items"]))
    )
    kept = items.copy()
    runner.FileShard(index, root=root).pytest_collection_modifyitems(config, kept)
    return kept, rejected


def test_every_case_is_selected_once_and_all_cases_of_a_file_share_a_partition(tmp_path):
    files = ["tests/test_module_" + str(file) + ".py" for file in range(100)] + list(runner.PINNED)
    items = [
        SimpleNamespace(path=tmp_path / file, nodeid=(file, case))
        for file in files
        for case in range(5)
    ]
    groups = []
    all_ids, selected_ids = {id(item) for item in items}, set()
    for index in range(runner.SHARDS):
        kept, rejected = select(tmp_path, items, index)
        known = {id(item) for item in kept}
        assert not selected_ids & known
        assert {id(item) for item in rejected} == all_ids - known
        selected_ids |= known
        groups.append(kept)
    assert selected_ids == all_ids
    assert sorted(item.nodeid for group in groups for item in group) == sorted(
        item.nodeid for item in items
    )
    for file in files:
        assert sorted(sum(item.nodeid[0] == file for item in group) for group in groups) == [0] * (
            runner.SHARDS - 1
        ) + [5]
    for file, index in runner.PINNED.items():
        assert type(index) is int and index in range(runner.SHARDS)
        assert sum(item.nodeid[0] == file for item in groups[index]) == 5


def test_adding_or_reordering_files_never_moves_existing_cases(tmp_path):
    original = ["tests/test_one.py", "tests/nested/test_two.py", "tests/test_three.py"]
    before = {path: runner.partition(path) for path in original}
    after = {path: runner.partition(path) for path in ["tests/test_added.py", *reversed(original)]}
    assert all(after[path] == value for path, value in before.items())


@pytest.mark.parametrize(
    "path",
    [
        "/tests/test_x.py",
        "tests/../outside.py",
        "test_x.py",
        "other/test_x.py",
        "tests//test_x.py",
        "tests/test_x.txt",
    ],
)
def test_path_outside_reviewed_collection_or_noncanonical_path_fails_closed(path):
    with pytest.raises(pytest.UsageError):
        runner.partition(path)


@pytest.mark.parametrize("index", [-1, 3, True, "0"])
def test_unknown_partition_cannot_silently_skip_tests(index):
    with pytest.raises(pytest.UsageError):
        runner.FileShard(index)


def test_empty_partition_and_outside_test_symlink_are_errors(tmp_path):
    with pytest.raises(pytest.UsageError, match="empty"):
        select(tmp_path, [], 0)
    outside = tmp_path / "external.py"
    outside.write_text("# fixture\n")
    root = tmp_path / "repo"
    (root / "tests").mkdir(parents=True)
    linked = root / "tests/test_link.py"
    linked.symlink_to(outside)
    with pytest.raises(pytest.UsageError, match="outside"):
        select(root, [SimpleNamespace(path=linked)], 0)


def test_cli_uses_full_test_root_and_cannot_accept_filters_or_ignore_paths(monkeypatch):
    monkeypatch.delenv("PYTEST_ADDOPTS", raising=False)
    calls = []
    monkeypatch.setattr(runner.pytest, "main", lambda args, **kw: calls.append((args, kw)) or 1)
    assert runner.main(["--shard", "0"]) == 1
    args, kwargs = calls[0]
    assert args[0] == str(runner.ROOT / "tests") and "--collect-only" not in args
    assert len(kwargs["plugins"]) == 1 and kwargs["plugins"][0].index == 0
    for extra in ("--ignore=tests/test_auth.py", "-k=never", "--shard=3"):
        with pytest.raises(SystemExit):
            runner.main(["--shard", "0", extra])


def test_inherited_filters_cannot_reduce_ci_coverage(monkeypatch):
    monkeypatch.setenv("PYTEST_ADDOPTS", "-k private-sensitive-sentinel")
    monkeypatch.setattr(
        runner.pytest, "main", lambda *a, **kw: pytest.fail("No filtered invocation")
    )
    with pytest.raises(pytest.UsageError, match="inherited") as caught:
        runner.main(["--shard", "0"])
    assert "private-sensitive-sentinel" not in str(caught.value)


def test_workflow_runs_all_partitions_and_preserves_all_quality_checks():
    workflow = yaml.safe_load((runner.ROOT / ".github/workflows/ci.yml").read_text())
    backend, web = workflow["jobs"]["validate"], workflow["jobs"]["web"]
    assert backend["strategy"]["matrix"]["shard"] == list(range(runner.SHARDS))
    assert backend["strategy"]["max-parallel"] == 2 and backend["timeout-minutes"] == 18
    assert backend["strategy"]["fail-fast"] is False
    assert workflow["concurrency"]["cancel-in-progress"] is True
    python_commands = "\n".join(step.get("run", "") for step in backend["steps"])
    assert "python scripts/run_ci_tests.py --shard ${{ matrix.shard }}" in python_commands
    assert "ruff check" in python_commands and "mypy" in python_commands
    assert "audit_dependencies.py" in python_commands
    frontend_commands = "\n".join(step.get("run", "") for step in web["steps"])
    assert all(
        command in frontend_commands
        for command in (
            "run lint",
            "run format:check",
            " test",
            "run build",
            "audit --audit-level=high",
        )
    )
    assert "services" not in web
