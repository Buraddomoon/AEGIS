"""Run one complementary file-based pytest partition; no lab startup."""

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHARDS = 3
# Run41641991673 hit18min in BOTH partitions as fixture coverage grew.
# Distribute whole heavy files, never cases; max-parallel remains2 in CI.
PINNED = {
    "tests/test_runner_activation_identity_lifecycle.py": 0,
    "tests/test_runner_diagnostic_coordinator.py": 1,
    # The new full identity coordinator took133s locally; run436's shard0 took
    # 369s versus924s in shard2. Preserve whole-file coverage and use that room.
    "tests/test_runner_identity_coordinator.py": 0,
    # Client lifecycle was not committed in run436; it adds132s locally.
    "tests/test_runner_activation_identity_client_lifecycle.py": 0,
}


def partition(path: str) -> int:
    relative = PurePosixPath(path)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or len(relative.parts) < 2
        or relative.parts[0] != "tests"
        or relative.suffix != ".py"
        or relative.as_posix() != path
    ):
        raise pytest.UsageError("CI partition requires a canonical path under tests")
    if path in PINNED:
        return PINNED[path]
    return int.from_bytes(hashlib.sha256(path.encode("utf-8")).digest()[:8], "big") % SHARDS


class FileShard:
    def __init__(self, index: int, *, root: Path = ROOT):
        if type(index) is not int or index not in range(SHARDS):
            raise pytest.UsageError("CI partition must be 0, 1 or 2")
        self.index, self.root = index, root.resolve()

    def pytest_collection_modifyitems(self, config, items):
        selected, other = [], []
        for item in items:
            try:
                relative = item.path.resolve().relative_to(self.root).as_posix()
            except ValueError:
                raise pytest.UsageError(
                    "Collected test is outside the reviewed repository"
                ) from None
            (selected if partition(relative) == self.index else other).append(item)
        if not selected:
            raise pytest.UsageError("CI partition is empty; refusing a vacuous success")
        config.hook.pytest_deselected(items=other)
        items[:] = selected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, choices=range(SHARDS), required=True)
    parser.add_argument("--collect-only", action="store_true")
    args = parser.parse_args(argv)
    if os.environ.get("PYTEST_ADDOPTS", "").strip():
        raise pytest.UsageError("CI partitions refuse inherited pytest options")
    options = [str(ROOT / "tests"), "-q", "--durations=15", "-o", "faulthandler_timeout=60"]
    if args.collect_only:
        options.append("--collect-only")
    return pytest.main(options, plugins=[FileShard(args.shard)])


if __name__ == "__main__":
    raise SystemExit(main())
