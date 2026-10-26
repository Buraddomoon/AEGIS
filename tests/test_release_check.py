"""Exercise the release tool on real disposable Git indexes, without services."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_release.py"


def index_file(root, path, content):
    target = root / path
    target.parent.mkdir(exist_ok=True, parents=True)
    target.write_bytes(content.encode() if isinstance(content, str) else content)
    subprocess.run(["git", "add", "--", path], cwd=root, check=True)


@pytest.fixture
def repository(tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    index_file(tmp_path, "pyproject.toml", '[project]\nversion = "0.2.0"\n')
    index_file(
        tmp_path, "apps/web/package.json", '{"version":"0.2.0","dependencies":{"react":"19"}}'
    )
    index_file(
        tmp_path,
        "apps/web/package-lock.json",
        json.dumps(
            {
                "version": "0.2.0",
                "packages": {"": {"version": "0.2.0", "dependencies": {"react": "19"}}},
            }
        ),
    )
    index_file(tmp_path, "README.md", "[Guide](docs/guide.md)\n![Image](docs/images/test.png)\n")
    index_file(tmp_path, "docs/guide.md", "# Guide\n[Home](../README.md#intro)\n")
    index_file(
        tmp_path,
        "docs/images/test.png",
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + (10).to_bytes(4) + (20).to_bytes(4),
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=tmp_path,
        check=True,
    )
    return tmp_path


def check(repository):
    return subprocess.run(
        [sys.executable, str(SCRIPT)], cwd=repository, capture_output=True, text=True
    )


def test_reads_index_not_untracked_or_worktree_files(repository):
    (repository / "README.md").write_text("[Wrong worktree](not-there.md)\n")
    (repository / ".env").write_text("untracked-private-value")
    result = check(repository)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["local_links"] == 3
    assert report["worktree_differs_from_index"] is True
    assert report["index_differs_from_head"] is False
    assert report["screenshots"][0]["width"] == 10
    assert "untracked-private-value" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "problem", ["missing", "escape", "scheme", "version", "dependencies", "image", "secret"]
)
def test_delivery_inconsistency_fails_without_disclosing_content(repository, problem):
    if problem == "missing":
        index_file(repository, "README.md", "[Missing](docs/missing.md)\n")
    elif problem == "escape":
        index_file(repository, "README.md", "[Outside](%2E%2E/outside.md)\n")
    elif problem == "scheme":
        index_file(repository, "README.md", "[Outside](file:///etc/passwd)\n")
    elif problem == "version":
        index_file(repository, "apps/web/package.json", '{"version":"9.9.9"}')
    elif problem == "dependencies":
        index_file(
            repository, "apps/web/package.json", '{"version":"0.2.0","dependencies":{"react":"18"}}'
        )
    elif problem == "image":
        index_file(repository, "docs/images/test.png", "not-an-image")
    else:
        index_file(repository, "oops.txt", "github_pat_" + "s" * 32)
    result = check(repository)
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["status"] == "failed"
    assert report["errors"]
    assert report["index_differs_from_head"] is True
    assert "github_pat_" + "s" * 32 not in result.stdout + result.stderr


def test_code_blocks_and_external_links_do_not_require_local_targets(repository):
    index_file(
        repository,
        "docs/guide.md",
        """# Guide
[Remote](https://example.invalid/not-requested)
```md
[Example](not-a-real-file.md)
```
[Space](<with space.md>)
""",
    )
    index_file(repository, "docs/with space.md", "# Tracked\n")
    result = check(repository)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["local_links"] == 3
