"""Security checks inspect Git's index, including filenames with newlines."""

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_staged.py"


@pytest.mark.parametrize("all_tracked", [False, True])
def test_checks_only_index_and_redacts_secret_values(tmp_path, all_tracked):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "safe.py").write_text("# safe\n")
    secret = "github_pat_" + "s" * 32
    (tmp_path / "tracked.txt").write_text(secret + "\n")
    # Safe working tree must not hide the secret already in the index.
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    (tmp_path / "tracked.txt").write_text("safe working tree\n")
    (tmp_path / "untracked.txt").write_text(secret)
    command = [sys.executable, str(SCRIPT)] + (["--all"] if all_tracked else [])
    result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "tracked.txt: possible secret" in result.stderr
    assert secret not in result.stdout + result.stderr
    (tmp_path / "tracked.txt").write_text("safe\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=tmp_path, check=True)
    result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, check=False)
    assert result.returncode == 0


@pytest.mark.parametrize(
    "path", [".env", "backup.agekey", "dir/.env.production", "line\nbreak.age"]
)
def test_rejects_sensitive_paths_even_with_newline_in_filename(tmp_path, path):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    file = tmp_path / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text("private\n")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--all"], cwd=tmp_path, capture_output=True, text=True
    )
    assert result.returncode == 1
    assert "sensitive/generated path" in result.stderr
