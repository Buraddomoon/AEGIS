"""Regenerate production lock for current Python/platform using inspected PyPI metadata."""

import argparse
import json
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
group.add_argument("--dev", action="store_true")
group.add_argument("--backup", action="store_true")
group.add_argument("--sigma-converter", action="store_true")
args = parser.parse_args()
targets = (
    ["pysigma==1.5.1", "pysigma-backend-opensearch==2.0.3", "pysigma-backend-elasticsearch==2.1.1"]
    if args.sigma_converter
    else (
        tomllib.loads(Path("pyproject.toml").read_text())["project"]["optional-dependencies"][
            "backup"
        ]
        if args.backup
        else [".[dev]" if args.dev else "."]
    )
)
with tempfile.TemporaryDirectory() as directory:
    report = Path(directory) / "resolution.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--report",
            str(report),
            *targets,
        ],
        check=True,
    )
    resolved = json.loads(report.read_text())
lines = [
    "# Python 3.13 / Linux x86_64, resolved from PyPI. Regenerate with scripts/lock_dependencies.py."
]
for item in sorted(resolved["install"], key=lambda p: p["metadata"]["name"].lower()):
    name = item["metadata"]["name"]
    if name == "aegis-purple":
        continue
    sha = item["download_info"]["archive_info"]["hashes"]["sha256"]
    lines.append(f"{name}=={item['metadata']['version']} --hash=sha256:{sha}")
destination = (
    "requirements-sigma-converter.lock"
    if args.sigma_converter
    else (
        "requirements-backup.lock"
        if args.backup
        else ("requirements-dev.lock" if args.dev else "requirements.lock")
    )
)
Path(destination).write_text("\n".join(lines) + "\n")
