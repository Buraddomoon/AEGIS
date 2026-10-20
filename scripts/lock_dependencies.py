"""Regenerate production lock for current Python/platform using inspected PyPI metadata."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--dev", action="store_true")
args = parser.parse_args()
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
            ".[dev]" if args.dev else ".",
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
Path("requirements-dev.lock" if args.dev else "requirements.lock").write_text(
    "\n".join(lines) + "\n"
)
