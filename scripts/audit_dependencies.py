"""Audit production lock, fail unknown findings, keep reviewed finding visible."""

import json
import subprocess
import sys
from pathlib import Path

from aegis.integrations.sigma_analysis import analyze
from aegis.integrations.sigma_readiness import assess
from aegis.integrations.yaml_import import parse_sigma

result = subprocess.run(
    [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        "requirements.lock",
        "--no-deps",
        "--disable-pip",
        "--format",
        "json",
    ],
    capture_output=True,
    text=True,
)
if result.returncode not in {0, 1}:
    print(result.stderr, file=sys.stderr)
    raise SystemExit(result.returncode)
report = json.loads(result.stdout)
baseline = json.loads(Path("docs/security/dependency-advisories.json").read_text())["reviewed"]
probe = """title: Cache path audit
id: 73e12878-5870-4588-a7b6-79704ad821a4
logsource:
  category: process_creation
detection:
  selection:
    Image: marker
  condition: selection
"""
parse_sigma(probe)
analyze(probe)
analyze(probe.replace("condition: selection", "condition: missing"))
assert not assess(probe)["can_convert"]
if "diskcache" in sys.modules:
    raise SystemExit(
        "Parser or analysis imported diskcache: reviewed advisory requires reassessment."
    )
unreviewed = []
seen = set()
for dependency in report["dependencies"]:
    for finding in dependency.get("vulns", []):
        key = (dependency["name"], dependency["version"], finding["id"])
        if key in seen:
            continue
        seen.add(key)
        known = next(
            (
                r
                for r in baseline
                if r["package"] == key[0] and r["version"] == key[1] and finding["id"] in r["ids"]
            ),
            None,
        )
        print("REVIEWED (parser path not affected):" if known else "UNREVIEWED:", *key)
        if not known:
            unreviewed.append(key)
if unreviewed:
    raise SystemExit("New/actionable dependency findings require review or fixes.")
print(
    f"Audit complete: {len(seen)} distinct finding(s), all explicitly reviewed. This is not a zero-findings claim."
)
