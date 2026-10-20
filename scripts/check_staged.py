"""Small pre-commit guard; supplement with human review and CI secret scanning."""

import re
import subprocess
import sys

paths = subprocess.check_output(
    ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"], text=True
).splitlines()
bad = []
for path in paths:
    if (
        any(
            part in {"node_modules", ".venv", "__pycache__", ".local", "dist"}
            for part in path.split("/")
        )
        or path.endswith((".log", ".pyc", ".tsbuildinfo"))
        or (path.split("/")[-1].startswith(".env") and path != ".env.example")
    ):
        bad.append(path + ": sensitive/generated path")
        continue
    content = subprocess.check_output(["git", "show", ":" + path])
    patterns = [
        rb"gh[pousr]_[A-Za-z0-9]{20,}",
        rb"github_pat_[A-Za-z0-9_]{30,}",
        rb"AKIA[A-Z0-9]{16}",
        rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    ]
    if any(re.search(pattern, content) for pattern in patterns):
        bad.append(path + ": possible secret (value omitted)")
print("Staged files reviewed:", ", ".join(paths) or "none")
if bad:
    print("\n".join(bad), file=sys.stderr)
    sys.exit(1)
subprocess.run(["git", "diff", "--cached", "--check"], check=True)
print("Staged path/credential-pattern/whitespace checks passed.")
