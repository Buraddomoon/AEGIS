"""Review staged or all tracked paths/content; supplement with human review."""

import argparse
import re
import subprocess
import sys

SECRET_PATTERNS = [
    rb"gh[pousr]_[A-Za-z0-9]{20,}",
    rb"github_pat_[A-Za-z0-9_]{30,}",
    rb"AKIA[A-Z0-9]{16}",
    rb"AGE-SECRET-KEY-1[A-Z0-9]{50,}",
    rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
]


def check_paths(paths: list[str]) -> list[str]:
    bad = []
    for path in paths:
        if (
            any(
                part in {"node_modules", ".venv", "__pycache__", ".local", "dist"}
                for part in path.split("/")
            )
            or path.endswith(
                (".log", ".pyc", ".tsbuildinfo", ".dump", ".dump.partial", ".age", ".agekey")
            )
            or (path.split("/")[-1].startswith(".env") and path != ".env.example")
        ):
            bad.append(path + ": sensitive/generated path")
            continue
        content = subprocess.check_output(["git", "show", ":" + path])
        if any(re.search(pattern, content) for pattern in SECRET_PATTERNS):
            bad.append(path + ": possible secret (value omitted)")
    return bad


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="Review the entire Git index")
    args = parser.parse_args()
    command = (
        ["git", "ls-files", "-z"]
        if args.all
        else ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"]
    )
    paths = subprocess.check_output(command, text=True).split("\0")
    paths = [path for path in paths if path]
    bad = check_paths(paths)
    if args.all:
        print(f"Tracked files reviewed: {len(paths)}")
    else:
        print("Staged files reviewed:", ", ".join(paths) or "none")
    if bad:
        print("\n".join(bad), file=sys.stderr)
        return 1
    subprocess.run(["git", "diff", "--cached", "--check"], check=True)
    print("Path/credential-pattern/whitespace checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
