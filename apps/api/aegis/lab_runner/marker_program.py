"""Fixed benign Linux program, launched with Python -I -S. No API command input."""

import ctypes
import hashlib
import json
import os
import resource
import signal
import sys
from datetime import UTC, datetime


def main():
    data = json.loads(sys.stdin.buffer.read(4096))
    # Install in child, never preexec_fn in the threaded parent. Fail closed on error/race.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != data["parent_pid"]:
        raise RuntimeError("Parent identity changed before watchdog binding")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8192, 8192))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
    os.umask(0o077)
    content = (data["marker"] + "\n").encode("ascii")
    if len(content) > 256:
        raise ValueError("Marker too long")
    started = datetime.now(UTC).isoformat()
    fd = os.open("proof.marker", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    receipt = {
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
        "artifact_bytes": len(content),
        "started_at": started,
        "ended_at": datetime.now(UTC).isoformat(),
    }
    fd = os.open("receipt.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(receipt, stream)
        stream.flush()
        os.fsync(stream.fileno())


if __name__ == "__main__":
    main()
