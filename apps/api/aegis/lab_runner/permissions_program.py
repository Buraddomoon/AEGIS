"""Fixed Linux permission change on one newly created owned file; no shell or inputs."""

import ctypes
import hashlib
import json
import os
import resource
import signal
import stat
import sys
from datetime import UTC, datetime
from uuid import UUID


def main():
    data = json.loads(sys.stdin.buffer.read(4096))
    if set(data) != {"marker", "parent_pid"}:
        raise ValueError("Unexpected input")
    marker = data["marker"]
    if not isinstance(marker, str) or marker != "aegis-" + str(UUID(marker[6:])):
        raise ValueError("Invalid marker")
    if os.geteuid() == 0:
        raise ValueError("Unprivileged runner required")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != data["parent_pid"]:
        raise RuntimeError("Parent identity changed before watchdog binding")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8192, 8192))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
    os.umask(0o077)
    directory = os.stat(".")
    if (
        directory.st_uid != os.geteuid()
        or stat.S_IMODE(directory.st_mode) != 0o700
        or os.listdir(".")
    ):
        raise ValueError("Private empty workspace required")
    content = (marker + "\n").encode("ascii")
    started = datetime.now(UTC).isoformat()
    fd = os.open("proof.marker", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o400
        ):
            raise ValueError("Unexpected owned artifact")
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o600)
        after = os.fstat(stream.fileno())
        if stat.S_IMODE(after.st_mode) != 0o600:
            raise ValueError("Permission change not observed")
        os.fsync(stream.fileno())
    receipt = {
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
        "artifact_bytes": len(content),
        "started_at": started,
        "ended_at": datetime.now(UTC).isoformat(),
        "mode_before": stat.S_IMODE(before.st_mode),
        "mode_after": stat.S_IMODE(after.st_mode),
    }
    fd = os.open("receipt.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(receipt, stream)
        stream.flush()
        os.fsync(stream.fileno())


if __name__ == "__main__":
    main()
