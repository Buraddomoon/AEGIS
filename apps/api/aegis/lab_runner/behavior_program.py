"""Two fixed children; Profile is selected by the reviewed policy, never API input."""

import ctypes
import hashlib
import json
import os
import re
import resource
import signal
import subprocess
import sys
from datetime import UTC, datetime
from uuid import UUID


def bind_parent(parent, death_signal):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, death_signal, 0, 0, 0) != 0 or os.getppid() != parent:
        raise RuntimeError("Parent changed before watchdog binding")


def interrupted(signum, frame):
    raise InterruptedError("Supervisor terminated")


def main(kind):
    data = json.loads(sys.stdin.buffer.read(4096))
    marker = data["marker"]
    if not re.fullmatch(r"aegis-[0-9a-f-]{36}", marker) or str(UUID(marker[6:])) != marker[6:]:
        raise ValueError("Invalid marker")
    signal.signal(signal.SIGTERM, interrupted)
    bind_parent(data["parent_pid"], signal.SIGTERM)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8192, 8192))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    # Python3.13's allocator reserves virtual arenas; RSS stays container-limited.
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    os.umask(0o077)
    content = (marker + "\n").encode("ascii")
    # Neither argv nor script comes from the request. Marker is one data argument.
    command = (
        ["/bin/true", marker]
        if kind == "process"
        else ["/bin/sh", "-c", "printf '%s\\n' \"$0\"", marker]
    )
    if kind not in ("process", "shell"):
        raise ValueError("Unknown fixed program")
    parent = os.getpid()

    def child_watchdog():
        # This helper is single-threaded; no threaded-parent preexec_fn.
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        bind_parent(parent, signal.SIGKILL)
        signal.pthread_sigmask(signal.SIG_SETMASK, [])

    started = datetime.now(UTC).isoformat()
    child = None
    # Defer termination until ownership of a newly spawned child is recorded.
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGTERM])
    try:
        try:
            child = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
                preexec_fn=child_watchdog,
            )
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        output = child.stdout.read(257)
        if len(output) > 256 or child.wait(timeout=1) != 0:
            raise ValueError("Fixed child failed or exceeded output limit")
        if output != (content if kind == "shell" else b""):
            raise ValueError("Unexpected child stdout")
    finally:
        # SIGTERM may arrive during read/wait or immediately after Popen returns.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=1)
            child.stdout.close()
    receipt = {
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
        "artifact_bytes": len(content),
        "started_at": started,
        "ended_at": datetime.now(UTC).isoformat(),
        "child_pid": child.pid,
        "child_exit_code": 0,
        "stdout_sha256": hashlib.sha256(output).hexdigest(),
        "stdout_bytes": len(output),
    }
    for name, value in (("proof.marker", content), ("receipt.json", json.dumps(receipt).encode())):
        fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
