"""Bounded host transport for the closed lab-recovery recipes; no public CLI."""

import os
import selectors
import subprocess
import tempfile
import time

from aegis.operations.lab_backup import SnapshotError

ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C"}


def run(arguments, *, output=None, source=None, timeout=20, maximum=65536):
    """Unix Docker only; bounded stdout/stderr, deadline and kill/reap on failure.

    Callers compile fixed argv; never pass API/YAML commands. Source is a held,
    verified private archive file. Diagnostics never echo daemon/SQL output.
    """
    if not 0 < timeout <= 120 or maximum not in {65536, 128 * 1024**2, 512 * 1024**2}:
        raise SnapshotError("recovery_transport_profile")
    with tempfile.TemporaryDirectory(prefix="aegis-lr-docker-") as config:
        process = subprocess.Popen(
            [
                "/usr/bin/docker",
                "--config",
                config,
                "--host",
                "unix:///var/run/docker.sock",
                *arguments,
            ],
            env=ENV,
            stdin=source if source is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        captured, count, errors = bytearray(), 0, 0
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "out")
                selector.register(process.stderr, selectors.EVENT_READ, "err")
                while selector.get_map():
                    left = deadline - time.monotonic()
                    if left <= 0:
                        raise SnapshotError("recovery_transport_timeout")
                    for key, _ in selector.select(left):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                        elif key.data == "err":
                            errors += len(data)
                            if errors > 65536:
                                raise SnapshotError("recovery_transport_stderr_limit")
                        else:
                            count += len(data)
                            if count > maximum:
                                raise SnapshotError("recovery_transport_output_limit")
                            if output is None:
                                captured.extend(data)
                            else:
                                output.write(data)
                left = deadline - time.monotonic()
                if left <= 0 or process.wait(timeout=left):
                    raise SnapshotError("recovery_transport_failed")
            return bytes(captured)
        except (OSError, subprocess.SubprocessError):
            raise SnapshotError("recovery_transport_failed") from None
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
            process.stderr.close()
