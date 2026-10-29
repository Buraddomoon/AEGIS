"""Bounded full-duplex transport through tiny local children, never Docker effects."""

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runner_activation_metadata as transport  # noqa: E402


def child(monkeypatch, code):
    original = subprocess.Popen
    processes = []

    def launch(arguments, **kwargs):
        assert arguments[:2] == ["/usr/bin/docker", "--config"]
        folder = Path(arguments[2])
        assert folder.is_dir() and list(folder.iterdir()) == []
        assert arguments[3:5] == ["--host", "unix:///var/run/docker.sock"]
        assert kwargs["stdin"] == subprocess.PIPE and kwargs["env"] == transport.ENV
        assert "shell" not in kwargs
        process = original([sys.executable, "-c", code], **kwargs)
        processes.append((process, folder))
        return process

    monkeypatch.setattr(transport.subprocess, "Popen", launch)
    monkeypatch.setenv("DOCKER_HOST", "tcp://untrusted.invalid:2375")
    monkeypatch.setenv("DOCKER_CONFIG", "/private/config")
    monkeypatch.setenv("HTTP_PROXY", "http://untrusted.invalid")
    return processes


@pytest.mark.parametrize("size", [0, 1, 1024, 4 * 1024**2])
def test_private_stdin_is_fully_delivered_and_eof_is_sent_without_deadlock(monkeypatch, size):
    processes = child(
        monkeypatch,
        "import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest(),end='')",
    )
    payload = b"x" * size
    result = transport._execute(("closed-fixture-only",), payload=payload, timeout=5)
    assert result == hashlib.sha256(payload).hexdigest().encode()
    process, folder = processes[0]
    assert process.returncode == 0 and process.stdin.closed and not folder.exists()


def test_output_is_drained_while_input_is_written_and_stderr_is_never_returned(monkeypatch):
    processes = child(
        monkeypatch,
        "import os,sys; os.write(2,b'private-sensitive-sentinel'*1024); os.write(1,b'ok'); assert len(sys.stdin.buffer.read())==4*1024**2",
    )
    assert (
        transport._execute(("closed-fixture-only",), payload=b"x" * (4 * 1024**2), timeout=5)
        == b"ok"
    )
    assert processes[0][0].returncode == 0


@pytest.mark.parametrize(
    "code,expected",
    [
        ("import time;time.sleep(30)", "timed_out"),
        ("import os,time;os.close(0);time.sleep(30)", "delivery_unconfirmed"),
        ("import os;os.write(1,b'x'*1000000)", "response_too_large"),
        ("import os;os.write(2,b'x'*1000000)", "response_too_large"),
    ],
)
def test_timeout_closed_input_and_output_overflow_reap_child_and_preserve_static_error(
    monkeypatch, code, expected
):
    processes = child(monkeypatch, code)
    with pytest.raises(transport.ActivationError, match=expected) as error:
        transport._execute(("closed-fixture-only",), payload=b"x" * (4 * 1024**2), timeout=0.3)
    assert "private-sensitive-sentinel" not in str(error.value)
    process, folder = processes[0]
    assert process.poll() is not None and process.stdin.closed and not folder.exists()


def test_nonzero_exit_does_not_expose_stderr_after_consuming_input(monkeypatch):
    processes = child(
        monkeypatch,
        "import sys;sys.stdin.buffer.read();sys.stderr.write('private-sensitive-sentinel');sys.exit(3)",
    )
    with pytest.raises(transport.ActivationError, match="query_failed") as error:
        transport._execute(("closed-fixture-only",), payload=b"proof", timeout=5)
    assert "private-sensitive-sentinel" not in str(error.value)
    assert processes[0][0].returncode == 3


@pytest.mark.parametrize("recognized", [False, True])
def test_nonzero_private_probe_has_only_a_trusted_bounded_rejection_decoder(
    monkeypatch, recognized
):
    processes = child(
        monkeypatch,
        "import sys;sys.stdin.buffer.read();sys.stdout.write('bounded-envelope');sys.stderr.write('private-sensitive-sentinel');sys.exit(1)",
    )

    def decoder(raw):
        assert raw == b"bounded-envelope"
        if recognized:
            raise transport.ActivationError("reviewed-static-rejection")

    with pytest.raises(
        transport.ActivationError,
        match="reviewed-static-rejection" if recognized else "query_failed",
    ) as error:
        transport._execute(
            ("closed-fixture-only",),
            payload=b"request",
            timeout=5,
            output_limit=4 * 1024**2,
            failure_decoder=decoder,
        )
    assert "private-sensitive-sentinel" not in str(error.value)
    assert processes[0][0].returncode == 1 and processes[0][0].stdin.closed


@pytest.mark.parametrize(
    "payload,limit,decoder",
    [(None, 4 * 1024**2, lambda _: None), (b"x", 65536, lambda _: None), (b"x", 4 * 1024**2, True)],
)
def test_metadata_or_invalid_callbacks_cannot_select_failure_decoding(
    monkeypatch, payload, limit, decoder
):
    monkeypatch.setattr(
        transport.subprocess, "Popen", lambda *a, **k: pytest.fail("No child permitted")
    )
    with pytest.raises(transport.ActivationError, match="failure_decoder_profile"):
        transport._execute(
            ("closed-fixture-only",), payload=payload, output_limit=limit, failure_decoder=decoder
        )


@pytest.mark.parametrize("payload", ["not-bytes", bytearray(b"proof"), b"x" * (4 * 1024**2 + 1)])
def test_unbounded_or_nonbytes_stdin_is_rejected_before_spawning(monkeypatch, payload):
    monkeypatch.setattr(
        transport.subprocess, "Popen", lambda *a, **k: pytest.fail("No child permitted")
    )
    with pytest.raises(transport.ActivationError, match="input_invalid"):
        transport._execute(("closed-fixture-only",), payload=payload)


@pytest.mark.parametrize("budget", [0, -1, 21, "20", float("inf"), float("nan"), True, False])
def test_invalid_or_unbounded_deadline_is_rejected_before_spawning(monkeypatch, budget):
    monkeypatch.setattr(
        transport.subprocess, "Popen", lambda *a, **k: pytest.fail("No child permitted")
    )
    with pytest.raises(transport.ActivationError, match="time_budget"):
        transport._execute(("closed-fixture-only",), payload=b"proof", timeout=budget)


def test_private_proof_output_profile_is_bounded_and_default_metadata_limit_stays_unchanged(
    monkeypatch,
):
    processes = child(
        monkeypatch, "import os,sys;sys.stdin.buffer.read();os.write(1,b'x'*(4*1024**2))"
    )
    result = transport._execute(
        ("closed-fixture-only",), payload=b"request", timeout=5, output_limit=4 * 1024**2
    )
    assert len(result) == 4 * 1024**2 and processes[0][0].returncode == 0
    with pytest.raises(transport.ActivationError, match="response_too_large"):
        transport._execute(("closed-fixture-only",), payload=b"request", timeout=5)
    assert processes[1][0].poll() is not None and transport.MAX_OUTPUT == 65536


@pytest.mark.parametrize("channel", [1, 2])
def test_private_output_cap_still_counts_stderr_and_reaps_overflow(monkeypatch, channel):
    processes = child(
        monkeypatch, f"import os,sys;sys.stdin.buffer.read();os.write({channel},b'x'*(4*1024**2+1))"
    )
    with pytest.raises(transport.ActivationError, match="response_too_large"):
        transport._execute(
            ("closed-fixture-only",), payload=b"request", timeout=5, output_limit=4 * 1024**2
        )
    assert processes[0][0].poll() is not None


@pytest.mark.parametrize("limit", [0, 1, 65537, 4 * 1024**2 + 1, True, "4194304"])
def test_only_closed_output_profiles_are_allowed_before_spawn(monkeypatch, limit):
    monkeypatch.setattr(
        transport.subprocess, "Popen", lambda *a, **k: pytest.fail("No child permitted")
    )
    with pytest.raises(transport.ActivationError, match="output_profile"):
        transport._execute(("closed-fixture-only",), payload=b"request", output_limit=limit)
