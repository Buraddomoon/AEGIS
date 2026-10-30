"""Fixed identity-only TLS controls; never submit a job or open lab state."""

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import re
import ssl
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from aegis.domain.validation import digest
from aegis.lab_runner.protocol import RunnerIdentity

HOST, PORT = "172.30.88.2", 8443
MAX_INPUT, MAX_RESPONSE = 16384, 32768
MAX_OUTPUT = 4096
REQUEST_FORMAT = "aegis-identity-tls-request/2"
RESULT_FORMAT = "aegis-identity-tls-probe/2"
DEADLINE_SECONDS = 12
FILES = {
    "candidate_server_ca": Path("/run/secrets/controller_server_ca"),
    "candidate_client_cert": Path("/run/secrets/controller_client_cert"),
    "previous_server_ca": Path("/run/secrets/identity_previous_server_ca"),
}
CLIENT_KEY = Path("/run/secrets/controller_client_key")
FLAGS = {
    "database_verified": False,
    "journal_verified": False,
    "old_client_rejection_verified": False,
    "activation_permitted": False,
    "normal_operation_permitted": False,
    "marker_executed": False,
}
ERRORS = frozenset(
    {
        "process_required",
        "private_pipe_required",
        "ambient_tls_configuration",
        "context_invalid",
        "reply_invalid",
        "certificate_inputs_unconfirmed",
        "tls13_unavailable",
        "positive_identity_unconfirmed",
        "missing_client_rejection_unconfirmed",
        "previous_trust_rejection_unconfirmed",
        "transport_deadline",
    }
)


class ProbeError(ValueError):
    pass


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProbeError("context_invalid")
        value[key] = item
    return value


def _sha(value):
    return isinstance(value, str) and re.fullmatch("[a-f0-9]{64}", value) is not None


def _now():
    return datetime.now(UTC)


def _window(value):
    created, expires = (datetime.fromisoformat(value[key]) for key in ("created_at", "expires_at"))
    if (
        created.utcoffset() != timedelta(0)
        or expires.utcoffset() != timedelta(0)
        or not timedelta(0) < expires - created <= timedelta(seconds=300)
    ):
        raise ProbeError("context_invalid")
    return created, expires


def decode(payload, expected_sha256, *, current=True):
    try:
        if type(payload) is not bytes or len(payload) > MAX_INPUT or not _sha(expected_sha256):
            raise ValueError
        value = json.loads(payload, object_pairs_hook=_unique)
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "format",
                "created_at",
                "expires_at",
                "operation_id",
                "plan_sha256",
                "scope_sha256",
                "identity",
                "certificate_sha256",
                "server_leaf_sha256",
                "client_leaf_sha256",
            }
            or digest(value) != expected_sha256
            or value["format"] != REQUEST_FORMAT
            or UUID(hex=value["operation_id"]).hex != value["operation_id"]
            or any(
                not _sha(value[key])
                for key in (
                    "plan_sha256",
                    "scope_sha256",
                    "server_leaf_sha256",
                    "client_leaf_sha256",
                )
            )
            or not isinstance(value["certificate_sha256"], dict)
            or set(value["certificate_sha256"]) != set(FILES)
            or any(not _sha(item) for item in value["certificate_sha256"].values())
            or value["certificate_sha256"]["candidate_server_ca"]
            == value["certificate_sha256"]["previous_server_ca"]
        ):
            raise ValueError
        identity = RunnerIdentity.model_validate(value["identity"])
        if identity.tests or digest(identity.model_dump(mode="json")) != digest(value["identity"]):
            raise ValueError
        created, expires = _window(value)
        if current and not created <= _now() < expires:
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ProbeError("context_invalid") from None


def _process():
    if (
        sys.platform != "linux"
        or os.getpid() != 1
        or os.geteuid() != 10001
        or os.getegid() != 10001
        or not Path("/.dockerenv").is_file()
    ):
        raise ProbeError("process_required")
    if sys.stdin.isatty() or sys.stdout.isatty():
        raise ProbeError("private_pipe_required")
    _tls_environment()


def _tls_environment():
    if any(name in os.environ for name in ("SSLKEYLOGFILE", "SSL_CERT_FILE", "SSL_CERT_DIR")):
        raise ProbeError("ambient_tls_configuration")


def _public(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 65536:
            raise ProbeError("certificate_inputs_unconfirmed")
        payload = stream.read(65537)
        if len(payload) != info.st_size:
            raise ProbeError("certificate_inputs_unconfirmed")
        return payload


def _context(cafile, *, authenticated):
    _tls_environment()
    if not ssl.HAS_TLSv1_3:
        raise ProbeError("tls13_unavailable")
    context = ssl.create_default_context(cafile=str(cafile))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    if authenticated:
        if CLIENT_KEY.is_symlink() or not CLIENT_KEY.is_file():
            raise ProbeError("certificate_inputs_unconfirmed")
        context.load_cert_chain(str(FILES["candidate_client_cert"]), str(CLIENT_KEY))
    return context


async def _exchange(context):
    reader, writer = await asyncio.open_connection(
        HOST, PORT, ssl=context, server_hostname=HOST, ssl_handshake_timeout=2, limit=8192
    )
    try:
        peer = writer.get_extra_info("ssl_object")
        if peer is None or peer.version() != "TLSv1.3":
            raise ProbeError("positive_identity_unconfirmed")
        peer_sha = hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest()
        writer.write(
            (
                "GET /v1/identity HTTP/1.1\r\nHost: "
                + HOST
                + ":"
                + str(PORT)
                + "\r\nConnection: close\r\nAccept: application/json\r\nAccept-Encoding: identity\r\n\r\n"
            ).encode("ascii")
        )
        await writer.drain()
        header = await reader.readuntil(b"\r\n\r\n")
        lines = header.decode("ascii").split("\r\n")
        if not lines[0].startswith("HTTP/1.1 200 "):
            raise ProbeError("positive_identity_unconfirmed")
        headers = {}
        for line in lines[1:-2]:
            key, value = line.split(":", 1)
            key = key.lower()
            if key in headers:
                raise ProbeError("positive_identity_unconfirmed")
            headers[key] = value.strip()
        length = headers.get("content-length", "")
        if (
            not length.isdecimal()
            or not 0 < int(length) <= MAX_RESPONSE
            or "transfer-encoding" in headers
            or "content-encoding" in headers
            or headers.get("content-type", "").split(";", 1)[0] != "application/json"
            or headers.get("x-aegis-runner-mode") != "identity-only"
            or not _sha(headers.get("x-aegis-client-cert-sha256"))
            or headers.get("x-aegis-client-cert-policy") != "required"
            or headers.get("x-aegis-tls-version") != "TLSv1.3"
        ):
            raise ProbeError("positive_identity_unconfirmed")
        body = await reader.readexactly(int(length))
        if await reader.read(1):
            raise ProbeError("positive_identity_unconfirmed")
        return (
            json.loads(body, object_pairs_hook=_unique),
            peer_sha,
            headers["x-aegis-client-cert-sha256"],
        )
    finally:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError, TimeoutError):
            async with asyncio.timeout(0.5):
                await writer.wait_closed()


async def check(value):
    """Internal fixed-peer operation; native invocation still requires host authorization."""
    created, expires = _window(value)
    if not created <= _now() < expires:
        raise ProbeError("transport_deadline")
    public = {}
    for name, path in FILES.items():
        public[name] = _public(path)
        if hashlib.sha256(public[name]).hexdigest() != value["certificate_sha256"][name]:
            raise ProbeError("certificate_inputs_unconfirmed")
    der = ssl.PEM_cert_to_DER_cert(public["candidate_client_cert"].decode("ascii"))
    if hashlib.sha256(der).hexdigest() != value["client_leaf_sha256"]:
        raise ProbeError("certificate_inputs_unconfirmed")
    good = _context(FILES["candidate_server_ca"], authenticated=True)
    missing = _context(FILES["candidate_server_ca"], authenticated=False)
    previous = _context(FILES["previous_server_ca"], authenticated=True)

    async def request(context):
        if not created <= _now() < expires:
            raise ProbeError("transport_deadline")
        return await _exchange(context)

    async def positive(context):
        document, peer_sha, client_sha = await request(context)
        if (
            digest(document) != digest(value["identity"])
            or peer_sha != value["server_leaf_sha256"]
            or client_sha != value["client_leaf_sha256"]
        ):
            raise ProbeError("positive_identity_unconfirmed")

    try:
        remaining = (expires - _now()).total_seconds()
        if remaining <= 0:
            raise ProbeError("transport_deadline")
        async with asyncio.timeout(min(DEADLINE_SECONDS, remaining)):
            await positive(good)
            omission = "certificate_required_alert"
            try:
                await request(missing)
            except ssl.SSLError as error:
                if error.reason != "TLSV13_ALERT_CERTIFICATE_REQUIRED":
                    raise ProbeError("missing_client_rejection_unconfirmed") from None
            except (ConnectionResetError, asyncio.IncompleteReadError):
                # A closed transport without a TLS reason is not certificate proof.
                omission = "connection_closed_without_tls_reason"
            else:
                raise ProbeError("missing_client_rejection_unconfirmed")
            try:
                await request(previous)
            except ssl.SSLCertVerificationError as error:
                if error.verify_code not in {19, 20, 21}:
                    raise ProbeError("previous_trust_rejection_unconfirmed") from None
            else:
                raise ProbeError("previous_trust_rejection_unconfirmed")
            await positive(good)
    except TimeoutError:
        raise ProbeError("transport_deadline") from None
    return _result(value, omission)


def _result(value, omission):
    return {
        "format": RESULT_FORMAT,
        "status": "identity_tls_controls_verified"
        if omission == "certificate_required_alert"
        else "identity_tls_controls_inconclusive",
        "context_sha256": digest(value),
        "identity_sha256": digest(value["identity"]),
        "server_leaf_sha256": value["server_leaf_sha256"],
        "client_leaf_sha256": value["client_leaf_sha256"],
        "tls_version": "TLSv1.3",
        "identity_with_candidate_material_verified": True,
        "candidate_client_certificate_verified": True,
        "server_client_certificate_policy_verified": True,
        "missing_client_rejection_verified": omission == "certificate_required_alert",
        "missing_client_control_outcome": omission,
        "previous_ca_rejected": True,
        "identity_revalidated": True,
        **FLAGS,
    }


def decode_result(payload, expected, expected_context_sha256):
    """Check closed wire integrity/classification only; runtime origin is a separate gate."""
    try:
        checked = decode(json.dumps(expected).encode(), expected_context_sha256, current=False)
        if type(payload) is not bytes or len(payload) > MAX_OUTPUT:
            raise ValueError
        value = json.loads(payload, object_pairs_hook=_unique)
        if not isinstance(value, dict):
            raise ValueError
        outcome = value.get("missing_client_control_outcome")
        if (
            not isinstance(outcome, str)
            or outcome not in {"certificate_required_alert", "connection_closed_without_tls_reason"}
            or digest(value) != digest(_result(checked, outcome))
        ):
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ProbeError("reply_invalid") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        _process()
        value = decode(sys.stdin.buffer.read(MAX_INPUT + 1), args.context_sha256)
        result = asyncio.run(check(value))
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        code = (
            error.args[0]
            if isinstance(error, ProbeError)
            and len(error.args) == 1
            and type(error.args[0]) is str
            and error.args[0] in ERRORS
            else "identity_tls_probe_rejected"
        )
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "code": code,
                    "context_sha256": args.context_sha256 if _sha(args.context_sha256) else None,
                    **FLAGS,
                },
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
