"""Prepare and verify offline runner PKI candidates. Never activate or start a lab."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from aegis.domain.validation import digest
from aegis.integrations.linux_runner import RunnerConnection
from aegis.lab_runner.network_profile import LEGACY_LINUX_URL, LINUX_URL, WAZUH_URL
from aegis.lab_runner.wazuh_network_profile import LEGACY_RUNNER_URL
from init_linux_lab import initialize

FORMAT = "aegis-runner-pki-candidate/1"
TRANSITION_FORMAT = "aegis-runner-pki-candidate/2"
PUBLIC = (
    "connection.json",
    "server-ca.crt",
    "client-ca.crt",
    "runner-server.crt",
    "runner-client.crt",
)
ROLES = ("server-ca", "client-ca", "runner-server", "runner-client")
IDS = ("runner_id", "laboratory_id", "asset_id")
FILES = (
    set(PUBLIC)
    | {f"{role}.key" for role in ROLES}
    | {
        "server-ca.srl",
        "client-ca.srl",
        "runner-server.csr",
        "runner-client.csr",
        "server-extensions.cnf",
        "client-extensions.cnf",
        "ids.env",
    }
)
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


class PKIError(ValueError):
    """Only static error codes may be emitted to operators."""


def clock() -> datetime:
    return datetime.now(UTC)


def absolute(path: Path) -> Path:
    path = path.absolute()
    if ".." in path.parts or any(parent.is_symlink() for parent in (path, *path.parents)):
        raise PKIError("unsafe_path")
    return path


def private_directory(path: Path, *, create: bool = False) -> Path:
    path = absolute(path)
    if create:
        missing = []
        parent = path
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
            sync(directory)
            sync(directory.parent)
    info = path.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise PKIError("private_directory_required")
    if create:
        # A prior interrupted attempt may have created an entry without a
        # durable parent. Flush the existing private chain on retries too.
        directory = path
        while True:
            sync(directory)
            sync(directory.parent)
            parent_info = directory.parent.stat()
            if parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) != 0o700:
                break
            directory = directory.parent
    return path


def read(path: Path, *, modes=(0o444, 0o600, 0o644), maximum=65536) -> bytes:
    path = absolute(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in modes
            or info.st_size > maximum
        ):
            raise PKIError("unsafe_or_excessive_file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            content = stream.read(maximum + 1)
        if len(content) > maximum:
            raise PKIError("excessive_file")
        return content
    finally:
        os.close(fd)


def openssl(*args: str, data: bytes = b"") -> bytes:
    result = subprocess.run(
        ["/usr/bin/openssl", *args],
        input=data,
        capture_output=True,
        timeout=5,
        env=ENV,
        check=False,
    )
    if result.returncode or len(result.stdout) > 1048576 or len(result.stderr) > 1048576:
        raise PKIError("openssl_validation_failed")
    return result.stdout


def extension(certificate: bytes, name: str) -> tuple[str, str]:
    output = openssl("x509", "-noout", "-ext", name, data=certificate).decode("ascii").strip()
    lines = output.splitlines()
    return (lines[0], " ".join(line.strip() for line in lines[1:])) if lines else ("", "")


def date(value: str) -> datetime:
    match = re.fullmatch(r"([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4}) GMT", value)
    if not match:
        raise PKIError("invalid_certificate_date")
    month, day, hour, minute, second, year = match.groups()
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    return datetime(
        int(year),
        months.index(month) + 1,
        int(day),
        int(hour),
        int(minute),
        int(second),
        tzinfo=UTC,
    )


def certificate(content: bytes, role: str, connection: dict) -> dict:
    # Cache only immutable PUBLIC certificate parsing, keyed by the actual
    # bytes and every identity input used below. Each caller gets its own dict.
    # File/permission reads, chain verification, clock/lifetime checks and all
    # candidate private-key comparisons still run on every inventory/verify.
    return dict(_certificate(content, role, connection["runner_id"], connection["url"]))


@lru_cache(maxsize=32)
def _certificate(content: bytes, role: str, runner_id: str, url: str) -> tuple:
    if (
        content.count(b"-----BEGIN CERTIFICATE-----") != 1
        or not content.strip().startswith(b"-----BEGIN CERTIFICATE-----")
        or not content.strip().endswith(b"-----END CERTIFICATE-----")
    ):
        raise PKIError("single_pem_certificate_required")
    der = openssl("x509", "-outform", "DER", data=content)
    values = dict(
        line.split("=", 1)
        for line in openssl(
            "x509", "-noout", "-dates", "-subject", "-nameopt", "RFC2253", data=content
        )
        .decode("ascii")
        .splitlines()
    )
    start, end = date(values["notBefore"]), date(values["notAfter"])
    header, constraints = extension(content, "basicConstraints")
    is_ca = role.endswith("-ca")
    if not header.endswith(": critical") or constraints != ("CA:TRUE" if is_ca else "CA:FALSE"):
        raise PKIError("certificate_constraints_mismatch")
    header, usage = extension(content, "keyUsage")
    if not header.endswith(": critical") or usage != (
        "Certificate Sign, CRL Sign" if is_ca else "Digital Signature"
    ):
        raise PKIError("certificate_key_usage_mismatch")
    public = openssl("x509", "-noout", "-pubkey", data=content)
    spki = openssl("pkey", "-pubin", "-outform", "DER", data=public)
    if b"ASN1 OID: prime256v1" not in openssl("pkey", "-pubin", "-text_pub", "-noout", data=public):
        raise PKIError("reviewed_curve_required")
    if not is_ca:
        purpose = role.removeprefix("runner-")
        if values["subject"].strip() != f"CN=aegis-{purpose}-{runner_id}":
            raise PKIError("certificate_identity_mismatch")
        _, eku = extension(content, "extendedKeyUsage")
        if eku != (
            "TLS Web Server Authentication"
            if purpose == "server"
            else "TLS Web Client Authentication"
        ):
            raise PKIError("certificate_purpose_mismatch")
        _, san = extension(content, "subjectAltName")
        expected = f"IP Address:{urlsplit(url).hostname}" if purpose == "server" else ""
        if san != expected:
            raise PKIError("certificate_san_mismatch")
    return tuple(
        {
            "pem_sha256": hashlib.sha256(content).hexdigest(),
            "der_sha256": hashlib.sha256(der).hexdigest(),
            "spki_sha256": hashlib.sha256(spki).hexdigest(),
            "not_before": start.isoformat(),
            "not_after": end.isoformat(),
        }.items()
    )


def descriptor(connection: dict, certs: dict) -> dict:
    return {
        **{key: connection[key] for key in IDS},
        "url": connection["url"],
        "server_ca_sha256": certs["server-ca"]["pem_sha256"],
        "client_cert_sha256": certs["runner-client"]["pem_sha256"],
        "protocol": "aegis-linux-runner/1",
        "test_id": "linux-file-marker/v1",
    }


def inventory(source: Path, *, current: bool = False) -> tuple[dict, dict]:
    source = private_directory(source)
    public = {name: read(source / name) for name in PUBLIC}
    connection = RunnerConnection.model_validate_json(public["connection.json"]).model_dump(
        mode="json"
    )
    expected_paths = {
        "server_ca": "/run/secrets/controller_server_ca",
        "client_cert": "/run/secrets/controller_client_cert",
        "client_key": "/run/secrets/controller_client_key",
    }
    if any(connection[key] != value for key, value in expected_paths.items()) or connection[
        "url"
    ] not in {LEGACY_LINUX_URL, LINUX_URL, WAZUH_URL, LEGACY_RUNNER_URL}:
        raise PKIError("unreviewed_runner_configuration")
    certs = {role: certificate(public[role + ".crt"], role, connection) for role in ROLES}
    if len({value["spki_sha256"] for value in certs.values()}) != 4:
        raise PKIError("distinct_keys_required")
    instant = clock()
    # A private stable copy prevents OpenSSL reopening a changed source path.
    with tempfile.TemporaryDirectory(prefix="aegis-pki-public-") as temporary:
        root = Path(temporary)
        for name in PUBLIC[1:]:
            (root / name).write_bytes(public[name])
        for purpose in ("server", "client"):
            args = [
                "verify",
                "-no-CAfile",
                "-no-CApath",
                "-no-CAstore",
                "-trusted",
                str(root / f"{purpose}-ca.crt"),
                "-check_ss_sig",
                "-x509_strict",
                "-auth_level",
                "2",
                "-purpose",
                f"ssl{purpose}",
            ]
            args += ["-attime", str(int(instant.timestamp()))] if current else ["-no_check_time"]
            if purpose == "server":
                args += ["-verify_ip", urlsplit(connection["url"]).hostname]
            openssl(*args, str(root / f"runner-{purpose}.crt"))
    record = {
        "connection": connection,
        "connection_sha256": hashlib.sha256(public["connection.json"]).hexdigest(),
        "certificates": certs,
        "descriptor_sha256": digest(descriptor(connection, certs)),
    }
    validity = {
        role: datetime.fromisoformat(info["not_before"])
        <= instant
        < datetime.fromisoformat(info["not_after"])
        for role, info in certs.items()
    }
    return record, validity


def inspect(source: Path) -> dict:
    record, validity = inventory(source)
    return {
        "format": FORMAT,
        "status": "public_inventory_only",
        "public": record,
        "inventory_sha256": digest(record),
        "valid_now": validity,
        "source_private_keys_read": False,
        "activation_performed": False,
    }


def target_connection(source: dict, *, migrate_linux_network: bool = False) -> dict:
    if type(migrate_linux_network) is not bool:
        raise PKIError("explicit_network_transition_required")
    connection = dict(source["connection"])
    if migrate_linux_network:
        if connection["url"] != LEGACY_LINUX_URL:
            raise PKIError("legacy_linux_source_required")
        connection["url"] = LINUX_URL
    return connection


def validate_new(source: dict, target: Path, *, migrate_linux_network: bool = False) -> dict:
    if set(os.listdir(target)) not in (FILES, FILES | {"rotation.json"}):
        raise PKIError("unexpected_candidate_artifacts")
    for name in FILES:
        read(target / name, modes=(0o444, 0o600))
    new, validity = inventory(target, current=True)
    expected = target_connection(source, migrate_linux_network=migrate_linux_network)
    if new["connection"] != expected or not all(validity.values()):
        raise PKIError("candidate_identity_or_validity_mismatch")
    old_keys = {value["spki_sha256"] for value in source["certificates"].values()}
    instant = clock()
    for role in ROLES:
        info = new["certificates"][role]
        if info["spki_sha256"] in old_keys:
            raise PKIError("source_key_reuse_refused")
        key = read(target / f"{role}.key", modes=(0o600,) if role.endswith("-ca") else (0o444,))
        public = openssl("pkey", "-passin", "pass:", "-pubout", "-outform", "DER", data=key)
        if hashlib.sha256(public).hexdigest() != info["spki_sha256"]:
            raise PKIError("candidate_key_pair_mismatch")
        start, end = (datetime.fromisoformat(info[key]) for key in ("not_before", "not_after"))
        if end - start != timedelta(
            days=7 if role.endswith("-ca") else 2
        ) or end < instant + timedelta(hours=24):
            raise PKIError("candidate_lifetime_outside_policy")
        if role.startswith("runner-") and end > datetime.fromisoformat(
            new["certificates"][role.removeprefix("runner-") + "-ca"]["not_after"]
        ):
            raise PKIError("leaf_outlives_ca")
    expected_env = f"AEGIS_LAB_CONFIG_DIR={target}\n" + "".join(
        f"AEGIS_RUNNER_{key.upper()}={new['connection'][key]}\n" for key in IDS
    )
    if read(target / "ids.env", modes=(0o600,)).decode() != expected_env:
        raise PKIError("candidate_environment_mismatch")
    return new


def sync(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        if not (stat.S_ISREG(os.fstat(fd).st_mode) or stat.S_ISDIR(os.fstat(fd).st_mode)):
            raise PKIError("unsafe_sync_artifact")
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare(
    source: Path, expected_sha256: str, output_root: Path, *, migrate_linux_network: bool = False
) -> dict:
    original, _ = inventory(source)
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or digest(original) != expected_sha256:
        raise PKIError("source_inventory_drift")
    connection = target_connection(original, migrate_linux_network=migrate_linux_network)
    output_root = absolute(output_root)
    if output_root == absolute(source) or absolute(source) in output_root.parents:
        raise PKIError("candidate_must_be_separate_from_source")
    if not re.fullmatch(r"[A-Za-z0-9/._-]+", str(output_root)):
        raise PKIError("unsafe_compose_path")
    output_root = private_directory(output_root, create=True)
    identifier = uuid4().hex
    target = output_root / identifier
    initialize(
        target,
        server_ip=urlsplit(connection["url"]).hostname,
        identifiers={name: original["connection"][name] for name in IDS},
    )
    new = validate_new(original, target, migrate_linux_network=migrate_linux_network)
    if inventory(source)[0] != original:
        raise PKIError("source_changed_during_preparation")
    manifest = {
        "format": TRANSITION_FORMAT if migrate_linux_network else FORMAT,
        "id": identifier,
        "created_at": clock().isoformat(),
        "source": original,
        "candidate": new,
        "activation_performed": False,
    }
    # Flush every generated artifact before publishing the completion marker.
    for name in FILES:
        read(target / name, modes=(0o444, 0o600))
        sync(target / name)
    fd = os.open(
        target / "rotation.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "w") as stream:
        json.dump(manifest, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    sync(target)
    sync(output_root)
    return {
        "id": identifier,
        "candidate_path": str(target),
        "manifest_sha256": digest(manifest),
        "status": "prepared_not_activated",
        "activation_performed": False,
    }


def verify(source: Path, candidate: Path, expected_sha256: str) -> dict:
    candidate = private_directory(candidate)
    if candidate == absolute(source) or absolute(source) in candidate.parents:
        raise PKIError("candidate_must_be_separate_from_source")
    if not re.fullmatch(r"[A-Za-z0-9/._-]+", str(candidate)):
        raise PKIError("unsafe_compose_path")
    manifest = json.loads(read(candidate / "rotation.json", modes=(0o600,)))
    if not isinstance(manifest, dict) or set(manifest) != {
        "format",
        "id",
        "created_at",
        "source",
        "candidate",
        "activation_performed",
    }:
        raise PKIError("invalid_candidate_manifest")
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or digest(manifest) != expected_sha256:
        raise PKIError("manifest_integrity_mismatch")
    created_at = datetime.fromisoformat(manifest["created_at"])
    if created_at.utcoffset() != timedelta(0):
        raise PKIError("utc_manifest_time_required")
    if (
        manifest["format"] not in {FORMAT, TRANSITION_FORMAT}
        or manifest["id"] != candidate.name
        or UUID(hex=manifest["id"]).hex != manifest["id"]
        or manifest["activation_performed"] is not False
    ):
        raise PKIError("invalid_candidate_manifest")
    original, _ = inventory(source)
    if original != manifest["source"]:
        raise PKIError("source_inventory_drift")
    new = validate_new(
        original, candidate, migrate_linux_network=manifest["format"] == TRANSITION_FORMAT
    )
    if new != manifest["candidate"] or new["descriptor_sha256"] == original["descriptor_sha256"]:
        raise PKIError("candidate_inventory_drift")
    return {
        "format": manifest["format"],
        "id": manifest["id"],
        "manifest_sha256": expected_sha256,
        "status": "offline_candidate_verified_not_activated",
        "descriptor_sha256": new["descriptor_sha256"],
        "activation_performed": False,
        "lab_started": False,
        "database_modified": False,
        "journal_opened": False,
        "normal_operation_permitted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "prepare", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--source", type=Path, required=True)
        if name != "inspect":
            command.add_argument("--expected-sha256", required=True)
        if name == "prepare":
            command.add_argument("--output-root", type=Path, default=Path(".local/pki-candidates"))
            command.add_argument(
                "--migrate-linux-network",
                action="store_true",
                help="Offline candidate only: reviewed legacy Linux address to current fixed profile.",
            )
        if name == "verify":
            command.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "inspect":
            result = inspect(args.source)
        elif args.command == "prepare":
            result = prepare(
                args.source,
                args.expected_sha256,
                args.output_root,
                migrate_linux_network=args.migrate_linux_network,
            )
        else:
            result = verify(args.source, args.candidate, args.expected_sha256)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except PKIError as error:
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "code": str(error),
                    "error": "Candidato recusado; nenhum laboratório ativado.",
                }
            )
        )
        return 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "error": "PKI inválida, drift, permissões ou pré-requisito ausente; nenhum laboratório ativado.",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
