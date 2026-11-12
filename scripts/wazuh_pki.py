"""Offline Wazuh service PKI inventory/candidates; no Docker, activation or old key reads."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import runner_pki as fs
from aegis.domain.validation import digest
from aegis.lab_runner.wazuh_network_profile import INDEXER_IP, LEGACY_INDEXER_IP

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "aegis-wazuh-pki-candidate/1"
TRANSITION_FORMAT = "aegis-wazuh-pki-candidate/2"
PUBLIC = ("root-ca.pem", "indexer.pem", "filebeat.pem")
KEYS = {
    "root-ca.pem": "ca-key.pem",
    "indexer.pem": "indexer-key.pem",
    "filebeat.pem": "filebeat-key.pem",
}
FILES = set(PUBLIC) | set(KEYS.values())
SUBJECTS = {
    "root-ca.pem": "CN=AEGIS isolated Wazuh CA",
    "indexer.pem": "O=AEGIS Lab,OU=AEGIS,CN=wazuh.indexer",
    "filebeat.pem": "O=AEGIS Lab,OU=AEGIS,CN=aegis-filebeat",
}
PROFILE_FILES = (
    "labs/wazuh/images.json",
    "labs/wazuh/compose.yml",
    "labs/wazuh/config/indexer.yml",
    "labs/wazuh/config/manager.xml",
    "labs/wazuh/config/agent.xml",
    "labs/wazuh/config/api.yml",
    "labs/wazuh/config/roles.yml",
    "labs/wazuh/config/roles_mapping.yml",
)


def profile(*, legacy: bool = False) -> dict:
    names = PROFILE_FILES if legacy else (*PROFILE_FILES, "labs/wazuh/network.yml")
    files = {name: hashlib.sha256(fs.read(ROOT / name)).hexdigest() for name in names}
    expected = (
        "d89a5089f6d88b7668fb2ca16107566edfb0a418287d0deb86c63c4acba08357"
        if legacy
        else "198d1a6feb3514d244902c41a8f31b6a730ba48a005abb7de12c036f3d6ce510"
    )
    # Both exact profiles are reviewed. The old public record stays byte-for-byte
    # comparable; it cannot be used by the current lifecycle/rotation procedure.
    if digest(files) != expected:
        raise fs.PKIError("unreviewed_wazuh_profile")
    # Only the already reviewed 4.14.9 amd64 manifests; this tool never discovers/upgrades images.
    if (
        files["labs/wazuh/images.json"]
        != "6cfa52e7ccd9878ba82adc10341e3539f4458d625e3a130cf7fcadf6f55c9a0d"
    ):
        raise fs.PKIError("unreviewed_wazuh_images")
    return {
        "files": files,
        "images": json.loads(fs.read(ROOT / "labs/wazuh/images.json")),
        "indexer_dns": "wazuh.indexer",
        "indexer_ip": LEGACY_INDEXER_IP if legacy else INDEXER_IP,
        "agent_transport": "wazuh-secure-aes-client.keys-not-x509",
        "management_api": "container-loopback-not-collector",
        "native_blockers": [149] if legacy else [],
    }


def certificate(content: bytes, name: str, *, indexer_ip: str = INDEXER_IP) -> dict:
    if indexer_ip not in {INDEXER_IP, LEGACY_INDEXER_IP}:
        raise fs.PKIError("unreviewed_wazuh_address")
    if (
        content.count(b"-----BEGIN CERTIFICATE-----") != 1
        or not content.strip().startswith(b"-----BEGIN CERTIFICATE-----")
        or not content.strip().endswith(b"-----END CERTIFICATE-----")
    ):
        raise fs.PKIError("single_pem_certificate_required")
    values = dict(
        line.split("=", 1)
        for line in fs.openssl(
            "x509", "-noout", "-dates", "-subject", "-nameopt", "RFC2253", data=content
        )
        .decode("ascii")
        .splitlines()
    )
    if values["subject"].strip() != SUBJECTS[name]:
        raise fs.PKIError("wazuh_certificate_dn_mismatch")
    is_ca = name == "root-ca.pem"
    header, constraints = fs.extension(content, "basicConstraints")
    if not header.endswith(": critical") or constraints != ("CA:TRUE" if is_ca else "CA:FALSE"):
        raise fs.PKIError("wazuh_certificate_constraints_mismatch")
    header, usage = fs.extension(content, "keyUsage")
    if not header.endswith(": critical") or usage != (
        "Certificate Sign, CRL Sign" if is_ca else "Digital Signature, Key Encipherment"
    ):
        raise fs.PKIError("wazuh_certificate_usage_mismatch")
    _, eku = fs.extension(content, "extendedKeyUsage")
    expected_eku = {
        "root-ca.pem": "",
        "indexer.pem": "TLS Web Server Authentication, TLS Web Client Authentication",
        "filebeat.pem": "TLS Web Client Authentication",
    }[name]
    if eku != expected_eku:
        raise fs.PKIError("wazuh_certificate_purpose_mismatch")
    _, san = fs.extension(content, "subjectAltName")
    if san != (f"DNS:wazuh.indexer, IP Address:{indexer_ip}" if name == "indexer.pem" else ""):
        raise fs.PKIError("wazuh_certificate_san_mismatch")
    public = fs.openssl("x509", "-pubkey", "-noout", data=content)
    if not fs.openssl("pkey", "-pubin", "-text_pub", "-noout", data=public).startswith(
        b"Public-Key: (2048 bit)"
    ):
        raise fs.PKIError("reviewed_rsa2048_required")
    # The textual size alone also describes other key types; RSA exponent must be present.
    if b"Exponent: 65537 (0x10001)" not in fs.openssl(
        "pkey", "-pubin", "-text_pub", "-noout", data=public
    ):
        raise fs.PKIError("reviewed_rsa2048_required")
    return {
        "pem_sha256": hashlib.sha256(content).hexdigest(),
        "spki_sha256": hashlib.sha256(
            fs.openssl("pkey", "-pubin", "-outform", "DER", data=public)
        ).hexdigest(),
        "subject": values["subject"].strip(),
        "san": san,
        "eku": eku,
        "not_before": fs.date(values["notBefore"]).isoformat(),
        "not_after": fs.date(values["notAfter"]).isoformat(),
    }


def inventory(source: Path, *, current: bool = False) -> dict:
    source = fs.private_directory(source)
    directory = fs.private_directory(source / "pki")
    public = {name: fs.read(directory / name) for name in PUBLIC}
    # Only two fixed exact SAN profiles. Do not infer arbitrary IPs from a certificate.
    _, san = fs.extension(public["indexer.pem"], "subjectAltName")
    indexer_ip = (
        LEGACY_INDEXER_IP
        if san == f"DNS:wazuh.indexer, IP Address:{LEGACY_INDEXER_IP}"
        else INDEXER_IP
    )
    certs = {
        name: certificate(content, name, indexer_ip=indexer_ip) for name, content in public.items()
    }
    if len({info["spki_sha256"] for info in certs.values()}) != 3:
        raise fs.PKIError("distinct_wazuh_keys_required")
    with tempfile.TemporaryDirectory(prefix="aegis-wazuh-public-") as folder:
        root = Path(folder)
        for name, content in public.items():
            (root / name).write_bytes(content)
        base = [
            "verify",
            "-no-CAfile",
            "-no-CApath",
            "-no-CAstore",
            "-trusted",
            str(root / "root-ca.pem"),
            "-check_ss_sig",
            "-x509_strict",
            "-auth_level",
            "2",
        ]
        base += ["-attime", str(int(fs.clock().timestamp()))] if current else ["-no_check_time"]
        fs.openssl(*base, str(root / "root-ca.pem"))
        for name, purpose in (
            ("indexer.pem", "sslserver"),
            ("indexer.pem", "sslclient"),
            ("filebeat.pem", "sslclient"),
        ):
            extra = ["-verify_hostname", "wazuh.indexer"] if purpose == "sslserver" else []
            fs.openssl(*base, "-purpose", purpose, *extra, str(root / name))
        fs.openssl(*base, "-verify_ip", indexer_ip, str(root / "indexer.pem"))
    return {"profile": profile(legacy=indexer_ip == LEGACY_INDEXER_IP), "certificates": certs}


def inspect(source: Path) -> dict:
    record = inventory(source)
    instant = fs.clock()
    return {
        "format": FORMAT,
        "status": "public_inventory_only",
        "public": record,
        "inventory_sha256": digest(record),
        "valid_now": {
            name: datetime.fromisoformat(info["not_before"])
            <= instant
            < datetime.fromisoformat(info["not_after"])
            for name, info in record["certificates"].items()
        },
        "source_private_keys_read": False,
        "activation_performed": False,
    }


def separate(source: Path, target: Path) -> Path:
    source, target = fs.absolute(source), fs.absolute(target)
    if source == target or source in target.parents or target in source.parents:
        raise fs.PKIError("candidate_must_be_separate_from_source")
    if not re.fullmatch(r"[A-Za-z0-9/._-]+", str(target)):
        raise fs.PKIError("unsafe_compose_path")
    return target


def generate(target: Path, *, indexer_ip: str = INDEXER_IP):
    """New service keys only; never invoke prepare_wazuh_lab/recreate credentials or runner IDs."""
    directory = target / "pki"
    directory.mkdir(mode=0o700)
    previous = os.umask(0o077)
    try:
        fs.openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(directory / "ca-key.pem"),
            "-out",
            str(directory / "root-ca.pem"),
            "-days",
            "7",
            "-subj",
            "/CN=AEGIS isolated Wazuh CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
        for name, common, eku in (
            ("indexer", "wazuh.indexer", "serverAuth,clientAuth"),
            ("filebeat", "aegis-filebeat", "clientAuth"),
        ):
            # CSR/extensions are transient private files, not completion markers.
            with tempfile.TemporaryDirectory(dir=target, prefix="request-") as temporary:
                root = Path(temporary)
                fs.openssl(
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(directory / f"{name}-key.pem"),
                    "-out",
                    str(root / "leaf.csr"),
                    "-subj",
                    f"/CN={common}/OU=AEGIS/O=AEGIS Lab",
                )
                extensions = (
                    "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
                    + f"extendedKeyUsage={eku}\n"
                )
                if name == "indexer":
                    extensions += f"subjectAltName=DNS:wazuh.indexer,IP:{indexer_ip}\n"
                (root / "extensions.cnf").write_text(extensions)
                fs.openssl(
                    "x509",
                    "-req",
                    "-in",
                    str(root / "leaf.csr"),
                    "-CA",
                    str(directory / "root-ca.pem"),
                    "-CAkey",
                    str(directory / "ca-key.pem"),
                    "-set_serial",
                    str(int(uuid4())),
                    "-out",
                    str(directory / f"{name}.pem"),
                    "-days",
                    "2",
                    "-sha256",
                    "-extfile",
                    str(root / "extensions.cnf"),
                )
        for name in FILES:
            (directory / name).chmod(0o600 if name == "ca-key.pem" else 0o444)
    finally:
        os.umask(previous)


def validate_new(original: dict, target: Path, *, migrate_wazuh_network: bool = False) -> dict:
    fs.private_directory(target)
    if set(os.listdir(target / "pki")) != FILES or set(os.listdir(target)) not in (
        {"pki"},
        {"pki", "rotation.json"},
    ):
        raise fs.PKIError("unexpected_wazuh_candidate_artifacts")
    for name in FILES:
        fs.read(target / "pki" / name, modes=(0o600,) if name == "ca-key.pem" else (0o444,))
    new = inventory(target, current=True)
    if type(migrate_wazuh_network) is not bool or (
        migrate_wazuh_network and original["profile"]["indexer_ip"] != LEGACY_INDEXER_IP
    ):
        raise fs.PKIError("explicit_legacy_wazuh_transition_required")
    if new["profile"] != (profile() if migrate_wazuh_network else original["profile"]):
        raise fs.PKIError("wazuh_profile_drift")
    old_keys = {info["spki_sha256"] for info in original["certificates"].values()}
    instant = fs.clock()
    for name, info in new["certificates"].items():
        if info["spki_sha256"] in old_keys:
            raise fs.PKIError("source_key_reuse_refused")
        key = fs.read(
            target / "pki" / KEYS[name], modes=(0o600,) if name == "root-ca.pem" else (0o444,)
        )
        public = fs.openssl("pkey", "-passin", "pass:", "-pubout", "-outform", "DER", data=key)
        if hashlib.sha256(public).hexdigest() != info["spki_sha256"]:
            raise fs.PKIError("wazuh_candidate_key_pair_mismatch")
        start, end = (datetime.fromisoformat(info[field]) for field in ("not_before", "not_after"))
        if end - start != timedelta(
            days=7 if name == "root-ca.pem" else 2
        ) or end < instant + timedelta(hours=24):
            raise fs.PKIError("candidate_lifetime_outside_policy")
        if end > datetime.fromisoformat(new["certificates"]["root-ca.pem"]["not_after"]):
            raise fs.PKIError("leaf_outlives_ca")
    return new


def write_json(path: Path, value: dict):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    fs.sync(path.parent)


def prepare(
    source: Path, expected_sha256: str, output_root: Path, *, migrate_wazuh_network: bool = False
) -> dict:
    original = inventory(source)
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or digest(original) != expected_sha256:
        raise fs.PKIError("source_inventory_drift")
    if type(migrate_wazuh_network) is not bool or (
        migrate_wazuh_network and original["profile"]["indexer_ip"] != LEGACY_INDEXER_IP
    ):
        raise fs.PKIError("explicit_legacy_wazuh_transition_required")
    output_root = fs.private_directory(separate(source, output_root), create=True)
    target = output_root / uuid4().hex
    target.mkdir(mode=0o700)
    generate(
        target,
        indexer_ip=INDEXER_IP if migrate_wazuh_network else original["profile"]["indexer_ip"],
    )
    new = validate_new(original, target, migrate_wazuh_network=migrate_wazuh_network)
    if inventory(source) != original:
        raise fs.PKIError("source_changed_during_preparation")
    manifest = {
        "format": TRANSITION_FORMAT if migrate_wazuh_network else FORMAT,
        "id": target.name,
        "created_at": fs.clock().isoformat(),
        "source": original,
        "candidate": new,
        "activation_performed": False,
    }
    for name in FILES:
        fs.sync(target / "pki" / name)
    fs.sync(target / "pki")
    write_json(target / "rotation.json", manifest)
    fs.sync(output_root)
    return {
        "id": target.name,
        "candidate_path": str(target),
        "manifest_sha256": digest(manifest),
        "status": "prepared_not_activated",
        "native_blockers": new["profile"]["native_blockers"],
        "activation_performed": False,
    }


def verify(source: Path, candidate: Path, expected_sha256: str) -> dict:
    candidate = fs.private_directory(separate(source, candidate))
    manifest = json.loads(fs.read(candidate / "rotation.json", modes=(0o600,)))
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or digest(manifest) != expected_sha256:
        raise fs.PKIError("manifest_integrity_mismatch")
    if (
        set(manifest)
        != {"format", "id", "created_at", "source", "candidate", "activation_performed"}
        or manifest["format"] not in {FORMAT, TRANSITION_FORMAT}
        or manifest["id"] != candidate.name
        or UUID(hex=manifest["id"]).hex != manifest["id"]
        or manifest["activation_performed"] is not False
        or datetime.fromisoformat(manifest["created_at"]).utcoffset() != timedelta(0)
    ):
        raise fs.PKIError("invalid_wazuh_candidate_manifest")
    original = inventory(source)
    if original != manifest["source"]:
        raise fs.PKIError("source_inventory_drift")
    new = validate_new(
        original, candidate, migrate_wazuh_network=manifest["format"] == TRANSITION_FORMAT
    )
    if new != manifest["candidate"]:
        raise fs.PKIError("candidate_inventory_drift")
    # Recheck time after all IO and key comparisons, never accept a stale successful parse.
    if any(
        datetime.fromisoformat(info["not_after"]) < fs.clock() + timedelta(hours=24)
        for info in new["certificates"].values()
    ):
        raise fs.PKIError("candidate_lifetime_outside_policy")
    return {
        "format": manifest["format"],
        "status": "offline_candidate_verified_not_activated",
        "manifest_sha256": expected_sha256,
        "candidate": new,
        "native_blockers": new["profile"]["native_blockers"],
        "activation_performed": False,
        "lab_started": False,
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
            command.add_argument("--migrate-wazuh-network", action="store_true")
            command.add_argument(
                "--output-root", type=Path, default=Path(".local/wazuh-pki-candidates")
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
                migrate_wazuh_network=args.migrate_wazuh_network,
            )
        else:
            result = verify(args.source, args.candidate, args.expected_sha256)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "error": "PKI Wazuh recusada: integridade, identidade, validade ou permissões. Origem preservada; nenhum serviço iniciado.",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
