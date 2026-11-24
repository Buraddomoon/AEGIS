"""Host-only data snapshot preparation, without lab lifecycle or credentials.

The trusted caller supplies a dump writer using the exported PostgreSQL snapshot
and previously exported private fences. This library does not prove physical
volume binding, complete host-fence collection or external quiescence. It never
starts Docker, PostgreSQL, a runner or an application. Native acceptance is #66.
"""

import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.domain.validation import digest
from aegis.lab_runner import continuity, persisted_review
from aegis.lab_runner.protocol import RunnerIdentity
from aegis.operations import backup, vault

FORMAT = "aegis-lab-data-snapshot/1"
MAX_DUMP = 128 * 1024 * 1024
MAX_JSON = 4 * 1024 * 1024
SHA = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
IMAGE = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]


class SnapshotError(ValueError):
    """Static errors only; source rows, credentials and paths stay private."""


class Images(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    application: IMAGE
    runner: IMAGE
    postgres: IMAGE
    redis: IMAGE


class Context(BaseModel):
    """Public inventory only; no private keys or database connection URLs.

    This initial profile is restricted to the historical marker labs. Imported
    Atomic and the opt-in process/shell profiles need their own snapshot review.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    project: Literal["aegis-linux-lab", "aegis-wazuh-lab"]
    source_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    identity: RunnerIdentity
    descriptor: dict[str, str]
    descriptor_sha256: SHA
    server_ca_sha256: SHA
    client_cert_sha256: SHA
    images: Images
    database_schema: Annotated[str, Field(pattern=r"^[a-z_][a-z_0-9]{0,62}$")]
    schema_revision: Annotated[str, Field(pattern=r"^[a-f0-9]{12}$")]
    environment_version: Annotated[int, Field(gt=0)]

    @model_validator(mode="after")
    def public_descriptor(self):
        value = self.descriptor
        expected = {
            **{
                name: str(getattr(self.identity, name))
                for name in ("runner_id", "laboratory_id", "asset_id")
            },
            "server_ca_sha256": self.server_ca_sha256,
            "client_cert_sha256": self.client_cert_sha256,
            "protocol": "aegis-linux-runner/1",
            "test_id": "linux-file-marker/v1",
            "url": value.get("url"),
        }
        address = urlsplit(value.get("url", ""))
        if (
            value != expected
            or not re.fullmatch(r"https://[0-9.]{7,15}:8443/?", value.get("url", ""))
            or digest(value) != self.descriptor_sha256
            or self.identity.tests != ("linux-file-marker/v1",)
            or address.scheme != "https"
            or address.username is not None
            or address.password is not None
            or address.query
            or address.fragment
            or address.path not in {"", "/"}
            or address.port != 8443
        ):
            raise ValueError("snapshot_public_descriptor_invalid")
        IPv4Address(address.hostname)
        return self


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _stable_proofs(bundle):
    # Only the review observation time is volatile. Never edit the stored proof.
    return {
        **bundle,
        "review": {key: value for key, value in bundle["review"].items() if key != "reviewed_at"},
    }


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SnapshotError("snapshot_duplicate_json_key")
            result[key] = value
        return result

    def invalid(_):
        raise SnapshotError("snapshot_nonfinite_json")

    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def _directory(path):
    vault.no_symlink_parents(path)
    info = path.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise SnapshotError("snapshot_directory_unsafe")


def _new(path):
    _directory(path.parent)
    vault.no_symlink_parents(path)
    path.mkdir(mode=0o700)  # Exclusive: never adopt/overwrite an existing directory.
    vault.sync_directory(path.parent)


def _read(path, maximum):
    with vault.private_file(path, maximum=maximum) as stream:
        before = continuity._signature(os.fstat(stream.fileno()))
        data = stream.read(maximum + 1)
        if (
            len(data) > maximum
            or continuity._signature(os.fstat(stream.fileno())) != before
            or continuity._signature(path.stat(follow_symlinks=False)) != before
        ):
            raise SnapshotError("snapshot_file_changed")
        return data


@contextmanager
def _guard():
    """Normalize diagnostics, including SQL errors that can contain row values."""
    try:
        yield
    except SnapshotError:
        raise
    except Exception:
        raise SnapshotError("snapshot_preparation_failed") from None


def create(
    engine, journal: Path, context: Context, fences: dict[str, bytes], destination: Path, dump
):
    """Prepare a new private bundle; dump(snapshot_id, stream) is trusted host code.

    The stream is exclusive,0600. No shell command, credentials or target address
    comes from the bundle. Failures retain private partial files, without manifest.
    Fences are opaque exported bytes; neither interpreted nor consumed/released.
    External volume access/collection is deliberately not implemented here.
    """
    from sqlalchemy import text

    with _guard():
        if not isinstance(context, Context) or not 1 <= len(fences) <= 100:
            raise SnapshotError("snapshot_inputs_invalid")
        if (
            any(
                not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", name)
                or not isinstance(value, bytes)
                or not 0 < len(value) <= MAX_JSON
                for name, value in fences.items()
            )
            or sum(map(len, fences.values())) > 8 * 1024 * 1024
        ):
            raise SnapshotError("snapshot_fences_invalid")
        # Pin mutable caller containers before I/O; their original bytes survive.
        fences = dict(fences)
        context = Context.model_validate_json(context.model_dump_json())
        _new(destination)
        with engine.connect().execution_options(isolation_level="REPEATABLE READ") as conn:
            conn.execute(text("SET TRANSACTION READ ONLY"))
            conn.execute(text("SET LOCAL timezone='UTC'"))
            conn.execute(text("SET LOCAL statement_timeout='15s'"))
            conn.execute(text("SET LOCAL row_security=off"))
            if int(conn.scalar(text("SHOW server_version_num"))) // 10000 != 17:
                raise SnapshotError("snapshot_postgres_version")
            schema = conn.scalar(text("SELECT current_schema()"))
            if schema != context.database_schema:
                raise SnapshotError("snapshot_database_schema_mismatch")
            snapshot_id = conn.scalar(text("SELECT pg_export_snapshot()"))
            bundle = persisted_review.collect(
                engine, context.identity, context.descriptor_sha256, snapshot_id=snapshot_id
            )
            if bundle["environment_version"] != context.environment_version:
                raise SnapshotError("snapshot_environment_mismatch")
            identity, expected = persisted_review.expected_proofs(bundle, digest(bundle))
            journal_review, journal_bytes = continuity.capture(journal, identity, expected)
            inventory = backup.inventory(lambda sql: conn.execute(text(sql)).scalars(), schema)
            if inventory["migration"] != [context.schema_revision]:
                raise SnapshotError("snapshot_schema_mismatch")
            dump_path = destination / "database.dump"
            fd = os.open(dump_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                dump(snapshot_id, stream)
                stream.flush()
                os.fsync(stream.fileno())
            dump_bytes = _read(dump_path, MAX_DUMP)
            if not dump_bytes.startswith(b"PGDMP"):
                raise SnapshotError("snapshot_dump_invalid")
            # Detect drift over the export, not just at its beginning. A native
            # coordinator must additionally exclude external consumers throughout.
            after = persisted_review.collect(engine, identity, context.descriptor_sha256)
            if _stable_proofs(after) != _stable_proofs(bundle) or continuity.capture(
                journal, identity, expected
            ) != (
                journal_review,
                journal_bytes,
            ):
                raise SnapshotError("snapshot_source_changed")
            with engine.connect().execution_options(isolation_level="REPEATABLE READ") as fresh:
                fresh.execute(text("SET TRANSACTION READ ONLY"))
                fresh.execute(text("SET LOCAL timezone='UTC'"))
                fresh.execute(text("SET LOCAL statement_timeout='15s'"))
                fresh.execute(text("SET LOCAL row_security=off"))
                backup.compare(
                    inventory,
                    backup.inventory(lambda sql: fresh.execute(text(sql)).scalars(), schema),
                )
        _new(destination / "journal")
        _new(destination / "fences")
        artifacts = {"database.dump": dump_bytes}
        for name, data in journal_bytes.items():
            artifacts["journal/" + name] = data
        for name, data in fences.items():
            artifacts["fences/" + name + ".json"] = data
        for name, value in {
            "context.json": context.model_dump(mode="json"),
            "inventory.json": inventory,
            "proofs.json": bundle,
            "journal-review.json": journal_review,
        }.items():
            artifacts[name] = json.dumps(value, sort_keys=True, allow_nan=False).encode()
        for name, data in artifacts.items():
            if name != "database.dump":
                vault.write_private(destination / name, data)
        for name, data in artifacts.items():
            if _read(destination / name, max(len(data), 1)) != data:
                raise SnapshotError("snapshot_file_changed")
        manifest = {
            "format": FORMAT,
            "id": uuid4().hex,
            "created_at": datetime.now(UTC).isoformat(),
            "status": "data_snapshot_created_not_restored",
            "context_sha256": digest(context.model_dump(mode="json")),
            "inventory_sha256": digest(inventory),
            "proofs_sha256": digest(bundle),
            "files": {
                name: {"bytes": len(data), "sha256": _hash(data)}
                for name, data in artifacts.items()
            },
            "physical_binding_verified": False,
            "host_fences_complete_verified": False,
            "external_quiescence_verified": False,
            "operational_snapshot_verified": False,
            "restore_verified": False,
            "activation_permitted": False,
            "normal_operation_permitted": False,
        }
        # Last durable publication; failures before this point are partial copies.
        vault.write_json(destination / "manifest.json", manifest)
        return manifest


def inspect(folder: Path, expected_sha256: str):
    """Read-only validation against an independently retained manifest hash.

    A hash pins bytes; it does not authenticate the host, dump writer or origin.
    Database dump contents still require a separate quarantined restore (#65).
    """
    with _guard():
        _directory(folder)
        manifest = _json(_read(folder / "manifest.json", MAX_JSON))
        flags = {
            "physical_binding_verified",
            "host_fences_complete_verified",
            "external_quiescence_verified",
            "operational_snapshot_verified",
            "restore_verified",
            "activation_permitted",
            "normal_operation_permitted",
        }
        if (
            not isinstance(expected_sha256, str)
            or not re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
            or digest(manifest) != expected_sha256
            or set(manifest)
            != {
                "format",
                "id",
                "created_at",
                "status",
                "context_sha256",
                "inventory_sha256",
                "proofs_sha256",
                "files",
                *flags,
            }
            or manifest["format"] != FORMAT
            or manifest["status"] != "data_snapshot_created_not_restored"
            or any(manifest[name] is not False for name in flags)
            or UUID(hex=manifest["id"]).hex != manifest["id"]
            or datetime.fromisoformat(manifest["created_at"]).utcoffset() is None
        ):
            raise SnapshotError("snapshot_manifest_invalid")
        fixed = {
            "database.dump",
            "context.json",
            "inventory.json",
            "proofs.json",
            "journal-review.json",
        }
        files = manifest["files"]
        journal_files = {
            name.removeprefix("journal/") for name in files if name.startswith("journal/")
        }
        fence_files = {
            name for name in files if re.fullmatch(r"fences/[a-z0-9][a-z0-9_-]{0,63}\.json", name)
        }
        if (
            not {"instance.lock", "journal.sqlite3"} <= journal_files <= continuity.FILES.keys()
            or not 1 <= len(fence_files) <= 100
            or set(files) != fixed | {"journal/" + name for name in journal_files} | fence_files
            or set(os.listdir(folder)) != fixed | {"journal", "fences", "manifest.json"}
        ):
            raise SnapshotError("snapshot_files_invalid")
        for subdir, expected in (
            ("journal", journal_files),
            ("fences", {Path(n).name for n in fence_files}),
        ):
            _directory(folder / subdir)
            if set(os.listdir(folder / subdir)) != expected:
                raise SnapshotError("snapshot_files_invalid")
        contents = {}
        for name, fingerprint in files.items():
            maximum = (
                MAX_DUMP
                if name == "database.dump"
                else (
                    continuity.FILES[Path(name).name] if name.startswith("journal/") else MAX_JSON
                )
            )
            data = _read(folder / name, maximum)
            if fingerprint != {"bytes": len(data), "sha256": _hash(data)}:
                raise SnapshotError("snapshot_file_integrity")
            contents[name] = data
        if sum(len(contents[name]) for name in fence_files) > 8 * 1024 * 1024:
            raise SnapshotError("snapshot_fences_invalid")
        if not contents["database.dump"].startswith(b"PGDMP"):
            raise SnapshotError("snapshot_dump_invalid")
        context = Context.model_validate_json(contents["context.json"])
        inventory = _json(contents["inventory.json"])
        bundle = _json(contents["proofs.json"])
        identity, expected = persisted_review.expected_proofs(bundle, manifest["proofs_sha256"])
        if (
            digest(context.model_dump(mode="json")) != manifest["context_sha256"]
            or digest(inventory) != manifest["inventory_sha256"]
            or inventory["format"] != backup.INVENTORY_FORMAT
            or inventory["migration"] != [context.schema_revision]
            or identity != context.identity
            or bundle["old_descriptor_sha256"] != context.descriptor_sha256
            or bundle["environment_version"] != context.environment_version
            or continuity.review(folder / "journal", identity, expected)
            != _json(contents["journal-review.json"])
        ):
            raise SnapshotError("snapshot_context_mismatch")
        return manifest
