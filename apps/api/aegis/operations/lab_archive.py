"""Private cold-copy archives. Manual extraction; never tar.extract or repair."""

import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path, PurePosixPath

from aegis.domain.validation import digest
from aegis.operations import lab_backup as snapshot
from aegis.operations import vault

MAX_ARCHIVE = 512 * 1024**2
MAX_ENTRIES = 30000
RECORD_PREFIXES = ("linux-", "wazuh-", "pki-", "runner-", "sigma-validation")
RECORD_SUFFIXES = {
    ".json",
    ".jsonl",
    ".env",
    ".crt",
    ".key",
    ".pem",
    ".conf",
    ".yml",
    ".yaml",
    ".lock",
}
CONFIGS = (
    ".env",
    "docker-compose.yml",
    "labs/linux/compose.yml",
    "labs/linux/platform.yml",
    "labs/linux/campaign.yml",
    "labs/wazuh/compose.yml",
    "labs/wazuh/network.yml",
)


def source_path(roots, name):
    label, relative = name.split("/", 1)
    if (
        label not in roots
        or PurePosixPath(relative).is_absolute()
        or ".." in PurePosixPath(relative).parts
    ):
        raise snapshot.SnapshotError("recovery_host_record_path")
    if relative.startswith("__configuration__/"):
        selected = relative.removeprefix("__configuration__/")
        if selected not in CONFIGS:
            raise snapshot.SnapshotError("recovery_host_configuration_path")
        return roots[label].parent / selected
    return roots[label] / relative


def extract(archive: Path, destination: Path):
    """Only regular files/directories, bounded and exclusively created0700/0600.

    Reject links, special files, path escapes, duplicates and sparse/PAX entries.
    A retained cold archive is inert; only a new isolated copy may be started.
    """
    snapshot._directory(destination)
    if any(destination.iterdir()):
        raise snapshot.SnapshotError("recovery_extract_new_directory_required")
    entries, total, seen = {}, 0, set()
    with vault.private_file(archive, maximum=MAX_ARCHIVE) as stream:
        original = snapshot.continuity._signature(os.fstat(stream.fileno()))
        with tarfile.open(fileobj=stream, mode="r:") as source:
            for member in source:
                pure = PurePosixPath(member.name)
                if (
                    pure.is_absolute()
                    or ".." in pure.parts
                    or "\x00" in member.name
                    or "\\" in member.name
                ):
                    raise snapshot.SnapshotError("recovery_archive_path")
                if pure == PurePosixPath(".") and member.isdir():
                    continue
                name = str(pure)
                if (
                    name in seen
                    or member.pax_headers
                    or member.issparse()
                    or not (member.isfile() or member.isdir())
                ):
                    raise snapshot.SnapshotError("recovery_archive_entry")
                seen.add(name)
                total += member.size
                if len(seen) > MAX_ENTRIES or total > MAX_ARCHIVE or member.size < 0:
                    raise snapshot.SnapshotError("recovery_archive_limit")
                target = destination / pure
                for parent in reversed(target.relative_to(destination).parents[:-1]):
                    if parent == PurePosixPath("."):
                        continue
                    path = destination / parent
                    if not path.exists():
                        path.mkdir(mode=0o700)
                    if not path.is_dir() or path.is_symlink():
                        raise snapshot.SnapshotError("recovery_archive_parent")
                if member.isdir():
                    target.mkdir(mode=0o700, exist_ok=True)
                    if not target.is_dir() or target.is_symlink():
                        raise snapshot.SnapshotError("recovery_archive_parent")
                    entries[name] = {"kind": "directory"}
                else:
                    reader = source.extractfile(member)
                    if reader is None:
                        raise snapshot.SnapshotError("recovery_archive_file")
                    fd = os.open(
                        target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                    )
                    hasher, count = hashlib.sha256(), 0
                    with os.fdopen(fd, "wb") as out, reader:
                        while data := reader.read(65536):
                            count += len(data)
                            if count > member.size:
                                raise snapshot.SnapshotError("recovery_archive_file_limit")
                            out.write(data)
                            hasher.update(data)
                        out.flush()
                        os.fsync(out.fileno())
                    if count != member.size:
                        raise snapshot.SnapshotError("recovery_archive_truncated")
                    entries[name] = {"kind": "file", "bytes": count, "sha256": hasher.hexdigest()}
        if snapshot.continuity._signature(os.fstat(stream.fileno())) != original:
            raise snapshot.SnapshotError("recovery_archive_changed")
    vault.sync_directory(destination)
    return {
        "format": "aegis-cold-copy-files/1",
        "entries": entries,
        "bytes": total,
        "sha256": digest(entries),
    }


def record_paths(roots: dict[str, Path]):
    """Inventory selected host custody records, without reading private content.

    Include every JSON/JSONL fence/intent/candidate record and PKI/configuration
    file under the declared roots. Logs, images, wheels and unrelated projects
    are outside this closed custody profile. Links are inventoried, never followed.
    """
    result = {}
    for label, root in sorted(roots.items()):
        if label not in {"primary", "legacy"}:
            raise snapshot.SnapshotError("recovery_host_root")
        vault.no_symlink_parents(root)
        if not root.is_dir():
            raise snapshot.SnapshotError("recovery_host_root_missing")
        configurations = [root.parent / name for name in CONFIGS if (root.parent / name).exists()]
        selected = [
            (p, "__configuration__/" + str(p.relative_to(root.parent))) for p in configurations
        ]
        for top in sorted(root.iterdir()):
            if not top.name.startswith(RECORD_PREFIXES):
                continue
            candidates = [top]
            if top.is_dir() and not top.is_symlink():
                candidates.extend(sorted(top.rglob("*")))
            selected.extend((path, str(path.relative_to(root))) for path in candidates)
        for path, relative_name in selected:
            info = path.lstat()
            relative = str(Path(label) / relative_name)
            if stat.S_ISLNK(info.st_mode):
                result[relative] = {
                    "kind": "link_record",
                    "target": os.readlink(path),
                    "mode": stat.S_IMODE(info.st_mode),
                }
            elif stat.S_ISREG(info.st_mode) and (
                path.suffix in RECORD_SUFFIXES or relative_name.startswith("__configuration__/")
            ):
                if info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_size > 16 * 1024**2:
                    raise snapshot.SnapshotError("recovery_host_file_unsafe")
                result[relative] = {
                    "kind": "file",
                    "bytes": info.st_size,
                    "mode": stat.S_IMODE(info.st_mode),
                    "mtime_ns": info.st_mtime_ns,
                    "ctime_ns": info.st_ctime_ns,
                }
            elif not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
                raise snapshot.SnapshotError("recovery_host_special_file")
    if (
        not result
        or len(result) > MAX_ENTRIES
        or sum(v.get("bytes", 0) for v in result.values()) > MAX_ARCHIVE
    ):
        raise snapshot.SnapshotError("recovery_host_record_limit")
    return result


def capture_records(roots: dict[str, Path], expected: dict, destination: Path):
    if record_paths(roots) != expected:
        raise snapshot.SnapshotError("recovery_host_records_changed")
    snapshot._new(destination)
    inventory = {}
    # A single durable pack avoids thousands of synchronous filesystem metadata
    # updates on a workstation. Members remain inert hash names, never paths to
    # recreate or JSON/configuration to execute. Publish the inventory last.
    fd = os.open(
        destination / "records.tar", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "w+b") as output:
        with tarfile.open(fileobj=output, mode="w|", format=tarfile.USTAR_FORMAT) as writer:
            for name, metadata in expected.items():
                target_name = hashlib.sha256(name.encode()).hexdigest()
                if metadata["kind"] == "link_record":
                    data = json.dumps(metadata, sort_keys=True).encode()
                else:
                    path = source_path(roots, name)
                    vault.no_symlink_parents(path)
                    source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(source_fd, "rb") as stream:
                        before = snapshot.continuity._signature(os.fstat(stream.fileno()))
                        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                            raise snapshot.SnapshotError("recovery_host_file_unsafe")
                        data = stream.read(16 * 1024**2 + 1)
                        if len(data) != metadata[
                            "bytes"
                        ] or before != snapshot.continuity._signature(os.fstat(stream.fileno())):
                            raise snapshot.SnapshotError("recovery_host_file_changed")
                member = tarfile.TarInfo(target_name)
                member.mode, member.size = 0o600, len(data)
                writer.addfile(member, io.BytesIO(data))
                if output.tell() > MAX_ARCHIVE:
                    raise snapshot.SnapshotError("recovery_host_pack_limit")
                inventory[name] = {
                    **metadata,
                    "stored_as": target_name,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
        output.flush()
        os.fsync(output.fileno())
        size = output.tell()
        if size > MAX_ARCHIVE:
            raise snapshot.SnapshotError("recovery_host_pack_limit")
        output.seek(0)
        pack = {"bytes": size, "sha256": hashlib.file_digest(output, "sha256").hexdigest()}
    vault.sync_directory(destination)
    if record_paths(roots) != expected:
        raise snapshot.SnapshotError("recovery_host_records_changed")
    result = {
        "format": "aegis-lab-host-custody/2",
        "pack": pack,
        "files": inventory,
        "inventory_sha256": digest(inventory),
        "links_followed": False,
        "historical_records_executed": False,
    }
    vault.write_json(destination / "inventory.json", result)
    return result


def verify_records(folder: Path, expected_hash: str):
    snapshot._directory(folder)
    inventory = snapshot._json(snapshot._read(folder / "inventory.json", snapshot.MAX_JSON))
    if (
        digest(inventory) != expected_hash
        or inventory["format"] not in {"aegis-lab-host-custody/1", "aegis-lab-host-custody/2"}
        or digest(inventory["files"]) != inventory["inventory_sha256"]
    ):
        raise snapshot.SnapshotError("recovery_host_inventory_integrity")
    names = {v["stored_as"] for v in inventory["files"].values()}
    legacy = inventory["format"] == "aegis-lab-host-custody/1"
    if set(os.listdir(folder)) != ({"inventory.json"} | (names if legacy else {"records.tar"})):
        raise snapshot.SnapshotError("recovery_host_inventory_files")
    for name, item in inventory["files"].items():
        if item["stored_as"] != hashlib.sha256(name.encode()).hexdigest():
            raise snapshot.SnapshotError("recovery_host_inventory_path")
        if legacy:
            content = snapshot._read(folder / item["stored_as"], 16 * 1024**2)
            if hashlib.sha256(content).hexdigest() != item["sha256"]:
                raise snapshot.SnapshotError("recovery_host_inventory_integrity")
    if not legacy:
        _verify_packed_records(folder, inventory)
    return inventory


def _verify_packed_records(folder, inventory):
    expected = {item["stored_as"]: item for item in inventory["files"].values()}
    with vault.private_file(folder / "records.tar", maximum=MAX_ARCHIVE) as stream:
        before = snapshot.continuity._signature(os.fstat(stream.fileno()))
        if inventory["pack"] != {
            "bytes": os.fstat(stream.fileno()).st_size,
            "sha256": hashlib.file_digest(stream, "sha256").hexdigest(),
        }:
            raise snapshot.SnapshotError("recovery_host_inventory_integrity")
        stream.seek(0)
        seen = set()
        with tarfile.open(fileobj=stream, mode="r|") as reader:
            for member in reader:
                if (
                    member.name not in expected
                    or member.name in seen
                    or len(seen) >= MAX_ENTRIES
                    or not member.isfile()
                    or member.pax_headers
                    or member.issparse()
                    or not 0 <= member.size <= 16 * 1024**2
                    or (
                        expected[member.name]["kind"] == "file"
                        and member.size != expected[member.name]["bytes"]
                    )
                ):
                    raise snapshot.SnapshotError("recovery_host_pack_entry")
                seen.add(member.name)
                source = reader.extractfile(member)
                if source is None:
                    raise snapshot.SnapshotError("recovery_host_pack_entry")
                with source:
                    content = source.read(16 * 1024**2 + 1)
                if (
                    len(content) != member.size
                    or hashlib.sha256(content).hexdigest() != expected[member.name]["sha256"]
                ):
                    raise snapshot.SnapshotError("recovery_host_inventory_integrity")
        if seen != set(expected) or any(
            snapshot.continuity._signature(info) != before
            for info in (
                os.fstat(stream.fileno()),
                (folder / "records.tar").stat(follow_symlinks=False),
            )
        ):
            raise snapshot.SnapshotError("recovery_host_inventory_integrity")
