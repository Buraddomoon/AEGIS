"""Passive marker observation for a future reviewed Wazuh lab. No process execution."""

import argparse
import hashlib
import json
import os
import stat
import time
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from aegis.marker_log import ObservationLog


def observe_once(
    workspace: Path, laboratory_id: UUID, asset_id: UUID, seen: set[str]
) -> list[dict]:
    if len(seen) >= 10000:
        raise ValueError("Limite de observações atingido; preservar registros e revisar operação.")
    root = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    records = []
    try:
        root_meta = os.fstat(root)
        if stat.S_IMODE(root_meta.st_mode) & 0o077:
            raise ValueError("Workspace do observador precisa usar modo 0700.")
        owner, device = root_meta.st_uid, root_meta.st_dev
        with os.scandir(root) as entries:
            for count, entry in enumerate(entries):
                if count >= 64:
                    raise ValueError("Workspace excede limite de entradas do observador.")
                try:
                    identifier = UUID(entry.name)
                    job = str(identifier)
                except ValueError:
                    continue
                if identifier.hex != entry.name or job in seen:
                    continue
                directory = marker_file = None
                try:
                    directory = os.open(
                        entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root
                    )
                    metadata = os.fstat(directory)
                    if (
                        metadata.st_uid != owner
                        or metadata.st_dev != device
                        or stat.S_IMODE(metadata.st_mode) & 0o077
                    ):
                        continue
                    marker_file = os.open(
                        "proof.marker",
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=directory,
                    )
                    metadata = os.fstat(marker_file)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_uid != owner
                        or metadata.st_dev != device
                        or metadata.st_nlink != 1
                        or metadata.st_size != 43
                    ):
                        continue
                    content = os.read(marker_file, 44)
                    marker = content.decode("ascii").removesuffix("\n")
                    if (
                        len(content) != 43
                        or marker != "aegis-" + str(UUID(marker.removeprefix("aegis-")))
                        or not content.endswith(b"\n")
                    ):
                        continue
                    records.append(
                        {
                            "aegis": {
                                "schema": "aegis-json/1",
                                "observation": "marker_file_read",
                                "laboratory_id": str(laboratory_id),
                                "asset_id": str(asset_id),
                                "execution_id": job,
                                "marker": marker,
                                "behavior": "temporary-marker",
                                "observed_at": datetime.now(UTC).isoformat(),
                                "artifact_bytes": len(content),
                                "artifact_sha256": hashlib.sha256(content).hexdigest(),
                            }
                        }
                    )
                    seen.add(job)
                except (OSError, ValueError, UnicodeError):
                    continue  # Deletion races, links and malformed files are never observations.
                finally:
                    if marker_file is not None:
                        os.close(marker_file)
                    if directory is not None:
                        os.close(directory)
    finally:
        os.close(root)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--laboratory-id", type=UUID, required=True)
    parser.add_argument("--asset-id", type=UUID, required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--log-directory", type=Path)
    args = parser.parse_args()
    sink = (
        ObservationLog(args.log_directory, args.laboratory_id, args.asset_id)
        if args.log_directory
        else nullcontext(None)
    )
    with sink as log:
        seen: set[str] = set(log.seen) if log else set()
        while True:
            for record in observe_once(args.workspace, args.laboratory_id, args.asset_id, seen):
                if not log or log.append(record):
                    print(json.dumps(record, ensure_ascii=False, separators=(",", ":")), flush=True)
            if args.once:
                return
            time.sleep(0.25)


if __name__ == "__main__":
    main()
