"""Create dedicated local PKI/config. Does not start containers or execute a test."""

import argparse
import json
import os
import subprocess
from pathlib import Path
from uuid import UUID, uuid4

from aegis.lab_runner.network_profile import LEGACY_LINUX_IP, LINUX_RUNNER_IP, WAZUH_RUNNER_IP
from aegis.lab_runner.wazuh_network_profile import LEGACY_RUNNER_IP


def openssl(*args: str):
    subprocess.run(
        ["/usr/bin/openssl", *args],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )


def initialize(
    output: Path, *, server_ip: str = LINUX_RUNNER_IP, identifiers: dict[str, str] | None = None
) -> Path:
    if server_ip not in {LEGACY_LINUX_IP, LINUX_RUNNER_IP, WAZUH_RUNNER_IP, LEGACY_RUNNER_IP}:
        raise ValueError("Endereço fora dos perfis de laboratório revisados.")
    names = ("runner_id", "laboratory_id", "asset_id")
    if identifiers is None:
        identifiers = {name: str(uuid4()) for name in names}
    elif set(identifiers) != set(names):
        raise ValueError("Forneça exatamente as três identidades existentes.")
    else:
        identifiers = {name: str(UUID(identifiers[name])) for name in names}
    output = output.resolve()
    output.mkdir(
        mode=0o700, parents=True, exist_ok=False
    )  # Never rotate identity/journal implicitly.
    previous = os.umask(0o077)
    try:
        for purpose in ("server", "client"):
            root = output / f"{purpose}-ca"
            openssl(
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                str(root.with_suffix(".key")),
                "-out",
                str(root.with_suffix(".crt")),
                "-days",
                "7",
                "-subj",
                f"/CN=AEGIS {purpose} CA {uuid4()}",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                "subjectKeyIdentifier=hash",
                "-addext",
                "authorityKeyIdentifier=keyid:always",
            )
            leaf = output / f"runner-{purpose}"
            openssl(
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                str(leaf.with_suffix(".key")),
                "-out",
                str(leaf.with_suffix(".csr")),
                "-subj",
                f"/CN=aegis-{purpose}-{identifiers['runner_id']}",
            )
            extensions = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            extensions += "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
            extensions += (
                f"extendedKeyUsage=serverAuth\nsubjectAltName=IP:{server_ip}\n"
                if purpose == "server"
                else "extendedKeyUsage=clientAuth\n"
            )
            config = output / f"{purpose}-extensions.cnf"
            config.write_text(extensions)
            openssl(
                "x509",
                "-req",
                "-in",
                str(leaf.with_suffix(".csr")),
                "-CA",
                str(root.with_suffix(".crt")),
                "-CAkey",
                str(root.with_suffix(".key")),
                "-CAcreateserial",
                "-out",
                str(leaf.with_suffix(".crt")),
                "-days",
                "2",
                "-sha256",
                "-extfile",
                str(config),
            )
            # Parent directory 0700 protects host paths. Individual Docker secrets need read by UID10001.
            leaf.with_suffix(".key").chmod(0o444)
            leaf.with_suffix(".crt").chmod(0o444)
            root.with_suffix(".crt").chmod(0o444)
        connection = {
            **identifiers,
            "url": f"https://{server_ip}:8443",
            "server_ca": "/run/secrets/controller_server_ca",
            "client_cert": "/run/secrets/controller_client_cert",
            "client_key": "/run/secrets/controller_client_key",
        }
        (output / "connection.json").write_text(json.dumps(connection, indent=2))
        (output / "connection.json").chmod(0o444)
        env = f"AEGIS_LAB_CONFIG_DIR={output}\n"
        env += "".join(
            f"AEGIS_RUNNER_{name.upper()}={value}\n" for name, value in identifiers.items()
        )
        (output / "ids.env").write_text(env)
    finally:
        os.umask(previous)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".local/linux-lab"))
    location = initialize(parser.parse_args().output)
    print(
        f"PKI/config local criada em {location}. Nenhum laboratório foi iniciado; não publicar chaves."
    )
