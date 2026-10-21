"""Generate private configuration only. No downloads, Docker calls or marker execution."""

import argparse
import json
import os
import re
import secrets
from pathlib import Path

from init_linux_lab import initialize, openssl


def prepare(output: Path):
    output = output.resolve()
    if not re.fullmatch(r"[A-Za-z0-9/._-]+", str(output)):
        raise ValueError("Use diretório local sem espaços/interpolação no arquivo Compose env.")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    previous = os.umask(0o077)
    try:
        runner = initialize(output / "runner", server_ip="172.30.89.2")
        connection = json.loads((runner / "connection.json").read_text())
        pki = output / "pki"
        pki.mkdir(mode=0o700)
        openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(pki / "ca-key.pem"),
            "-out",
            str(pki / "root-ca.pem"),
            "-days",
            "7",
            "-subj",
            "/CN=AEGIS isolated Wazuh CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
        for name, eku in [("indexer", "serverAuth,clientAuth"), ("filebeat", "clientAuth")]:
            common_name = "wazuh.indexer" if name == "indexer" else "aegis-filebeat"
            openssl(
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(pki / f"{name}-key.pem"),
                "-out",
                str(pki / f"{name}.csr"),
                "-subj",
                f"/CN={common_name}/OU=AEGIS/O=AEGIS Lab",
            )
            config = pki / f"{name}.cnf"
            config.write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                f"extendedKeyUsage={eku}\n"
                + ("subjectAltName=DNS:wazuh.indexer,IP:172.30.90.2\n" if name == "indexer" else "")
            )
            openssl(
                "x509",
                "-req",
                "-in",
                str(pki / f"{name}.csr"),
                "-CA",
                str(pki / "root-ca.pem"),
                "-CAkey",
                str(pki / "ca-key.pem"),
                "-CAcreateserial",
                "-out",
                str(pki / f"{name}.pem"),
                "-days",
                "2",
                "-sha256",
                "-extfile",
                str(config),
            )
            (pki / f"{name}-key.pem").chmod(0o444)
            (pki / f"{name}.pem").chmod(0o444)
        (pki / "root-ca.pem").chmod(0o444)
        # A pre-provisioned identity belongs only to this new isolated manager.
        # Readiness must confirm it active before campaign approval.
        (output / "client.keys").write_text(f"001 aegis-marker any {secrets.token_hex(32)}\n")
        (output / "client.keys").chmod(0o444)
        credentials = {
            name: secrets.token_urlsafe(32) for name in ("admin", "aegis_reader", "aegis_ingest")
        }
        (output / "indexer-passwords.json").write_text(json.dumps(credentials))
        policy = {
            "laboratory_id": connection["laboratory_id"],
            "asset_id": connection["asset_id"],
            "agent_id": "001",
            "expected_rule": "100200",
            "schema_id": "aegis-json/1",
            "alerts_index": "wazuh-alerts-4.x-*",
            "archives_index": None,
            "clock_skew_seconds": 5,
            "ingestion_window_seconds": 60,
            "ingestion_wait_seconds": 60,
            "poll_interval_seconds": 2,
            "request_timeout_seconds": 3,
        }
        (output / "collection.json").write_text(json.dumps(policy, indent=2))
        (output / "collection.json").chmod(0o444)
        env = {
            "AEGIS_LAB_CONFIG_DIR": str(runner),
            "AEGIS_WAZUH_CONFIG_DIR": str(output),
            **{
                f"AEGIS_RUNNER_{name.upper()}": connection[name]
                for name in ("runner_id", "laboratory_id", "asset_id")
            },
            "POSTGRES_PASSWORD": secrets.token_hex(32),
            "APP_DB_PASSWORD": secrets.token_hex(32),
            "REDIS_PASSWORD": secrets.token_hex(32),
            "WAZUH_URL": "https://wazuh.indexer:9200",
            "WAZUH_ALLOWED_IP": "172.30.90.2",
            "WAZUH_USERNAME": "aegis_reader",
            "WAZUH_PASSWORD": credentials["aegis_reader"],
            "WAZUH_CA_BUNDLE": "/run/secrets/wazuh_ca",
            "WAZUH_COLLECTION_CONFIG": "/run/secrets/wazuh_collection",
            "AEGIS_INDEXER_INGEST_PASSWORD": credentials["aegis_ingest"],
            "AEGIS_WAZUH_API_PASSWORD": "Aa1!" + secrets.token_hex(24),
        }
        manifest = json.loads(
            (Path(__file__).resolve().parents[1] / "labs/wazuh/images.json").read_text()
        )
        env.update(
            {f"AEGIS_WAZUH_{name.upper()}_IMAGE": ref for name, ref in manifest["images"].items()}
        )
        (output / "lab.env").write_text("".join(f"{key}={value}\n" for key, value in env.items()))
    finally:
        os.umask(previous)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".local/wazuh-lab"))
    prepare(parser.parse_args().output)
    print(
        "Configuração privada criada. Hashes Indexer e validação real pendentes; nenhum serviço iniciado."
    )
