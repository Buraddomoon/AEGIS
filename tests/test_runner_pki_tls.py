"""TLS fixture only: loopback echo, no runner/app/journal or marker execution."""

import runpy
import socket
import ssl
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
pki = runpy.run_path("scripts/runner_pki.py")


@pytest.fixture(scope="module", params=[False, True], ids=["rotation", "network_transition"])
def certificates(tmp_path_factory, request):
    root = tmp_path_factory.mktemp("pki-handshake")
    old = pki["initialize"](
        root / "old", server_ip="172.30.88.2" if request.param else "192.168.253.2"
    )
    initial = pki["inspect"](old)
    new = pki["prepare"](
        old,
        initial["inventory_sha256"],
        root / "candidates",
        migrate_linux_network=request.param,
    )
    candidate = Path(new["candidate_path"])
    assert (
        pki["verify"](old, candidate, new["manifest_sha256"])["status"]
        == "offline_candidate_verified_not_activated"
    )
    return old, candidate


@pytest.mark.parametrize("scenario", ["new_pair", "old_trust", "old_client"])
def test_new_mutual_tls_pair_works_and_old_trust_or_client_fails(certificates, scenario):
    old, new = certificates
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(new / "runner-server.crt", new / "runner-server.key")
    server.load_verify_locations(new / "client-ca.crt")
    server.verify_mode = ssl.CERT_REQUIRED
    client = ssl.create_default_context(
        cafile=str((old if scenario == "old_trust" else new) / "server-ca.crt")
    )
    client.minimum_version = ssl.TLSVersion.TLSv1_2
    credentials = old if scenario == "old_client" else new
    client.load_cert_chain(credentials / "runner-client.crt", credentials / "runner-client.key")
    accepted = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)

    def serve():
        try:
            raw, _ = listener.accept()
            with raw:
                raw.settimeout(3)
                with server.wrap_socket(raw, server_side=True) as secured:
                    accepted.append(secured.getpeercert())
                    if secured.recv(1) == b"?":
                        secured.sendall(b"!")
        except (ssl.SSLError, ConnectionError):
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    address = listener.getsockname()
    thread.start()
    try:

        def exchange():
            with socket.create_connection(address, timeout=3) as raw:
                # TCP always stays on loopback; SAN verification uses the real pinned lab IP.
                hostname = pki["inventory"](new)[0]["connection"]["url"].split("/")[2].split(":")[0]
                with client.wrap_socket(raw, server_hostname=hostname) as secured:
                    secured.sendall(b"?")
                    assert secured.recv(1) == b"!"

        if scenario == "new_pair":
            exchange()
        else:
            with pytest.raises((ssl.SSLError, ConnectionError, AssertionError)):
                exchange()
    finally:
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert bool(accepted) is (scenario == "new_pair")
