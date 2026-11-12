"""Fixed read-only collector probe for the specifically authorized Wazuh TLS assay.

Credentials arrive only on stdin. No Docker/lifecycle operations or free destinations.
Run only in the reviewed reader container; unit tests inject a provider and TLS peer.
"""

import hashlib
import json
import re
import socket
import ssl
import sys
import time

import httpx
from aegis.integrations.wazuh import WazuhIndexerProvider

IP = "192.168.253.18"
HOSTNAME = "wazuh.indexer"
URL = "https://wazuh.indexer:9200"
CA = "/run/secrets/wazuh_ca"
PATHS = (
    "/",
    "/_plugins/_security/authinfo",
    "/_plugins/_security/api/permissionsinfo",
    "/wazuh-alerts-4.x-*/_search?size=0&track_total_hits=false",
    "/.opendistro_security/_search?size=0",
)


def peer_identity() -> dict:
    context = ssl.create_default_context(cafile=CA)
    with socket.create_connection((IP, 9200), timeout=3) as stream:
        with context.wrap_socket(stream, server_hostname=HOSTNAME) as secure:
            return {
                "certificate_der_sha256": hashlib.sha256(
                    secure.getpeercert(binary_form=True)
                ).hexdigest(),
                "tls_version": secure.version(),
            }


def probe(payload: dict, *, provider_factory=None, peer=None) -> dict:
    if (
        not isinstance(payload, dict)
        or set(payload) != {"username", "password", "expected_certificate_der_sha256"}
        or payload["username"] != "aegis_reader"
        or not isinstance(payload["password"], str)
        or not 1 <= len(payload["password"]) <= 256
        or not isinstance(payload["expected_certificate_der_sha256"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", payload["expected_certificate_der_sha256"])
    ):
        raise ValueError("invalid_probe_scope")
    observed = (peer or peer_identity)()
    if observed.get("certificate_der_sha256") != payload[
        "expected_certificate_der_sha256"
    ] or observed.get("tls_version") not in {"TLSv1.2", "TLSv1.3"}:
        raise ValueError("tls_peer_identity_mismatch")
    provider = (provider_factory or WazuhIndexerProvider)(
        URL,
        payload["username"],
        payload["password"],
        IP,
        ca_bundle=CA,
        budget_end=time.monotonic() + 20,
    )
    try:
        version = provider._request("GET", PATHS[0])
        if not isinstance(version.get("version"), dict) or not isinstance(
            version["version"].get("number"), str
        ):
            raise ValueError("indexer_version_unavailable")
        principal = provider._request("GET", PATHS[1])
        if principal.get("user_name") != "aegis_reader" or principal.get("roles") != [
            "aegis_reader"
        ]:
            raise ValueError("reader_principal_or_role_mismatch")
        permissions = provider._request("GET", PATHS[2])
        if permissions.get("has_api_access") is not False:
            raise ValueError("reader_security_api_access_not_denied")
        alerts = provider._request("GET", PATHS[3])
        shards = alerts.get("_shards", {})
        if (
            alerts.get("timed_out") is not False
            or not isinstance(shards, dict)
            or type(shards.get("total")) is not int
            or shards["total"] <= 0
            or type(shards.get("failed")) is not int
            or type(shards.get("successful")) is not int
            or shards.get("failed") != 0
            or shards.get("successful") != shards["total"]
            or not isinstance(alerts.get("hits"), dict)
            or alerts["hits"].get("hits") != []
        ):
            raise ValueError("alert_index_read_incomplete")
        try:
            provider._request("GET", PATHS[4])
        except httpx.HTTPStatusError as error:
            if error.response.status_code != 403:
                raise ValueError("security_index_denial_unconfirmed") from None
        else:
            raise ValueError("security_index_read_was_not_denied")
        return {
            "format": "aegis-wazuh-tls-probe/1",
            "status": "tls_identity_and_read_acl_verified",
            "tls_version": observed["tls_version"],
            "certificate_der_sha256": observed["certificate_der_sha256"],
            "principal_verified": True,
            "alerts_read_verified": True,
            "security_api_access_denied": True,
            "security_index_read_denied": True,
            "write_request_performed": False,
            "write_acl_verified": False,
            "marker_executed": False,
            "normal_operation_permitted": False,
        }
    finally:
        provider.close()


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError("probe_input_too_large")
        result = probe(json.loads(raw, object_pairs_hook=unique_fields))
    except (OSError, ValueError, TypeError, KeyError, TimeoutError, httpx.HTTPError):
        print(
            json.dumps(
                {
                    "status": "inconclusive",
                    "error": "Verificação TLS/identidade/ACL não confirmada; preservar evidências e executar cleanup.",
                }
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_probe_field")
        result[key] = value
    return result


if __name__ == "__main__":
    raise SystemExit(main())
