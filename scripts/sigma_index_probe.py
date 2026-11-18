"""Two-phase, fixed #89 reader. No lifecycle or document-write operations.

Run only in the approved isolated reader. Credentials arrive by one stdin line;
reviewed version snapshots/metadata approval arrive as read-only mounted files.
"""

import json
import os
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from aegis.config import settings
from aegis.domain.validation import digest
from aegis.integrations import sigma_conversion, sigma_validation
from aegis.integrations.sigma_index import IndexProfile
from aegis.integrations.wazuh import WazuhIndexerProvider
from wazuh_schema_probe import REFERENCE, AuditedReader, wait_for_peer
from wazuh_tls_probe import CA, IP, URL, peer_identity, unique_fields

INDEX = REFERENCE["index"]
PATHS = {name: f"/{INDEX}/_{name}" for name in ("mapping", "settings", "alias")}


def credentials(payload):
    if (
        not isinstance(payload, dict)
        or set(payload) != {"username", "password", "expected_certificate_der_sha256"}
        or payload["username"] != "aegis_reader"
        or not isinstance(payload["password"], str)
        or not 1 <= len(payload["password"]) <= 256
        or not isinstance(payload["expected_certificate_der_sha256"], str)
        or len(payload["expected_certificate_der_sha256"]) != 64
    ):
        raise ValueError("invalid_credentials_scope")


def metadata(payload, *, factory=WazuhIndexerProvider, peer=wait_for_peer):
    credentials(payload)
    identity = peer()
    if identity["certificate_der_sha256"] != payload["expected_certificate_der_sha256"]:
        raise ValueError("tls_peer_mismatch")
    reader = factory(
        URL,
        payload["username"],
        payload["password"],
        IP,
        ca_bundle=CA,
        budget_end=time.monotonic() + 20,
    )
    try:
        version = reader._request("GET", "/")
        principal = reader._request("GET", "/_plugins/_security/authinfo")
        permissions = reader._request("GET", "/_plugins/_security/api/permissionsinfo")
        if principal.get("user_name") != "aegis_reader" or principal.get("roles") != [
            "aegis_reader"
        ]:
            raise ValueError("reader_role_mismatch")
        if permissions.get("has_api_access") is not False:
            raise ValueError("security_api_access_not_denied")
        try:
            reader._request("GET", "/.opendistro_security/_search?size=0")
        except httpx.HTTPStatusError as error:
            if error.response.status_code != 403:
                raise ValueError("security_index_denial_unconfirmed") from None
        else:
            raise ValueError("security_index_read_not_denied")
        values = {key: reader._request("GET", path) for key, path in PATHS.items()}
        return {
            "status": "metadata_collected",
            "tls": identity,
            "version": version["version"],
            "principal_verified": True,
            "security_api_denied": True,
            "security_index_denied": True,
            "write_acl_verified": False,
            **values,
        }
    finally:
        reader.close()


def queries(
    payload, versions, approval, *, validate=sigma_validation.validate_query, peer=peer_identity
):
    credentials(payload)
    if set(versions) != {"positive", "negative"}:
        raise ValueError("two_reviewed_versions_required")
    profile = IndexProfile.model_validate(approval["index_profile"])
    if profile.index != INDEX or datetime.fromisoformat(approval["expires_at"]) <= datetime.now(
        UTC
    ):
        raise ValueError("metadata_approval_invalid")
    identity = peer()
    if identity["certificate_der_sha256"] != payload["expected_certificate_der_sha256"]:
        raise ValueError("tls_peer_mismatch")
    cfg = settings()
    cfg.wazuh_url, cfg.wazuh_allowed_ip, cfg.wazuh_ca_bundle = URL, IP, CA
    cfg.wazuh_username, cfg.wazuh_password = payload["username"], payload["password"]
    cfg.sigma_validation_scope = Path("/run/sigma/scope.json")
    audit = []
    original = sigma_validation.configured_provider

    def factory(**kwargs):
        return AuditedReader(
            URL, payload["username"], payload["password"], IP, ca_bundle=CA, audit=audit, **kwargs
        )

    sigma_validation.configured_provider = factory
    results = {}
    try:
        for name in ("positive", "negative"):
            saved = versions[name]
            artifact = sigma_conversion.convert(saved["content"])
            if (
                artifact["query_sha256"] != saved["query_sha256"]
                or digest(saved["content"]) != saved["sha256"]
            ):
                raise ValueError("reviewed_version_drift")
            instant = datetime.fromisoformat(REFERENCE["timestamp"])
            scope = sigma_validation.Scope(
                index_profile=profile,
                connection_sha256=sigma_validation.connection_hash(),
                rule_id=saved["rule_id"],
                rule_version_id=saved["id"],
                content_sha256=saved["sha256"],
                contract_sha256=artifact["contract"]["sha256"],
                query_sha256=saved["query_sha256"],
                agent_id="001",
                start=instant - timedelta(seconds=5),
                end=instant + timedelta(seconds=5),
                approved_at=approval["approved_at"],
                expires_at=approval["expires_at"],
            )
            with cfg.sigma_validation_scope.open("w") as stream:
                os.chmod(cfg.sigma_validation_scope, 0o600)
                stream.write(scope.model_dump_json())
            result = validate(
                saved["content"],
                saved["rule_id"],
                saved["id"],
                digest(scope.model_dump(mode="json")),
            )
            results[name] = result
            if not result["complete"] or not result["cleanup_confirmed"]:
                raise ValueError("query_incomplete")
            if name == "positive":
                if len(result["hits"]) != 1 or digest(result["hits"][0]) != REFERENCE["raw_sha256"]:
                    raise ValueError("original_alert_changed")
            elif result["hits"] or result["total"] != 0:
                raise ValueError("negative_query_not_empty")
        return {
            "status": "sigma_native_query_verified",
            "tls": identity,
            "reference": REFERENCE,
            "results": results,
            "requests": audit,
            "new_markers": 0,
            "new_runs": 0,
        }
    finally:
        sigma_validation.configured_provider = original
        cfg.sigma_validation_scope.unlink(missing_ok=True)


def main():
    try:
        raw = sys.stdin.buffer.readline(4097)
        if len(raw) > 4096:
            raise ValueError("payload_too_large")
        payload = json.loads(raw, object_pairs_hook=unique_fields)
        if sys.argv[1:] == ["metadata"]:
            result = metadata(payload)
        elif sys.argv[1:] == ["queries"]:
            versions = json.loads(Path("/review/rule-versions.json").read_text())
            approval = json.loads(Path("/review/metadata-approval.json").read_text())
            result = queries(payload, versions, approval)
        else:
            raise ValueError("invalid_phase")
    except Exception as error:
        result = {"status": "inconclusive", "error_type": type(error).__name__}
        if isinstance(error, httpx.HTTPStatusError):
            result.update(http_status=error.response.status_code, path=error.request.url.path)
        print(json.dumps(result))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
