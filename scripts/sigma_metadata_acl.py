"""Explicitly authorized #89 maintenance of one role, with guarded reversal.

Not an application API. Run only in the isolated maintenance container. The
operator must durably retain snapshot output before invoking grant or restore.
"""

import copy
import json
import sys
import time

import httpx
from aegis.domain.validation import digest
from aegis.integrations.wazuh import WazuhIndexerProvider
from wazuh_schema_probe import wait_for_peer
from wazuh_tls_probe import CA, IP, URL, unique_fields

ROLE = "aegis_reader"
PATH = "/_plugins/_security/api/roles/" + ROLE
ACTIONS = [
    "indices:admin/mappings/get",
    "indices:monitor/settings/get",
    "indices:admin/aliases/get",
]
ENTRY = {
    "index_patterns": ["wazuh-alerts-4.x-2026.11.16"],
    "allowed_actions": ACTIONS,
    "dls": "",
    "fls": [],
    "masked_fields": [],
}


def baseline(value):
    if not isinstance(value, dict) or any(
        value.get(k, False) is not False for k in ("reserved", "hidden", "static")
    ):
        raise ValueError("role_not_mutable")
    if set(value.get("cluster_permissions", [])) != {
        "cluster:monitor/main",
        "indices:data/read/scroll*",
    }:
        raise ValueError("unexpected_cluster_permissions")
    if value.get("tenant_permissions"):
        raise ValueError("unexpected_tenant_permissions")
    entries = value.get("index_permissions")
    if not isinstance(entries, list) or len(entries) != 1:
        raise ValueError("unexpected_index_permissions")
    entry = entries[0]
    if (
        set(entry) - {"index_patterns", "allowed_actions", "dls", "fls", "masked_fields"}
        or entry.get("index_patterns") != ["wazuh-alerts-4.x-*"]
        or entry.get("allowed_actions") != ["read"]
        or entry.get("dls", "") != ""
        or entry.get("fls", []) != []
        or entry.get("masked_fields", []) != []
    ):
        raise ValueError("unexpected_reader_baseline")
    return copy.deepcopy(value)


def canonical(value):
    result = copy.deepcopy(value)
    result["cluster_permissions"] = sorted(result["cluster_permissions"])
    for entry in result["index_permissions"]:
        entry["allowed_actions"] = sorted(entry["allowed_actions"])
        for name, empty in (("dls", ""), ("fls", []), ("masked_fields", [])):
            entry.setdefault(name, empty)
    return result


def temporary(before):
    result = baseline(before)
    result["index_permissions"].append(copy.deepcopy(ENTRY))
    return result


def maintain(payload, phase, *, factory=WazuhIndexerProvider, peer=wait_for_peer):
    if (
        not isinstance(payload, dict)
        or set(payload) != {"username", "password", "expected_certificate_der_sha256", "snapshot"}
        or payload["username"] != "admin"
        or not isinstance(payload["password"], str)
        or not 1 <= len(payload["password"]) <= 256
        or phase not in {"snapshot", "grant", "restore"}
    ):
        raise ValueError("invalid_maintenance_scope")
    identity = peer()
    if identity["certificate_der_sha256"] != payload["expected_certificate_der_sha256"]:
        raise ValueError("tls_peer_mismatch")
    if phase != "snapshot":
        before = baseline(payload["snapshot"])
        after = temporary(before)
    reader = factory(
        URL, "admin", payload["password"], IP, ca_bundle=CA, budget_end=time.monotonic() + 20
    )

    def read():
        value = reader._request("GET", PATH)
        if set(value) != {ROLE}:
            raise ValueError("unexpected_role_response")
        return value[ROLE]

    try:
        principal = reader._request("GET", "/_plugins/_security/authinfo")
        if principal.get("user_name") != "admin" or principal.get("roles") != ["aegis_admin"]:
            raise ValueError("maintenance_principal_mismatch")
        current = read()
        if phase == "snapshot":
            return {
                "status": "role_snapshot",
                "role": baseline(current),
                "role_sha256": digest(canonical(current)),
                "tls": identity,
            }
        if phase == "grant":
            if canonical(current) != canonical(before):
                raise ValueError("role_drift_before_grant")
            patch = [
                {"op": "test", "path": "/index_permissions", "value": current["index_permissions"]},
                {"op": "add", "path": "/index_permissions/-", "value": ENTRY},
            ]
            reader._request("PATCH", PATH, patch)
            observed = read()
            if canonical(observed) != canonical(after):
                raise ValueError("temporary_role_not_verified")
            return {
                "status": "temporary_metadata_grant_verified",
                "before_sha256": digest(canonical(before)),
                "after_sha256": digest(canonical(observed)),
                "role": observed,
            }
        if canonical(current) != canonical(before):
            if canonical(current) != canonical(after):
                raise ValueError("role_drift_before_restore")
            patch = [
                {"op": "test", "path": "/index_permissions", "value": current["index_permissions"]},
                {"op": "remove", "path": "/index_permissions/1"},
            ]
            reader._request("PATCH", PATH, patch)
        observed = read()
        if canonical(observed) != canonical(before):
            raise ValueError("role_restore_not_verified")
        return {
            "status": "original_role_restored",
            "role_sha256": digest(canonical(observed)),
            "role": observed,
        }
    finally:
        reader.close()


def main():
    try:
        raw = sys.stdin.buffer.readline(32769)
        if len(raw) > 32768 or len(sys.argv) != 2:
            raise ValueError("invalid_maintenance_input")
        result = maintain(json.loads(raw, object_pairs_hook=unique_fields), sys.argv[1])
    except Exception as error:
        result = {"status": "maintenance_unconfirmed", "error_type": type(error).__name__}
        if isinstance(error, httpx.HTTPStatusError):
            result["http_status"] = error.response.status_code
        print(json.dumps(result))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
