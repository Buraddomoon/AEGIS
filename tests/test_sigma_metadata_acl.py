import copy
import json
import sys
from pathlib import Path

import httpx
import pytest
from test_sigma_index import provider_for

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sigma_metadata_acl as acl  # noqa: E402

BEFORE = {
    "reserved": False,
    "hidden": False,
    "cluster_permissions": ["cluster:monitor/main", "indices:data/read/scroll*"],
    "index_permissions": [
        {
            "index_patterns": ["wazuh-alerts-4.x-*"],
            "allowed_actions": ["read"],
            "dls": "",
            "fls": [],
            "masked_fields": [],
        }
    ],
    "tenant_permissions": [],
}
PAYLOAD = {
    "username": "admin",
    "password": "private-maintenance-fixture",
    "expected_certificate_der_sha256": "a" * 64,
    "snapshot": BEFORE,
    "exclusive_scope_sha256": "b" * 64,
}
PEER = {"certificate_der_sha256": "a" * 64, "tls_version": "TLSv1.3"}


class Indexer:
    def __init__(self):
        self.role = copy.deepcopy(BEFORE)
        self.calls = []
        self.lose_patch_reply = False

    def handle(self, request):
        self.calls.append(request)
        if request.url.path == "/_plugins/_security/authinfo":
            assert request.method == "GET"
            return httpx.Response(200, json={"user_name": "admin", "roles": ["aegis_admin"]})
        assert request.url.path == acl.PATH
        if request.method == "GET":
            return httpx.Response(200, json={acl.ROLE: self.role})
        assert request.method == "PATCH"
        patch = json.loads(request.content)
        # The native Security API rejects test, move and copy; do not let a
        # permissive HTTP fixture hide another unsupported native request.
        assert len(patch) == 1 and patch[0]["op"] in {"add", "remove"}
        operation = patch[0]
        if operation["op"] == "add":
            assert operation["path"] == "/index_permissions/-" and operation["value"] == acl.ENTRY
            self.role["index_permissions"].append(operation["value"])
        else:
            assert operation == {"op": "remove", "path": "/index_permissions/1"}
            self.role["index_permissions"].pop(1)
        if self.lose_patch_reply:
            raise httpx.ReadTimeout("private-response-sentinel")
        return httpx.Response(200, json={"status": "OK"})

    def run(self, phase):
        provider = provider_for(self.handle)
        try:
            return acl.maintain(
                PAYLOAD, phase, factory=lambda *a, **kw: provider, peer=lambda: PEER
            )
        finally:
            assert provider.closed


def test_exact_grant_and_restore_only_touch_one_role_and_three_read_actions():
    indexer = Indexer()
    snapshot = indexer.run("snapshot")
    assert snapshot["role"] == BEFORE
    grant = indexer.run("grant")
    assert grant["status"] == "temporary_metadata_grant_verified"
    assert indexer.role == acl.temporary(BEFORE)
    restored = indexer.run("restore")
    assert restored["role"] == BEFORE and indexer.role == BEFORE
    assert restored["role_sha256"] == snapshot["role_sha256"]
    assert len([r for r in indexer.calls if r.method == "PATCH"]) == 2
    assert PAYLOAD["password"] not in json.dumps([snapshot, grant, restored])


def test_lost_reply_is_reconciled_by_reading_current_role_before_restore():
    indexer = Indexer()
    indexer.lose_patch_reply = True
    with pytest.raises(httpx.ReadTimeout):
        indexer.run("grant")
    assert indexer.role == acl.temporary(BEFORE)
    indexer.lose_patch_reply = False
    assert indexer.run("restore")["role"] == BEFORE


def test_restore_preserves_concurrent_role_changes_and_never_overwrites_snapshot():
    indexer = Indexer()
    indexer.run("grant")
    indexer.role["description"] = "concurrent-change"
    before = copy.deepcopy(indexer.role)
    with pytest.raises(ValueError, match="role_drift_before_restore"):
        indexer.run("restore")
    assert indexer.role == before
    assert len([r for r in indexer.calls if r.method == "PATCH"]) == 1


@pytest.mark.parametrize(
    "change",
    [
        lambda role: role.update(reserved=True),
        lambda role: role["cluster_permissions"].append("*"),
        lambda role: role["index_permissions"][0].update(index_patterns=["*"]),
        lambda role: role["index_permissions"][0].update(allowed_actions=["manage"]),
        lambda role: role["index_permissions"][0].update(dls="restricted"),
    ],
)
def test_unexpected_baseline_never_gets_a_grant(change):
    indexer = Indexer()
    change(indexer.role)
    with pytest.raises(ValueError):
        indexer.run("snapshot")
    with pytest.raises(ValueError):
        indexer.run("grant")
    assert not [r for r in indexer.calls if r.method == "PATCH"]


def test_identity_and_operation_refused_before_authenticated_effect():
    def forbidden(*a, **kw):
        pytest.fail("No request before maintenance identity and operation review")

    with pytest.raises(ValueError):
        acl.maintain({**PAYLOAD, "username": "reader"}, "grant", factory=forbidden, peer=forbidden)
    with pytest.raises(ValueError):
        acl.maintain(PAYLOAD, "arbitrary", factory=forbidden, peer=forbidden)
    with pytest.raises(ValueError):
        acl.maintain(
            {**PAYLOAD, "exclusive_scope_sha256": None}, "grant", factory=forbidden, peer=forbidden
        )
    with pytest.raises(ValueError):
        acl.maintain(
            PAYLOAD, "grant", factory=forbidden, peer=lambda: {"certificate_der_sha256": "b" * 64}
        )


def test_restore_of_already_original_role_is_read_only():
    indexer = Indexer()
    assert indexer.run("restore")["role"] == BEFORE
    assert not [r for r in indexer.calls if r.method == "PATCH"]
