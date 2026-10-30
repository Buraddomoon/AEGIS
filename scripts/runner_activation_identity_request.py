"""Build a bounded probe request from pinned public PKI; no Docker, private-key read or CLI."""

import json
from pathlib import Path

import runner_activation as plan
from aegis.domain.validation import digest
from aegis.lab_runner import identity_probe as probe
from aegis.lab_runner.protocol import RunnerIdentity
from runner_activation_confirmation import ConfirmedPlan
from runner_activation_metadata import ActivationError, document


def request(confirmation):
    """Public bytes/hash only; source/image/runtime authorization remain separate gates."""
    if not isinstance(confirmation, ConfirmedPlan):
        raise ActivationError("identity_request_confirmed_plan_required")
    original = confirmation._guard()
    artifact = confirmation.artifact
    if plan.tool_state() != artifact["tool_commit"]:
        raise ActivationError("identity_request_executor_drift")
    source, candidate = (Path(artifact[key]) for key in ("source_path", "candidate_path"))

    def snapshot():
        old, _ = plan.pki.inventory(source, current=False)
        new, _ = plan.pki.inventory(candidate, current=True)
        manifest = document(plan.pki.read(candidate / "rotation.json", modes=(0o600,)))
        if (
            digest(manifest) != artifact["pki"]["manifest_sha256"]
            or manifest.get("source") != old
            or manifest.get("candidate") != new
            or digest(old) != artifact["pki"]["source_inventory_sha256"]
            or old["descriptor_sha256"] != artifact["pki"]["old_descriptor_sha256"]
            or new["descriptor_sha256"] != artifact["pki"]["new_descriptor_sha256"]
            or any(
                new["connection"][key] != old["connection"][key]
                or new["connection"][key] != artifact["pki"]["identities"][key]
                for key in plan.pki.IDS
            )
            or new["connection"]["url"] != plan.profile()["runner_url"]
            or old["connection"]["url"] != new["connection"]["url"]
        ):
            raise ActivationError("identity_request_public_pki_drift")
        return old, new

    old, new = snapshot()
    identity = RunnerIdentity(**{key: new["connection"][key] for key in plan.pki.IDS}, tests=())
    value = {
        "format": probe.REQUEST_FORMAT,
        "operation_id": confirmation.operation,
        "created_at": plan.pki.clock().isoformat(),
        "expires_at": confirmation.expires.isoformat(),
        "plan_sha256": confirmation.plan_sha256,
        "scope_sha256": confirmation.scope,
        "identity": identity.model_dump(mode="json"),
        "server_leaf_sha256": new["certificates"]["runner-server"]["der_sha256"],
        "client_leaf_sha256": new["certificates"]["runner-client"]["der_sha256"],
        "certificate_sha256": {
            "candidate_server_ca": new["certificates"]["server-ca"]["pem_sha256"],
            "candidate_client_cert": new["certificates"]["runner-client"]["pem_sha256"],
            "previous_server_ca": old["certificates"]["server-ca"]["pem_sha256"],
        },
    }
    if (
        snapshot() != (old, new)
        or confirmation._guard() != original
        or plan.tool_state() != artifact["tool_commit"]
    ):
        raise ActivationError("identity_request_inputs_changed")
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    expected = digest(value)
    probe.decode(raw, expected)
    return raw, expected
