"""Compute identity-server gates from live reviews; no lifecycle or saved gate input."""

import copy
import time
from datetime import datetime, timedelta

import runner_activation as plan
import runner_activation_active_plan as active
import runner_activation_identity_image as image
import runner_activation_identity_inspection as inspection
import runner_activation_identity_network as network
import runner_activation_identity_runtime as runtime
from aegis.domain.validation import digest
from runner_activation_confirmation import ConfirmedPlan
from runner_activation_metadata import ActivationError
from runner_activation_owned_probe import fresh

CHECKS = frozenset(
    {
        "specific_authorization_verified",
        "plan_current",
        "pki_candidate_verified",
        "current_sealed_image_inputs_verified",
        "image_profile_verified",
        "reviewed_identity_profile",
        "project_quiescent_or_owned",
        "worker_stopped",
        "original_volume_consumers_absent",
        "isolated_network_members_verified",
        "phase_configuration_verified",
    }
)


def validate(gate, phase, spec, state, operation, manifest_sha256):
    """Consumer-side context/strict-boolean/freshness check; not authorization by itself."""
    expected = {
        "format": "aegis-identity-server-gate/1",
        "phase": phase,
        "operation_id": operation,
        "resource_id": state["resources"]["runner"]["resource_id"],
        "plan_sha256": state["header"]["plan_sha256"],
        "scope_sha256": state["header"]["scope_sha256"],
        "recipe_sha256": digest(spec),
        "pki_manifest_sha256": manifest_sha256,
        "network_resource_id": spec["network_resource_id"],
    }
    if (
        phase not in {"create", "start", "running"}
        or not isinstance(gate, dict)
        or set(gate) != {*expected, "checked_at", "expires_at", "checks"}
        or any(gate[key] != value for key, value in expected.items())
        or not isinstance(gate["checks"], dict)
        or set(gate["checks"]) != CHECKS
        or any(value is not True for value in gate["checks"].values())
    ):
        raise ActivationError("identity_server_gate_mismatch")
    fresh(gate)
    return gate


class IdentityGates:
    """Reuse the SAME confirmation/budget as network creation, without renewing it.

    Only trusted internal coordinator use. All reviews are read-only. A successful
    gate does not prove TLS, authorize a native assay or enable normal operation.
    """

    def __init__(
        self,
        confirmation,
        build_inputs,
        *,
        docker=None,
        ownership_docker=None,
        runtime_docker=None,
        network_docker=None,
    ):
        if not isinstance(confirmation, ConfirmedPlan):
            raise ActivationError("identity_gate_confirmed_plan_required")
        confirmation._guard()
        self.confirmation = confirmation
        self.build_inputs = copy.deepcopy(build_inputs)
        self.docker, self.ownership_docker = docker, ownership_docker
        self.runtime_docker, self.network_docker = runtime_docker, network_docker
        self.evidence = []
        self._last_review = None

    def review(self, phase, spec):
        self._last_review = None
        c = self.confirmation
        original = c._guard()
        resource = original["resources"].get("runner", {})
        if (
            phase not in {"create", "start", "running"}
            or (phase == "create" and resource != {"state": "REQUESTED", "resource_id": None})
            or (phase == "start" and (resource.get("state") != "OBSERVED" or "start" in resource))
            or (
                phase == "running"
                and (
                    resource.get("state") not in {"START_REQUESTED", "OBSERVED"}
                    or resource.get("start", {}).get("mode") != "identity-only"
                )
            )
        ):
            raise ActivationError("identity_gate_phase_or_no_replay_mismatch")
        expected = runtime.recipe(c.store, c.path, c.plan_sha256)
        if digest(spec) != digest(expected):
            raise ActivationError("identity_gate_recipe_mismatch")
        started, deadline = plan.pki.clock(), time.monotonic() + 20

        def facts():
            c._guard()
            return active.recheck(
                c.path,
                c.plan_sha256,
                c.store,
                "runner",
                "identity-" + phase,
                docker=self.docker,
                ownership_docker=self.ownership_docker,
            )

        before = facts()
        sealed = image.review(
            self.build_inputs, expected["image"], c.artifact["tool_commit"], repo=plan.ROOT
        )
        profile = inspection.review_image(expected["image"], docker=self.runtime_docker)
        bridge = network.review(
            c.store,
            c.path,
            c.plan_sha256,
            phase,
            docker=self.network_docker,
            ownership_docker=self.ownership_docker,
        )
        physical = None
        if phase != "create":
            physical = inspection.review(
                c.store,
                c.path,
                c.plan_sha256,
                resource["resource_id"],
                "created" if phase == "start" else "running",
                docker=self.runtime_docker,
                ownership_docker=self.ownership_docker,
            )
        after = facts()
        if (
            digest(before["owned_metadata"]) != digest(after["owned_metadata"])
            or c._guard() != original
            or digest(runtime.recipe(c.store, c.path, c.plan_sha256)) != digest(expected)
            or time.monotonic() >= deadline
        ):
            raise ActivationError("identity_gate_inputs_changed_or_expired")
        meta = after["owned_metadata"]
        checks = {
            "specific_authorization_verified": after["scope_sha256"] == c.scope,
            "plan_current": after["status"] == "active_plan_revalidated_not_activated",
            "pki_candidate_verified": after["pki_manifest_sha256"]
            == c.artifact["pki"]["manifest_sha256"]
            and after["new_descriptor_sha256"] == c.artifact["pki"]["new_descriptor_sha256"],
            "current_sealed_image_inputs_verified": sealed["native_image_id"] == expected["image"]
            and sealed["tool_commit"] == c.artifact["tool_commit"]
            and sealed["package_and_dependency_sources_current"] is True
            and sealed["build_client_exit_verified"] is True,
            "image_profile_verified": profile["image"] == expected["image"]
            and profile["anonymous_volumes_excluded"] is True,
            "reviewed_identity_profile": digest(spec) == digest(expected),
            "project_quiescent_or_owned": meta["project_membership_verified"] is True,
            "worker_stopped": meta["project_membership_verified"] is True,
            "original_volume_consumers_absent": meta["journal_consumer_set_verified"] is True,
            "isolated_network_members_verified": bridge["expected_member_set_verified"] is True
            and bridge["configured_internal_isolated_bridge_verified"] is True,
            "phase_configuration_verified": phase == "create"
            or (
                physical["runtime_configuration_verified"] is True
                and physical["original_volumes_not_mounted_verified"] is True
                and physical["published_ports_absent_verified"] is True
            ),
        }
        gate = {
            "format": "aegis-identity-server-gate/1",
            "phase": phase,
            "operation_id": c.operation,
            "resource_id": resource["resource_id"],
            "plan_sha256": c.plan_sha256,
            "scope_sha256": c.scope,
            "recipe_sha256": digest(expected),
            "pki_manifest_sha256": c.artifact["pki"]["manifest_sha256"],
            "network_resource_id": expected["network_resource_id"],
            "checked_at": started.isoformat(),
            "expires_at": min(
                started + timedelta(seconds=20),
                c.expires,
                datetime.fromisoformat(c.artifact["expires_at"]),
            ).isoformat(),
            "checks": checks,
        }
        validate(gate, phase, expected, original, c.operation, c.artifact["pki"]["manifest_sha256"])
        c._guard()
        self.evidence.append(
            {
                "gate_sha256": digest(gate),
                "before_sha256": digest(before),
                "after_sha256": digest(after),
                "sealed_image_sha256": digest(sealed),
                "image_profile_sha256": digest(profile),
                "network_sha256": digest(bridge),
                "runtime_sha256": digest(physical) if physical is not None else None,
            }
        )
        self._last_review = copy.deepcopy(
            {
                "plan_before": before,
                "plan_after": after,
                "image_inputs": sealed,
                "image_profile": profile,
                "network": bridge,
                "runtime": physical,
            }
        )
        return gate
