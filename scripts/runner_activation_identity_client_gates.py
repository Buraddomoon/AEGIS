"""Computed identity-client gates under the original confirmation; no lifecycle or CLI."""

import copy
import time
from datetime import datetime, timedelta

import runner_activation as plan
import runner_activation_active_plan as active
import runner_activation_identity_client_inspection as inspection
import runner_activation_identity_client_network as network
import runner_activation_identity_client_runtime as runtime
import runner_activation_identity_image as image
import runner_activation_identity_inspection as parent
import runner_activation_identity_request as request
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
        "reviewed_client_profile",
        "request_public_pins_verified",
        "identity_server_profile_verified",
        "project_quiescent_or_owned",
        "worker_stopped",
        "original_volume_consumers_absent",
        "isolated_network_members_verified",
        "phase_configuration_verified",
    }
)


def validate(gate, phase, spec, state, operation, manifest_sha256):
    """Closed consumer check, never a saved-JSON authorization interface."""
    expected = {
        "format": "aegis-identity-client-gate/1",
        "phase": phase,
        "operation_id": operation,
        "resource_id": state["resources"][runtime.ROLE]["resource_id"],
        "plan_sha256": state["header"]["plan_sha256"],
        "scope_sha256": state["header"]["scope_sha256"],
        "recipe_sha256": digest(spec),
        "request_context_sha256": spec["request_context_sha256"],
        "pki_manifest_sha256": manifest_sha256,
        "runner_resource_id": spec["runner_resource_id"],
        "network_resource_id": spec["network_resource_id"],
    }
    if (
        phase not in {"create", "start", "exited"}
        or not isinstance(gate, dict)
        or set(gate) != {*expected, "checked_at", "expires_at", "checks"}
        or any(gate[key] != value for key, value in expected.items())
        or not isinstance(gate["checks"], dict)
        or set(gate["checks"]) != CHECKS
        or any(value is not True for value in gate["checks"].values())
    ):
        raise ActivationError("identity_client_gate_mismatch")
    fresh(gate)
    return gate


class IdentityClientGates:
    """Combine real read-only facts; reuse the same lease and original request bytes.

    Specific native authorization and a complete coordinator are still required.
    Gate success proves neither TLS output nor activation. Evidence is in memory
    until the coordinator persists it under its durable operation.
    """

    def __init__(
        self,
        confirmation,
        build_inputs,
        payload,
        expected_sha256,
        *,
        docker=None,
        ownership_docker=None,
        runtime_docker=None,
        network_docker=None,
    ):
        if not isinstance(confirmation, ConfirmedPlan):
            raise ActivationError("identity_client_gate_confirmed_plan_required")
        self.confirmation = confirmation
        self.context = request.review(confirmation, payload, expected_sha256)
        self._payload, self.context_sha256 = payload, expected_sha256
        self.build_inputs = copy.deepcopy(build_inputs)
        self.docker, self.ownership_docker = docker, ownership_docker
        self.runtime_docker, self.network_docker = runtime_docker, network_docker
        self.evidence = []
        self._last_gate = None
        self._last_review = None

    def review(self, phase, spec):
        self._last_gate = None
        self._last_review = None
        c = self.confirmation
        original = c._guard()
        current = original["resources"].get(runtime.ROLE, {})
        if (
            phase not in {"create", "start", "exited"}
            or (phase == "create" and current != {"state": "REQUESTED", "resource_id": None})
            or (phase == "start" and (current.get("state") != "OBSERVED" or "start" in current))
            or (
                phase == "exited"
                and (
                    current.get("state") not in {"START_REQUESTED", "OBSERVED"}
                    or current.get("start", {}).get("request_context_sha256") != self.context_sha256
                )
            )
        ):
            raise ActivationError("identity_client_gate_phase_or_no_replay_mismatch")
        expected = runtime.recipe(c.store, c.path, c.plan_sha256, self.context_sha256)
        if digest(spec) != digest(expected):
            raise ActivationError("identity_client_gate_recipe_mismatch")
        started, deadline = plan.pki.clock(), time.monotonic() + 20

        def facts():
            c._guard()
            return active.recheck(
                c.path,
                c.plan_sha256,
                c.store,
                runtime.ROLE,
                "identity-" + phase,
                request_context_sha256=self.context_sha256,
                docker=self.docker,
                ownership_docker=self.ownership_docker,
            )

        before = facts()
        context_before = request.review(c, self._payload, self.context_sha256)
        sealed = image.review(
            self.build_inputs, expected["image"], c.artifact["tool_commit"], repo=plan.ROOT
        )
        profile = parent.review_image(expected["image"], docker=self.runtime_docker)
        server = parent.review(
            c.store,
            c.path,
            c.plan_sha256,
            expected["runner_resource_id"],
            "running",
            docker=self.runtime_docker,
            ownership_docker=self.ownership_docker,
        )
        bridge = network.review(
            c.store,
            c.path,
            c.plan_sha256,
            self.context_sha256,
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
                self.context_sha256,
                current["resource_id"],
                "created" if phase == "start" else "exited",
                docker=self.runtime_docker,
                ownership_docker=self.ownership_docker,
            )
        after = facts()
        # The second full active-plan review has already revalidated the SAME
        # manifest and public/private material against the pinned plan. Recheck
        # the original bytes/window here without repeating those crypto reads.
        context_after = request.probe.decode(self._payload, self.context_sha256)
        if (
            context_before != self.context
            or context_after != self.context
            or digest(before["owned_metadata"]) != digest(after["owned_metadata"])
            or c._guard() != original
            or digest(runtime.recipe(c.store, c.path, c.plan_sha256, self.context_sha256))
            != digest(expected)
            or time.monotonic() >= deadline
        ):
            raise ActivationError("identity_client_gate_inputs_changed_or_expired")
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
            "reviewed_client_profile": digest(spec) == digest(expected),
            "request_public_pins_verified": after["request_context_sha256"] == self.context_sha256,
            "identity_server_profile_verified": server["recipe_sha256"]
            == expected["server_recipe_sha256"]
            and server["runtime_configuration_verified"] is True
            and server["original_volumes_not_mounted_verified"] is True
            and server["published_ports_absent_verified"] is True,
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
            "format": "aegis-identity-client-gate/1",
            "phase": phase,
            "operation_id": c.operation,
            "resource_id": current["resource_id"],
            "plan_sha256": c.plan_sha256,
            "scope_sha256": c.scope,
            "recipe_sha256": digest(expected),
            "request_context_sha256": self.context_sha256,
            "pki_manifest_sha256": c.artifact["pki"]["manifest_sha256"],
            "runner_resource_id": expected["runner_resource_id"],
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
                "server_runtime_sha256": digest(server),
                "network_sha256": digest(bridge),
                "client_runtime_sha256": digest(physical) if physical is not None else None,
                "request_context_sha256": self.context_sha256,
            }
        )
        self._last_gate = copy.deepcopy(gate)
        self._last_review = copy.deepcopy(
            {
                "plan_before": before,
                "plan_after": after,
                "image_inputs": sealed,
                "image_profile": profile,
                "server_runtime": server,
                "network": bridge,
                "client_runtime": physical,
                "request_context_sha256": self.context_sha256,
            }
        )
        return gate
