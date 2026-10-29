"""Internal live gates for one isolated bridge; no CLI, approval service or lifecycle."""

import time
from datetime import datetime, timedelta

import runner_activation as plan
import runner_activation_active_plan as active
import runner_activation_isolated_network as network
import runner_activation_network_lifecycle as lifecycle
import runner_activation_subnet_review as subnet
from aegis.domain.validation import digest
from runner_activation_metadata import ActivationError


class NetworkGates:
    """Compute facts under an explicit local operator confirmation, never saved gate JSON.

    The future coordinator must obtain specific authorization before instantiation
    against real resources. Confirmation is not a signed human approval. This
    component does not authorize other resources, PKI writes or normal operation.
    """

    def __init__(
        self,
        path,
        plan_sha256,
        store,
        authorized_scope_sha256,
        authorization_expires_at,
        *,
        docker=None,
        ownership_docker=None,
        subnet_docker=None,
        routes=None,
    ):
        plan.sha256(authorized_scope_sha256)
        self.path, self.plan_sha256, self.store = path, plan_sha256, store
        self.artifact = plan.load_plan(path, plan_sha256)
        self.scope = authorized_scope_sha256
        self.confirmed_at = plan.pki.clock()
        self.expires = datetime.fromisoformat(authorization_expires_at)
        if self.expires.utcoffset() != timedelta(0) or not timedelta(
            0
        ) < self.expires - self.confirmed_at <= timedelta(seconds=300):
            raise ActivationError("network_authorization_interval_invalid")
        self.deadline = time.monotonic() + (self.expires - self.confirmed_at).total_seconds()
        self.operation = store.summary()["id"]
        self.docker, self.ownership_docker = docker, ownership_docker
        self.subnet_docker, self.routes = subnet_docker, routes
        self.evidence = []
        self._guard()

    def _guard(self):
        state = self.store.review()
        now = plan.pki.clock()
        if (
            self.scope != self.artifact["scope_sha256"]
            or state["closed"]
            or state["header"]
            != {
                "plan_id": self.artifact["id"],
                "plan_sha256": self.plan_sha256,
                "scope_sha256": self.scope,
            }
            or self.store.summary()["id"] != self.operation
            or not self.confirmed_at <= now < self.expires
            or time.monotonic() >= self.deadline
            or plan.load_plan(self.path, self.plan_sha256) != self.artifact
        ):
            raise ActivationError("network_scope_or_budget_unconfirmed")
        return state

    def _facts(self):
        self._guard()
        value = active.recheck(
            self.path,
            self.plan_sha256,
            self.store,
            network.ROLE,
            "create",
            docker=self.docker,
            ownership_docker=self.ownership_docker,
        )
        self._guard()
        return value

    def before_create(self, phase, spec):
        if phase != "create":
            raise ActivationError("network_gate_create_only")
        original = self._guard()
        expected = network.recipe(self.store)
        if digest(spec) != digest(expected):
            raise ActivationError("network_gate_recipe_mismatch")
        # Timestamp the beginning, not the end, of the observations. Slow IO
        # cannot mint a fresh lease over stale facts. The lifecycle checks age
        # again immediately before its single create RPC.
        started, deadline = plan.pki.clock(), time.monotonic() + 20
        before = self._facts()
        availability = subnet.review(docker=self.subnet_docker, routes=self.routes)
        after = self._facts()
        if (
            digest(before["owned_metadata"]) != digest(after["owned_metadata"])
            or self._guard() != original
            or digest(network.recipe(self.store)) != digest(expected)
            or time.monotonic() >= deadline
        ):
            raise ActivationError("network_gate_inputs_changed_or_expired")
        meta = after["owned_metadata"]
        checks = {
            "specific_authorization_verified": after["scope_sha256"] == self.scope,
            "plan_current": after["status"] == "active_plan_revalidated_not_activated",
            "pki_candidate_verified": after["pki_manifest_sha256"]
            == self.artifact["pki"]["manifest_sha256"]
            and after["new_descriptor_sha256"] == self.artifact["pki"]["new_descriptor_sha256"],
            "reviewed_network_profile": digest(spec) == digest(expected),
            "project_quiescent_or_owned": meta["project_membership_verified"] is True
            and meta["journal_consumer_set_verified"] is True,
            "subnet_availability_verified": availability["subnet"] == network.SUBNET
            and availability["status"] == "no_observed_fixed_ipv4_subnet_overlap"
            and availability["observed_ipv4_overlap_absent"] is True,
            # active.recheck enumerates ALL project members including stopped
            # containers; worker is never an admissible owned role.
            "worker_stopped": meta["project_membership_verified"] is True,
        }
        gate = {
            "format": "aegis-rotation-network-gate/1",
            "phase": phase,
            "operation_id": self.operation,
            "plan_sha256": self.plan_sha256,
            "scope_sha256": self.scope,
            "recipe_sha256": digest(expected),
            "network_name": expected["name"],
            "checked_at": started.isoformat(),
            "expires_at": min(
                started + timedelta(seconds=20),
                self.expires,
                datetime.fromisoformat(self.artifact["expires_at"]),
            ).isoformat(),
            "checks": checks,
        }
        # Reuse the consumer's closed shape, strict booleans and freshness check.
        lifecycle._gate(lambda *_: gate, expected, original, self.operation)
        self._guard()
        self.evidence.append(
            {
                "gate_sha256": digest(gate),
                "before_sha256": digest(before),
                "after_sha256": digest(after),
                "subnet_review_sha256": digest(availability),
            }
        )
        return gate
