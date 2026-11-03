"""Closed native identity-assay readers/bridge/cleanup with one original time budget."""

import time
from datetime import timedelta

import runner_activation_cleanup as cleanup
import runner_activation_identity_inspection as physical
import runner_activation_isolated_network as network
import runner_activation_metadata as metadata
import runner_activation_ownership as ownership
import runner_activation_subnet_review as subnet
import runner_pki as pki
from runner_activation_confirmation import ConfirmedPlan
from runner_activation_metadata import ActivationError

ROLES = frozenset({"network-isolated", "runner", "identity-client"})


class IdentityBudget:
    """At most240s for effects; cleanup only until original begin+300s.

    Construction is not human authorization. Monotonic deadlines never refresh;
    UTC jumps forward can only shorten the window. Read-only native queries share
    the hard cleanup deadline; callers recheck normal admission before any effect.
    """

    def __init__(self, confirmation):
        if not isinstance(confirmation, ConfirmedPlan):
            raise ActivationError("identity_budget_confirmed_plan_required")
        confirmation._guard()
        if confirmation.expires > confirmation.started_at + timedelta(seconds=240):
            raise ActivationError("identity_budget_cleanup_reserve_required")
        self.confirmation = confirmation
        self.expires = confirmation.started_at + timedelta(seconds=300)
        self.deadline = (
            confirmation.deadline + (self.expires - confirmation.expires).total_seconds()
        )

    def remaining(self, cap=20, *, effect=False):
        if type(cap) not in (int, float) or not 0 < cap <= 20 or type(effect) is not bool:
            raise ActivationError("identity_budget_cap_invalid")
        c = self.confirmation
        if effect:
            c._guard()
        deadline, expires = (c.deadline, c.expires) if effect else (self.deadline, self.expires)
        left = min(deadline - time.monotonic(), (expires - pki.clock()).total_seconds())
        if left <= 0:
            raise ActivationError("identity_assay_budget_exhausted")
        return min(cap, left)


class _Metadata:
    def __init__(self, budget):
        self.budget = budget

    def query(self, kind, value=None):
        return metadata._execute(metadata.command(kind, value), timeout=self.budget.remaining())


class _Ownership:
    def __init__(self, budget):
        self.budget = budget

    def query(self, kind, operation_id, plan_sha256, role, known_id=None):
        c = self.budget.confirmation
        if role not in ROLES or (operation_id, plan_sha256) != (c.operation, c.plan_sha256):
            raise ActivationError("identity_assay_ownership_scope_mismatch")
        return metadata._execute(
            ownership.command(kind, operation_id, plan_sha256, role, known_id),
            timeout=self.budget.remaining(),
        )


class _Physical:
    def __init__(self, budget):
        self.budget = budget

    def query(self, kind, image, *, spec=None, known_id=None):
        if spec is not None and spec.get("role") not in {"runner", "identity-client"}:
            raise ActivationError("identity_assay_physical_role_mismatch")
        return metadata._execute(
            physical.command(kind, image, spec=spec, known_id=known_id),
            timeout=self.budget.remaining(),
        )


class _Network:
    def __init__(self, budget):
        self.budget = budget

    def query(self, store, known_id):
        if store is not self.budget.confirmation.store:
            raise ActivationError("identity_assay_network_store_mismatch")
        return metadata._execute(network.command(store, known_id), timeout=self.budget.remaining())


class _Subnet(subnet.NetworkReader):
    def __init__(self, budget):
        self.budget = budget

    def query(self, known_id=None, *, timeout):
        return super().query(known_id, timeout=min(timeout, self.budget.remaining()))


class _Routes(subnet.RouteReader):
    def __init__(self, budget):
        self.budget = budget

    def query(self, *, timeout):
        return super().query(timeout=min(timeout, self.budget.remaining(5)))


class _BridgeCreate:
    def __init__(self, budget):
        self.budget = budget

    def create(self, store):
        if store is not self.budget.confirmation.store:
            raise ActivationError("identity_assay_network_store_mismatch")
        self.budget.remaining(effect=True)
        args = network.create_arguments(store)
        raw = metadata._execute(args, timeout=self.budget.remaining(effect=True))
        return ownership.identifier(raw.decode("ascii").removesuffix("\n"))


class _Cleanup:
    def __init__(self, budget):
        self.budget = budget

    def effect(self, kind, operation_id, plan_sha256, role, known_id):
        c = self.budget.confirmation
        if role not in ROLES or (operation_id, plan_sha256) != (c.operation, c.plan_sha256):
            raise ActivationError("identity_assay_cleanup_scope_mismatch")
        metadata._execute(
            cleanup.command(kind, operation_id, plan_sha256, role, known_id),
            timeout=self.budget.remaining(),
        )


class IdentityNativeAdapters:
    """Only fixed compiler commands; never an API for caller-supplied argv or targets."""

    def __init__(self, budget):
        if not isinstance(budget, IdentityBudget):
            raise ActivationError("identity_assay_original_budget_required")
        self.metadata = _Metadata(budget)
        self.ownership = _Ownership(budget)
        self.physical = _Physical(budget)
        self.network = _Network(budget)
        self.subnet = _Subnet(budget)
        self.routes = _Routes(budget)
        self.bridge_create = _BridgeCreate(budget)
        self.cleanup = _Cleanup(budget)
