"""Bound local scope confirmation to the original durable operation; no external effects."""

import time
from datetime import datetime, timedelta

import runner_activation as plan
from runner_activation_metadata import ActivationError


class ConfirmedPlan:
    """Trusted operator assertion, not a signed approval or an operational executor.

    Reconstructing a gate cannot extend the original operation's 300s window.
    Cleanup remains independent of this lease, including after expiration.
    """

    def __init__(self, path, plan_sha256, store, authorized_scope_sha256, authorization_expires_at):
        plan.sha256(authorized_scope_sha256)
        self.path, self.plan_sha256, self.store = path, plan_sha256, store
        self.artifact = plan.load_plan(path, plan_sha256)
        self.scope = authorized_scope_sha256
        store.review()  # Validate the durable chain before reading its origin.
        origin = store.summary()
        self.operation, self.begin_sha256 = origin["id"], origin["begin_sha256"]
        self.started_at = datetime.fromisoformat(store.events[0]["at"])
        self.confirmed_at = plan.pki.clock()
        self.expires = datetime.fromisoformat(authorization_expires_at)
        if (
            self.expires.utcoffset() != timedelta(0)
            or not timedelta(0) < self.expires - self.confirmed_at <= timedelta(seconds=300)
            or not self.started_at <= self.confirmed_at < self.expires
            or self.expires > self.started_at + timedelta(seconds=300)
        ):
            raise ActivationError("activation_confirmation_interval_invalid")
        self.deadline = time.monotonic() + (self.expires - self.confirmed_at).total_seconds()
        self._guard()

    def _guard(self):
        state = self.store.review()
        now = plan.pki.clock()
        origin = self.store.summary()
        if (
            self.scope != self.artifact["scope_sha256"]
            or state["closed"]
            or state["header"]
            != {
                "plan_id": self.artifact["id"],
                "plan_sha256": self.plan_sha256,
                "scope_sha256": self.scope,
            }
            or origin["id"] != self.operation
            or origin["begin_sha256"] != self.begin_sha256
            or not self.confirmed_at <= now < self.expires
            or now < datetime.fromisoformat(self.store.events[-1]["at"])
            or time.monotonic() >= self.deadline
            or plan.load_plan(self.path, self.plan_sha256) != self.artifact
        ):
            raise ActivationError("activation_scope_or_budget_unconfirmed")
        return state
