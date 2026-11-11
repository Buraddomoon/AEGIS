"""Compute closed diagnostic lifecycle gates from live checks; no CLI or lifecycle."""

import time
from datetime import datetime, timedelta

import runner_activation_database_inspection as database
import runner_activation_database_lifecycle as reader
import runner_activation_database_result as captures
import runner_activation_database_server_lifecycle as server
import runner_activation_probe_lifecycle as journal
import runner_diagnostic_recheck as facts
from aegis.domain.validation import digest
from aegis.lab_runner.persisted_review import expected_proofs
from aegis.lab_runner.protocol import RunnerIdentity
from runner_activation_intents import _hash
from runner_activation_metadata import ActivationError


class DiagnosticGates:
    """Host-only, operator scope confirmation; not a signed human approval service.

    A future authorized coordinator must supply the explicitly confirmed scope.
    Never instantiate against original resources merely because fixtures pass.
    Each method computes live facts; callers cannot provide checks=True JSON.
    """

    def __init__(
        self,
        folder,
        plan_sha256,
        store,
        authorized_scope_sha256,
        authorization_expires_at,
        *,
        repo=facts.plan.ROOT,
        policy_root=database.server.policy.DEFAULT_ROOT,
        capture_root=captures.DEFAULT_ROOT,
        docker=None,
        ownership_docker=None,
        runtime_docker=None,
    ):
        _hash(authorized_scope_sha256)
        self.folder, self.plan_sha256, self.store = folder, plan_sha256, store
        self.artifact = facts.plan.load(folder, plan_sha256)
        self.scope = authorized_scope_sha256
        self.expires = datetime.fromisoformat(authorization_expires_at)
        now = facts.plan.pki.clock()
        store.review()
        self.origin = store.summary()
        self.started_at = datetime.fromisoformat(store.events[0]["at"])
        self.confirmed_at = now
        if (
            self.expires.utcoffset() != timedelta(0)
            or not timedelta(0) < self.expires - now <= timedelta(seconds=300)
            or not self.started_at <= now < self.expires
            or self.expires > self.started_at + timedelta(seconds=300)
        ):
            raise ActivationError("diagnostic_authorization_interval_invalid")
        self.deadline = time.monotonic() + (self.expires - now).total_seconds()
        self.repo, self.policy_root, self.capture_root = repo, policy_root, capture_root
        self.docker, self.ownership_docker, self.runtime_docker = (
            docker,
            ownership_docker,
            runtime_docker,
        )
        snapshot = self.artifact["snapshot"]
        self.images = {
            key: snapshot["metadata"]["images"][key]["id"] for key in facts.plan.metadata.IMAGES
        }
        self.identity = RunnerIdentity.model_validate(snapshot["identity"])
        self.descriptor = snapshot["old_descriptor_sha256"]
        self.proof_role, self.proof_sha256 = None, None
        self.evidence = []
        self._guard()

    def _guard(self):
        state = self.store.review()
        now = facts.plan.pki.clock()
        if (
            self.scope != self.artifact["scope_sha256"]
            or state["closed"]
            or state["header"]
            != {
                "plan_id": self.artifact["id"],
                "plan_sha256": self.plan_sha256,
                "scope_sha256": self.scope,
            }
            or time.monotonic() >= self.deadline
            or now >= self.expires
            or now < self.confirmed_at
            or now < datetime.fromisoformat(self.store.events[-1]["at"])
            or self.store.summary()["id"] != self.origin["id"]
            or self.store.summary()["begin_sha256"] != self.origin["begin_sha256"]
            or facts.plan.load(self.folder, self.plan_sha256) != self.artifact
        ):
            raise ActivationError("diagnostic_scope_or_budget_unconfirmed")

    def _facts(self, role, phase):
        self._guard()
        observed = facts.recheck(
            self.folder,
            self.plan_sha256,
            self.store,
            role,
            phase,
            repo=self.repo,
            docker=self.docker,
            ownership_docker=self.ownership_docker,
        )
        self._guard()
        return observed

    def _database(self, phase):
        item = self.store.review()["resources"].get("db")
        if item is None or item["resource_id"] is None:
            raise ActivationError("diagnostic_physical_database_required")
        return database.review(
            self.store,
            self.images["postgres"],
            item["resource_id"],
            phase,
            policy_root=self.policy_root,
            docker=self.runtime_docker,
            ownership_docker=self.ownership_docker,
        )

    def _base(self, phase, spec, observed, checks):
        self._guard()
        if any(value is not True for value in checks.values()):
            raise ActivationError("diagnostic_computed_gate_incomplete")
        now = facts.plan.pki.clock()
        gate = {
            "phase": phase,
            "operation_id": self.store.summary()["id"],
            "plan_sha256": self.plan_sha256,
            "scope_sha256": self.scope,
            "recipe_sha256": digest(spec),
            "checked_at": now.isoformat(),
            "expires_at": min(
                now + timedelta(seconds=20),
                self.expires,
                datetime.fromisoformat(self.artifact["expires_at"]),
            ).isoformat(),
            "checks": checks,
        }
        self.evidence.append(
            {
                "role": spec["role"],
                "phase": phase,
                "metadata_sha256": digest(observed),
                "gate_base_sha256": digest(gate),
            }
        )
        return gate

    def _common(self, observed):
        meta = observed["owned_metadata"]
        return {
            "specific_authorization_verified": observed["scope_sha256"] == self.scope,
            "plan_current": observed["status"]
            == "owned_diagnostic_inputs_consistent_not_authorized",
            # Local source/official registry binding under host+daemon trust;
            # publisher signatures and raw local layer verification are not claimed.
            "image_provenance_verified": observed["local_runner_build_inputs_verified"]
            and self.artifact["snapshot"]["postgres_origin"]["registry_manifest_verified"],
            "worker_stopped": meta["project_membership_verified"],
        }

    def before_server(self, phase, spec):
        if phase not in {"create", "start", "ready"}:
            raise ActivationError("diagnostic_server_phase_invalid")
        observed = self._facts("db", "running" if phase == "ready" else phase)
        expected = server.server.recipe(
            self.store, self.images["postgres"], policy_root=self.policy_root
        )
        if digest(spec) != digest(expected):
            raise ActivationError("diagnostic_server_recipe_mismatch")
        authentication = database.server.policy.verify(self.store, root=self.policy_root)
        physical = (
            self._database("running" if phase == "ready" else "created")
            if phase != "create"
            else None
        )
        meta = observed["owned_metadata"]
        checks = {
            **self._common(observed),
            "original_database_volume_verified": meta["inventory"]["volumes"]["postgres-data"][
                "name"
            ]
            == spec["volume"],
            "database_policy_file_verified": authentication["fixed_policy_verified"],
            "exclusive_database_consumer_verified": meta["project_membership_verified"],
            "original_journal_quiescent": meta["journal_consumer_set_verified"],
        }
        if physical is not None and not physical["expected_database_volume_mount_verified"]:
            raise ActivationError("diagnostic_server_mount_unconfirmed")
        gate = {
            "format": "aegis-database-server-gate/1",
            **self._base(phase, spec, observed, checks),
            "resource_id": self.store.review()["resources"]["db"]["resource_id"],
            "policy_sha256": spec["policy_sha256"],
            "volume": spec["volume"],
        }
        return server._gate(
            lambda *a: gate,
            phase,
            spec,
            self.store.review(),
            self.store.summary()["id"],
            gate["resource_id"],
        )

    def before_reader(self, phase, spec):
        role = spec["role"]
        if role not in {"database-review-before", "database-review-after"} or phase not in {
            "create",
            "start",
        }:
            raise ActivationError("diagnostic_reader_context_invalid")
        observed = self._facts(role, phase)
        physical = self._database("running")
        context_sha = digest(captures.context(self.identity, self.descriptor))
        expected = reader.runtime.recipe(self.store, role, self.images["runner"], context_sha)
        if digest(spec) != digest(expected):
            raise ActivationError("diagnostic_reader_recipe_mismatch")
        checks = {
            **self._common(observed),
            "original_database_volume_verified": physical[
                "expected_database_volume_mount_verified"
            ],
            "database_runtime_isolated": physical["network_none_verified"]
            and physical["published_ports_absent_verified"],
            "database_authentication_policy_verified": physical[
                "fixed_authentication_policy_mount_verified"
            ],
            "exclusive_database_consumer_verified": observed["owned_metadata"][
                "project_membership_verified"
            ],
        }
        gate = {
            "format": "aegis-database-reader-gate/1",
            **self._base(phase, spec, observed, checks),
            "request_context_sha256": context_sha,
            "old_descriptor_sha256": self.descriptor,
            "identity_sha256": digest(self.identity.model_dump(mode="json")),
            "database_resource_id": spec["database_resource_id"],
        }
        return reader._gate(
            lambda *a: gate,
            phase,
            spec,
            self.store.review(),
            self.store.summary()["id"],
            self.identity,
            self.descriptor,
            context_sha,
        )

    def use_capture(self, role, expected_sha256):
        if role != "database-review-before":
            raise ActivationError("diagnostic_initial_capture_required")
        _hash(expected_sha256)
        self._guard()
        captures.load(
            self.store,
            role,
            expected_sha256,
            self.identity,
            self.descriptor,
            root=self.capture_root,
        )
        if self.store.review()["resources"][role]["state"] != "ABSENT":
            raise ActivationError("diagnostic_capture_reader_cleanup_required")
        if self.proof_sha256 is not None:
            raise ActivationError("diagnostic_capture_already_pinned")
        self.proof_role, self.proof_sha256 = role, expected_sha256

    def before_journal(self, phase, spec):
        role = spec["role"]
        if (
            role not in {"journal-before", "journal-after"}
            or phase not in {"create", "start"}
            or self.proof_sha256 is None
        ):
            raise ActivationError("diagnostic_journal_context_invalid")
        observed = self._facts(role, phase)
        physical = self._database("running")
        bundle = captures.load(
            self.store,
            self.proof_role,
            self.proof_sha256,
            self.identity,
            self.descriptor,
            root=self.capture_root,
        )
        identity, _proofs = expected_proofs(bundle, self.proof_sha256)
        expected = journal.runtime.recipe(
            self.store.summary()["id"],
            self.plan_sha256,
            role,
            self.images["runner"],
            self.proof_sha256,
        )
        if digest(spec) != digest(expected) or identity != self.identity:
            raise ActivationError("diagnostic_journal_recipe_mismatch")
        meta = observed["owned_metadata"]
        checks = {
            **self._common(observed),
            "original_database_binding_verified": physical[
                "expected_database_volume_mount_verified"
            ],
            "persisted_history_verified": bundle["old_descriptor_sha256"] == self.descriptor,
            "existing_journal_volume_verified": meta["inventory"]["volumes"]["journal"]["name"]
            == spec["volume"],
            "exclusive_journal_consumer_verified": meta["journal_consumer_set_verified"],
        }
        gate = {
            "format": "aegis-journal-probe-gate/1",
            **self._base(phase, spec, observed, checks),
            "proof_bundle_sha256": self.proof_sha256,
            "old_descriptor_sha256": self.descriptor,
            "identity_sha256": digest(self.identity.model_dump(mode="json")),
        }
        return journal._gate(
            lambda *a: gate,
            phase,
            spec,
            self.store.review(),
            self.store.summary()["id"],
            self.identity,
            bundle,
            self.proof_sha256,
        )
