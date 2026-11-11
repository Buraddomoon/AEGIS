"""Concrete bounded Docker rotation executor; invocation requires an approved native package."""

import json
import time
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import runner_activation as base
import runner_activation_cleanup as closure
import runner_activation_database_inspection as database
import runner_activation_database_policy as policy
import runner_activation_identity_image as image
import runner_activation_identity_inspection as physical
import runner_activation_isolated_network as network
import runner_activation_metadata as metadata
import runner_activation_ownership as ownership
import runner_activation_subnet_review as subnet
import runner_postgres_origin as postgres
import runner_rotation_runtime as runtime
from aegis.domain.validation import digest
from aegis.lab_runner import persisted_review
from aegis.lab_runner.rotation_probe import FORMAT, LIMIT, RESULT
from build_review_runner import _write
from runner_activation_intents import ROTATION_RUNNERS, _hash
from runner_activation_metadata import ActivationError
from runner_identity_budget import IdentityBudget
from runner_rotation_package import NativeConfirmation

ROOT = base.ROOT / ".local/pki-native-rotation-runtime"
ALL_ROLES = runtime.ROLES | {network.ROLE}


class NativeRotation:
    """No default flags or caller-supplied recipes can replace live gates.

    RPC injection is a Python test seam, never input parsed by a CLI/API.
    Native calls use the closed minimal-environment local Docker transport.
    """

    def __init__(
        self, confirmation, password, *, rpc=None, root=ROOT, subnet_reader=None, routes=None
    ):
        if not isinstance(confirmation, NativeConfirmation):
            raise ActivationError("rotation_native_package_confirmation_required")
        self.c, self.password = confirmation, password
        if type(password) is not str or not 1 <= len(password) <= 512 or "\0" in password:
            raise ActivationError("rotation_native_private_input_invalid")
        self.budget = IdentityBudget(confirmation)
        self.rpc = rpc or metadata._execute
        self.images = {
            k: confirmation.artifact["metadata"]["images"][k]["id"] for k in metadata.IMAGES
        }
        self.recipes, self.phases = {}, {}
        self.folder = base.pki.private_directory(root, create=True) / confirmation.operation
        self.folder.mkdir(mode=0o700)
        base.pki.sync(self.folder.parent)
        self.policy_root = self.folder / "policy"
        self.meta = SimpleNamespace(
            query=lambda kind, value=None: self._rpc(metadata.command(kind, value))
        )
        self.owners = SimpleNamespace(query=self._owner_query)
        self.cleaner = SimpleNamespace(effect=self._cleanup_effect)
        self.subnet_reader, self.routes = subnet_reader, routes

    def _rpc(self, args, *, payload=None, effect=False, output_limit=metadata.MAX_OUTPUT):
        return self.rpc(
            args,
            payload=payload,
            timeout=self.budget.remaining(effect=effect),
            output_limit=output_limit,
        )

    def _owner_query(self, kind, operation, plan, role, known_id=None):
        if (operation, plan) != (self.c.operation, self.c.plan_sha256) or role not in ALL_ROLES:
            raise ActivationError("rotation_native_ownership_scope_mismatch")
        return self._rpc(ownership.command(kind, operation, plan, role, known_id))

    def _cleanup_effect(self, kind, operation, plan, role, known_id):
        if (operation, plan) != (self.c.operation, self.c.plan_sha256) or role not in ALL_ROLES:
            raise ActivationError("rotation_native_cleanup_scope_mismatch")
        self._rpc(closure.command(kind, operation, plan, role, known_id))

    def record(self, name, body):
        _write(self.folder / (name + ".json"), json.dumps(body, sort_keys=True).encode())

    def admit(self):
        state = self.c._guard()
        if state.get("rotation_scope") != {
            "package_sha256": self.c.package_sha256,
            "expires_at": self.c.expires.isoformat(),
        }:
            raise ActivationError("rotation_native_durable_scope_required")
        if base.tool_state() != self.c.artifact["tool_commit"]:
            raise ActivationError("rotation_native_source_changed")
        verified = base.pki.verify(
            Path(self.c.artifact["source_path"]),
            Path(self.c.artifact["candidate_path"]),
            self.c.artifact["pki"]["manifest_sha256"],
        )
        if verified["descriptor_sha256"] != self.c.artifact["pki"]["new_descriptor_sha256"]:
            raise ActivationError("rotation_native_candidate_changed")
        self.budget.remaining(effect=True)
        return state

    def observe(self, role, known_id=None):
        return ownership.observe(
            self.c.operation, self.c.plan_sha256, role, known_id, docker=self.owners
        )

    def inspect(self, role):
        item = self.c.store.review()["resources"][role]
        spec = self.recipes[role]
        projection = self._rpc(
            (
                "container",
                "inspect",
                "--format",
                runtime.container_format(spec),
                item["resource_id"],
            )
        )
        return runtime.validate(
            spec, metadata.document(projection), item["resource_id"], self.phases[role]
        )

    def _sample(self):
        state = self.c.store.review()
        observed = metadata.inventory(self.images, docker=self.meta)
        if observed != self.c.artifact["metadata"]:
            raise ActivationError("rotation_native_inventory_drift")
        owned = state["resources"]
        if not set(owned) <= ALL_ROLES or any(
            v["state"] in {"CONFLICT", "REMOVAL_REQUESTED"} for v in owned.values()
        ):
            raise ActivationError("rotation_native_ownership_unresolved")
        containers, networks, journal, db_ids, reports = set(), set(), set(), set(), {}
        for role, value in owned.items():
            found = self.observe(role, value["resource_id"])
            exists = value["state"] not in {"REQUESTED", "ABSENT"}
            if (found["status"] == "present_owned_snapshot") is not exists:
                raise ActivationError("rotation_native_presence_changed")
            if not exists:
                continue
            if value["resource_id"] != found["resource_id"]:
                raise ActivationError("rotation_native_resource_changed")
            if role == network.ROLE:
                networks.add(value["resource_id"])
            else:
                if (
                    found["details"]["image"]
                    != self.images["postgres" if role == "db" else "runner"]
                ):
                    raise ActivationError("rotation_native_owned_image_changed")
                containers.add(value["resource_id"])
                if role == "db":
                    db_ids.add(value["resource_id"])
                if role in ROTATION_RUNNERS or role in runtime.JOURNAL_ROLES:
                    journal.add(value["resource_id"])
                reports[role] = self.inspect(role)

        def ids(raw):
            if type(raw) is not bytes or len(raw) > metadata.MAX_OUTPUT:
                raise ActivationError("rotation_native_id_projection_invalid")
            lines = raw.decode("ascii").splitlines()
            if len(lines) > 16 or len(set(lines)) != len(lines):
                raise ActivationError("rotation_native_id_projection_ambiguous")
            return {ownership.identifier(v) for v in lines}

        if (
            ids(self.meta.query("containers")) != containers
            or ids(self.meta.query("networks")) != networks
        ):
            raise ActivationError("rotation_native_foreign_project_member")
        for reserved in metadata.NETWORKS:
            if ids(self.meta.query("network_name", reserved)) != (
                networks if reserved == "isolated" else set()
            ):
                raise ActivationError("rotation_native_reserved_network_changed")
        if (
            len(journal) > 1
            or ids(self.meta.query("consumers", "journal")) != journal
            or ids(self.meta.query("consumers", "postgres-data")) != db_ids
        ):
            raise ActivationError("rotation_native_exclusive_volume_binding_required")
        if networks:
            known = next(iter(networks))
            item = metadata.document(self._rpc(network.command(self.c.store, known)))
            spec = network.recipe(self.c.store)
            network._configuration(spec, item, known)
            members = item["containers"] or {}
            possible = {
                v["resource_id"]: role
                for role, v in owned.items()
                if role == "db" or role in ROTATION_RUNNERS
                if v["state"] not in {"REQUESTED", "ABSENT"}
            }
            required = {key for key, role in possible.items() if self.phases[role] == "running"}
            if not isinstance(members, dict) or not required <= set(members) <= set(possible):
                raise ActivationError("rotation_native_network_members_changed")
            for key, endpoint in members.items():
                spec = self.recipes[possible[key]]
                if (
                    endpoint.get("Name") != spec["name"]
                    or endpoint.get("IPv4Address") != spec["ipv4_address"] + "/29"
                    or endpoint.get("IPv6Address") not in (None, "")
                ):
                    raise ActivationError("rotation_native_network_endpoint_changed")
            reports[network.ROLE] = digest(item)
        if self.c.store.review() != state:
            raise ActivationError("rotation_native_intent_changed_during_review")
        return {"inventory": observed, "physical": reports}

    def facts(self):
        self.admit()
        first, second = self._sample(), self._sample()
        if first != second:
            raise ActivationError("rotation_native_runtime_changed_during_review")
        self.admit()
        return first

    def gate(self, role, phase, spec):
        started = base.pki.clock()
        monotonic_deadline = time.monotonic() + 20
        evidence = self.facts()
        gate = {
            "role": role,
            "phase": phase,
            "recipe_sha256": digest(spec),
            "facts_sha256": digest(evidence),
            "checked_at": started.isoformat(),
            "package_sha256": self.c.package_sha256,
            "operation_id": self.c.operation,
        }
        if (base.pki.clock() - started).total_seconds() >= 20:
            raise ActivationError("rotation_native_gate_expired")
        gate["monotonic_deadline"] = monotonic_deadline
        self.record(role + "-" + phase + "-gate", gate)
        return gate

    def fresh(self, gate, spec):
        self.admit()
        age = (base.pki.clock() - datetime.fromisoformat(gate["checked_at"])).total_seconds()
        if (
            not 0 <= age < 20
            or time.monotonic() >= gate["monotonic_deadline"]
            or gate["recipe_sha256"] != digest(spec)
            or gate["package_sha256"] != self.c.package_sha256
        ):
            raise ActivationError("rotation_native_recent_computed_gate_required")

    def _new(self, role):
        if role in self.c.store.review()["resources"]:
            raise ActivationError("rotation_native_role_consumed_no_replay")
        self.c.store.request(role)
        found = self.observe(role)
        if found["status"] != "absent_snapshot":
            self.c.store.append(
                "ownership_conflict", {"role": role, "evidence_sha256": digest(found)}
            )
            raise ActivationError("rotation_native_name_collision")

    def bridge(self):
        self._new(network.ROLE)
        spec = network.recipe(self.c.store)
        available = subnet.review(docker=self.subnet_reader, routes=self.routes)
        if available["observed_ipv4_overlap_absent"] is not True:
            raise ActivationError("rotation_native_subnet_unconfirmed")
        gate = self.gate(network.ROLE, "create", spec)
        self.fresh(gate, spec)
        known = ownership.identifier(
            self._rpc(network.create_arguments(self.c.store), effect=True).decode("ascii").strip()
        )
        if self.observe(network.ROLE)["resource_id"] != known:
            raise ActivationError("rotation_native_created_network_unconfirmed")
        self.c.store.append("observed", {"role": network.ROLE, "resource_id": known})
        self.facts()

    def create(self, role, context_sha256=None):
        self._new(role)
        spec = runtime.recipe(self.c, role, context_sha256, policy_root=self.policy_root)
        self.recipes[role], self.phases[role] = spec, "created"
        gate = self.gate(role, "create", spec)
        self.fresh(gate, spec)
        known = ownership.identifier(
            self._rpc(runtime.create_arguments(spec), effect=True).decode("ascii").strip()
        )
        if self.observe(role)["resource_id"] != known:
            raise ActivationError("rotation_native_created_container_unconfirmed")
        self.c.store.append("observed", {"role": role, "resource_id": known})
        self.facts()

    def start(self, role, payload=None):
        spec = self.recipes[role]
        gate = self.gate(role, "start", spec)
        self.c.store.append(
            "rotation_start_requested",
            {"role": role, "recipe_sha256": digest(spec), "gates_sha256": digest(gate)},
        )
        known = self.c.store.review()["resources"][role]["resource_id"]
        self.fresh(gate, spec)
        args = (
            "container",
            "start",
            *(("--attach", "--interactive") if payload is not None else ()),
            known,
        )
        raw = self._rpc(
            args,
            payload=payload,
            effect=True,
            output_limit=LIMIT if payload is not None else metadata.MAX_OUTPUT,
        )
        self.phases[role] = "exited" if payload is not None else "running"
        if payload is None:
            self.ready(role, known)
        evidence = self.inspect(role)
        self.c.store.append(
            "rotation_runtime_observed", {"role": role, "runtime_evidence_sha256": digest(evidence)}
        )
        self.facts()
        return raw

    def ready(self, role, known):
        if role == "db":
            args = (
                "container",
                "exec",
                known,
                "/usr/local/bin/pg_isready",
                "-h",
                "127.0.0.1",
                "-p",
                "5432",
                "-U",
                "aegis_app",
                "-d",
                "aegis",
            )
        elif role in ROTATION_RUNNERS:
            args = (
                "container",
                "exec",
                known,
                "/usr/local/bin/python",
                "-I",
                "-B",
                "-c",
                "import socket; socket.create_connection(('127.0.0.1',8443),timeout=1).close()",
            )
        else:
            raise ActivationError("rotation_native_readiness_role_invalid")
        end = time.monotonic() + 8
        while True:
            self.admit()
            try:
                self._rpc(args, effect=True)
                return
            except ActivationError:
                if time.monotonic() >= end:
                    raise ActivationError("rotation_native_service_not_ready") from None
                time.sleep(0.1)

    def remove(self, role):
        report = closure.cleanup(
            self.c.store,
            self.images,
            roles={role},
            close_operation=False,
            docker=self.cleaner,
            ownership_docker=self.owners,
        )
        if not report["selected_resources_absence_verified"]:
            raise ActivationError("rotation_native_selected_cleanup_unconfirmed")

    def call(self, mode, baseline):
        role = "rotation-" + mode
        public = {
            "format": FORMAT,
            "operation_id": str(UUID(hex=self.c.operation)),
            "plan_sha256": self.c.plan_sha256,
            "scope_sha256": self.c.scope,
            "expires_at": self.c.expires.isoformat(),
            "mode": mode,
            "identity": persisted_review.RunnerIdentity.model_validate(
                self.c.artifact["pki"]["identities"]
            ).model_dump(mode="json"),
            "old_descriptor_sha256": self.c.artifact["pki"]["old_descriptor_sha256"],
            "new_descriptor_sha256": self.c.artifact["pki"]["new_descriptor_sha256"],
            "actor_id": self.c.package["actor_id"],
            "registration": self.c.package["registration"],
            "baseline": baseline,
        }
        context_sha256 = digest(public)
        payload = json.dumps(public | {"database_password": self.password}).encode()
        if len(payload) > LIMIT:
            raise ActivationError("rotation_native_private_input_limit")
        self.create(role, context_sha256)
        raw = self.start(role, payload)
        value = metadata.document(raw)
        if (
            not isinstance(value, dict)
            or set(value) != {"format", "context_sha256", "mode", "status", "result"}
            or value["format"] != RESULT
            or value["context_sha256"] != context_sha256
            or value["mode"] != mode
            or value["status"] != "phase_verified"
            or not isinstance(value["result"], dict)
        ):
            raise ActivationError("rotation_native_admin_response_unconfirmed")
        self.record(role + "-result", value)
        self.remove(role)
        return value["result"]

    def execute(self):
        c = self.c
        self.admit()
        if c.store.review()["resources"]:
            raise ActivationError("rotation_native_new_operation_required")
        fence = c.path.parent / "native-rotation-requested.json"
        _write(
            fence,
            json.dumps(
                {
                    "package_sha256": c.package_sha256,
                    "operation_id": c.operation,
                    "expires_at": c.expires.isoformat(),
                },
                sort_keys=True,
            ).encode(),
        )
        baseline, stages, failed, interrupted, cleanup = None, {}, None, None, None
        binding = "not_requested"
        phase, failure_phase = "provenance", None
        try:
            image.review(
                c.package["build_inputs"], self.images["runner"], c.artifact["tool_commit"]
            )
            postgres.review(
                self.images["postgres"],
                c.package["postgres_origin"],
                docker=lambda args: self._rpc(args),
            )
            physical.review_image(
                self.images["runner"],
                docker=SimpleNamespace(
                    query=lambda kind, image: self._rpc(physical.command(kind, image))
                ),
            )
            database.review_image(
                self.images["postgres"],
                docker=SimpleNamespace(
                    query=lambda kind, image: self._rpc(database.command(kind, image))
                ),
            )
            self.facts()
            phase = "network"
            self.bridge()
            phase = "database"
            policy.prepare(c.store, root=self.policy_root)
            self.create("db")
            self.start("db")
            phase = "review-before"
            stages["review-before"] = self.call("review-before", None)
            baseline = stages["review-before"].get("baseline")
            if not isinstance(baseline, dict) or set(baseline) != {"bundle", "inventory_sha256"}:
                raise ActivationError("rotation_native_baseline_unconfirmed")
            _hash(baseline["inventory_sha256"])
            if (
                baseline["bundle"].get("old_descriptor_sha256")
                != c.artifact["pki"]["old_descriptor_sha256"]
            ):
                raise ActivationError("rotation_native_baseline_binding_changed")
            identity, _ = persisted_review.expected_proofs(
                baseline["bundle"], digest(baseline["bundle"])
            )
            if identity.model_dump(mode="json") != persisted_review.RunnerIdentity.model_validate(
                c.artifact["pki"]["identities"]
            ).model_dump(mode="json"):
                raise ActivationError("rotation_native_baseline_identity_changed")
            phase = "runner-before"
            self.create("rotation-runner-before")
            self.start("rotation-runner-before")
            phase = "identity-before"
            stages["identity-before"] = self.call("identity-before", baseline)
            if digest(stages["identity-before"]) != digest(
                {
                    "candidate_identity_verified": True,
                    "previous_server_trust_rejected": True,
                    "jobs_requested": False,
                }
            ):
                raise ActivationError("rotation_native_identity_unconfirmed")
            phase = "runner-before-cleanup"
            self.remove("rotation-runner-before")
            phase = "binding"
            binding = "unconfirmed"
            stages["binding"] = self.call("binding", baseline)
            if digest(stages["binding"]) != digest(
                {
                    "binding_registered_revoked": True,
                    "environment_version": baseline["bundle"]["environment_version"] + 1,
                    "preflight_verified": False,
                }
            ):
                raise ActivationError("rotation_native_binding_unconfirmed")
            binding = "committed_revoked"
            phase = "runner-after"
            self.create("rotation-runner-after")
            self.start("rotation-runner-after")
            phase = "preflight"
            stages["preflight"] = self.call("preflight", baseline)
            if digest(stages["preflight"]) != digest(
                stages["binding"] | {"preflight_verified": True}
            ):
                raise ActivationError("rotation_native_preflight_unconfirmed")
            phase = "runner-after-cleanup"
            self.remove("rotation-runner-after")
            phase = "review-after"
            stages["review-after"] = self.call("review-after", baseline)
            if digest(stages["review-after"]) != digest(
                {
                    "continuity_verified": True,
                    "inventory_sha256": baseline["inventory_sha256"],
                    "environment_version": baseline["bundle"]["environment_version"] + 1,
                }
            ):
                raise ActivationError("rotation_native_final_continuity_unconfirmed")
            phase = "final-review"
            self.facts()
        except Exception:
            failed, failure_phase = "native_rotation_phase_unconfirmed", phase
        except BaseException as error:
            failed, interrupted = "native_rotation_interrupted", error
            failure_phase = phase
        finally:
            try:
                cleanup = closure.cleanup(
                    c.store, self.images, docker=self.cleaner, ownership_docker=self.owners
                )
            except BaseException as error:
                failed = failed or "native_rotation_cleanup_unconfirmed"
                failure_phase = failure_phase or "cleanup"
                if not isinstance(error, Exception):
                    interrupted = interrupted or error
        closed = (
            cleanup is not None
            and cleanup["managed_resources_absence_verified"] is True
            and cleanup["operation_closed"] is True
        )
        if not closed:
            failed = failed or "native_rotation_cleanup_unconfirmed"
            failure_phase = failure_phase or "cleanup"
        if closed:
            try:
                if metadata.metadata(self.images, docker=self.meta) != c.artifact["metadata"]:
                    raise ActivationError("rotation_native_final_inventory_changed")
            except Exception:
                failed = failed or "native_rotation_final_inventory_unconfirmed"
                failure_phase = failure_phase or "final-inventory"
        verified = failed is None and closed and binding == "committed_revoked"
        receipt = {
            "format": "aegis-native-rotation-receipt/1",
            "operation_id": c.operation,
            "begin_sha256": c.begin_sha256,
            "package_sha256": c.package_sha256,
            "status": "native_rotation_verified_and_closed"
            if verified
            else "native_rotation_failed_and_closed"
            if closed
            else "native_rotation_cleanup_unconfirmed",
            "error": failed,
            "failure_phase": failure_phase,
            "binding_commit_state": binding,
            "stages": {k: digest(v) for k, v in stages.items()},
            "managed_resources_absence_verified": closed,
            "activation_verified": verified,
            "previous_client_rejection_verified": False,
            "all_tls_controls_verified": False,
            "normal_operation_permitted": False,
            "marker_executed": False,
            "worker_started": False,
            "volumes_removed": False,
        }
        self.record("receipt", receipt)
        if interrupted is not None:
            raise interrupted
        return receipt
