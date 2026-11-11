"""Durable host-only resource ownership records; no Docker or activation executor."""

import fcntl
import json
import os
import re
import stat
from datetime import datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import runner_pki as pki
from aegis.domain.validation import digest
from runner_activation_metadata import PROJECT, ActivationError, document

FORMAT = "aegis-activation-resource-event/1"
DATABASE_REVIEW_ROLES = frozenset({"database-review-before", "database-review-after"})
IDENTITY_CLIENT_ROLE = "identity-client"
ROTATION_HELPERS = frozenset(
    "rotation-" + mode
    for mode in (
        "review-before",
        "identity-before",
        "binding",
        "preflight",
        "review-after",
    )
)
ROTATION_RUNNERS = frozenset({"rotation-runner-before", "rotation-runner-after"})
ROLES = frozenset(
    (
        "db",
        "redis",
        "api",
        "runner",
        IDENTITY_CLIENT_ROLE,
        "journal-before",
        "journal-after",
        *DATABASE_REVIEW_ROLES,
        *ROTATION_HELPERS,
        *ROTATION_RUNNERS,
        "network-backend",
        "network-ingress",
        "network-isolated",
    )
)
FLAGS = {
    "authorization_verified": False,
    "activation_verified": False,
    "daemon_absence_verified": False,
    "normal_operation_permitted": False,
}
MAX_EVENTS = 64
DEFAULT_ROOT = Path(__file__).resolve().parents[1] / ".local/pki-activation-intents"


def _hash(value):
    if not isinstance(value, str) or not re.fullmatch("[a-f0-9]{64}", value):
        raise ActivationError("intent_hash_required")
    return value


def _identifier(value):
    try:
        valid = isinstance(value, str) and UUID(hex=value).hex == value
    except ValueError:
        valid = False
    if not valid:
        raise ActivationError("intent_identifier_invalid")
    return value


def resource(identifier, plan_sha256, role):
    _identifier(identifier)
    _hash(plan_sha256)
    if role not in ROLES:
        raise ActivationError("intent_resource_not_allowed")
    network = role.startswith("network-")
    return {
        "role": role,
        "kind": "network" if network else "container",
        "name": PROJECT + "_" + role.removeprefix("network-")
        if network
        else PROJECT + "-activation-" + identifier + "-" + role,
        "labels": {
            "com.docker.compose.project": PROJECT,
            "io.aegis.activation-id": identifier,
            "io.aegis.activation-plan-sha256": plan_sha256,
            "io.aegis.activation-role": role,
            "io.aegis.activation-resource": identifier + ":" + role,
        },
    }


def _dependents(role, owned):
    if role.startswith("network-"):
        return {key for key in owned if not key.startswith("network-")}
    if role == "db":
        return {"api", *DATABASE_REVIEW_ROLES, *ROTATION_HELPERS}
    if role == "rotation-runner-before":
        return {"rotation-identity-before"}
    if role == "rotation-runner-after":
        return {"rotation-preflight"}
    if role == "runner":
        return {"api", IDENTITY_CLIENT_ROLE}
    return {"api"} if role == "redis" else set()


def _identity_parents(owned):
    runner, network = owned.get("runner", {}), owned.get("network-isolated", {})
    if (
        runner.get("state") != "OBSERVED"
        or runner.get("resource_id") is None
        or runner.get("start", {}).get("mode") != "identity-only"
        or "runtime_evidence_sha256" not in runner
        or network.get("state") != "OBSERVED"
        or network.get("resource_id") is None
        or runner["start"].get("network_resource_id") != network["resource_id"]
        or any(
            key not in {"runner", "network-isolated", IDENTITY_CLIENT_ROLE}
            and value["state"] != "ABSENT"
            for key, value in owned.items()
        )
    ):
        raise ActivationError("intent_observed_identity_server_required")
    return runner, network


def _require_no_dependents(role, owned):
    if any(key in owned and owned[key]["state"] != "ABSENT" for key in _dependents(role, owned)):
        raise ActivationError("intent_dependencies_retained")


def _apply(state, event, identifier):
    kind, data = event["kind"], event["data"]
    if state["closed"]:
        raise ActivationError("intent_already_closed")
    if kind == "begin":
        if state["header"] is not None or set(data) != {"plan_id", "plan_sha256", "scope_sha256"}:
            raise ActivationError("intent_header_invalid")
        _identifier(data["plan_id"])
        _hash(data["plan_sha256"])
        _hash(data["scope_sha256"])
        state["header"] = data
        return
    if state["header"] is None:
        raise ActivationError("intent_header_required")
    if kind == "rotation_scope_confirmed":
        if (
            "rotation_scope" in state
            or state["resources"]
            or set(data) != {"package_sha256", "expires_at"}
        ):
            raise ActivationError("intent_rotation_scope_invalid_or_replay")
        _hash(data["package_sha256"])
        stamp = datetime.fromisoformat(data["expires_at"])
        at = datetime.fromisoformat(event["at"])
        if stamp.utcoffset() != timedelta(0) or not timedelta(0) < stamp - at <= timedelta(
            seconds=240
        ):
            raise ActivationError("intent_rotation_scope_expiration_invalid")
        state["rotation_scope"] = data
        return
    owned = state["resources"]
    if kind == "closed":
        if set(data) != {"evidence_sha256"} or any(
            item["state"] != "ABSENT" for item in owned.values()
        ):
            raise ActivationError("intent_unresolved_resources")
        _hash(data["evidence_sha256"])
        state["closed"] = True
        return
    role = data["role"]
    if role not in ROLES:
        raise ActivationError("intent_resource_not_allowed")
    if kind == "create_requested":
        if role in owned or data != resource(identifier, state["header"]["plan_sha256"], role):
            raise ActivationError("intent_duplicate_or_foreign_resource")
        # New work must not resurrect dependents during/after their dependency's
        # cleanup. Journal probes are network=none in the future fixed profile.
        parents = {"db", "redis", "runner"} if role == "api" else set()
        if role in ROTATION_HELPERS | ROTATION_RUNNERS and "rotation_scope" not in state:
            raise ActivationError("intent_rotation_scope_required")
        if role == IDENTITY_CLIENT_ROLE:
            _identity_parents(owned)
            parents |= {"runner", "network-isolated"}
        if role in DATABASE_REVIEW_ROLES:
            database = owned.get("db")
            if (
                database is None
                or database["state"] != "OBSERVED"
                or database["resource_id"] is None
            ):
                raise ActivationError("intent_observed_database_required")
            parents.add("db")
        if role in ROTATION_HELPERS:
            database = owned.get("db", {})
            if (
                database.get("state") != "OBSERVED"
                or database.get("start", {}).get("mode") != "rotation"
            ):
                raise ActivationError("intent_rotation_database_required")
            parents.add("db")
        if role in {"db", "redis", "api", "runner", *ROTATION_RUNNERS}:
            parents |= {key for key in owned if key.startswith("network-")}
        if any(
            key in owned and owned[key]["state"] in {"REMOVAL_REQUESTED", "ABSENT", "CONFLICT"}
            for key in parents
        ):
            raise ActivationError("intent_dependency_is_closing")
        owned[role] = {"state": "REQUESTED", "resource_id": None}
        return
    if role not in owned:
        raise ActivationError("intent_ownership_required")
    item = owned[role]
    if kind == "ownership_conflict":
        if (
            set(data) != {"role", "evidence_sha256"}
            or item["state"] != "REQUESTED"
            or item["resource_id"] is not None
        ):
            raise ActivationError("intent_conflict_invalid")
        _hash(data["evidence_sha256"])
        item["state"] = "CONFLICT"
        item["conflict_evidence_sha256"] = data["evidence_sha256"]
    elif kind == "observed":
        if (
            set(data) != {"role", "resource_id"}
            or item["state"] not in {"REQUESTED", "REMOVAL_REQUESTED"}
            or item["resource_id"] is not None
            or not isinstance(data["resource_id"], str)
            or not re.fullmatch("[a-f0-9]{64}", data["resource_id"])
        ):
            raise ActivationError("intent_observation_invalid")
        if any(other["resource_id"] == data["resource_id"] for other in owned.values()):
            raise ActivationError("intent_resource_id_reused")
        if item["state"] == "REQUESTED":
            item["state"] = "OBSERVED"
        item["resource_id"] = data["resource_id"]
    elif kind == "rotation_start_requested":
        if (
            role not in {"db", *ROTATION_HELPERS, *ROTATION_RUNNERS}
            or "rotation_scope" not in state
            or set(data) != {"role", "recipe_sha256", "gates_sha256"}
            or item["state"] != "OBSERVED"
            or item["resource_id"] is None
            or "start" in item
        ):
            raise ActivationError("intent_rotation_start_invalid_or_replay")
        _hash(data["recipe_sha256"])
        _hash(data["gates_sha256"])
        item["state"] = "START_REQUESTED"
        item["start"] = {
            "mode": "rotation",
            "recipe_sha256": data["recipe_sha256"],
            "gates_sha256": data["gates_sha256"],
        }
    elif kind == "rotation_runtime_observed":
        if (
            role not in {"db", *ROTATION_HELPERS, *ROTATION_RUNNERS}
            or set(data) != {"role", "runtime_evidence_sha256"}
            or item["state"] != "START_REQUESTED"
            or item.get("start", {}).get("mode") != "rotation"
        ):
            raise ActivationError("intent_rotation_runtime_invalid")
        _hash(data["runtime_evidence_sha256"])
        item["state"] = "OBSERVED"
        item["runtime_evidence_sha256"] = data["runtime_evidence_sha256"]
    elif kind == "database_start_requested":
        if (
            set(data) != {"role", "recipe_sha256", "gates_sha256", "policy_sha256"}
            or role != "db"
            or item["state"] != "OBSERVED"
            or item["resource_id"] is None
            or "start" in item
        ):
            raise ActivationError("intent_database_start_invalid_or_already_requested")
        for key in ("recipe_sha256", "gates_sha256", "policy_sha256"):
            _hash(data[key])
        _require_no_dependents(role, owned)
        item["state"] = "START_REQUESTED"
        item["start"] = {key: data[key] for key in data if key != "role"}
    elif kind == "database_runtime_observed":
        if (
            set(data) != {"role", "runtime_evidence_sha256"}
            or role != "db"
            or item["state"] != "START_REQUESTED"
            or item["resource_id"] is None
            or "start" not in item
            or "runtime_evidence_sha256" in item
        ):
            raise ActivationError("intent_database_runtime_observation_invalid")
        _hash(data["runtime_evidence_sha256"])
        item["state"] = "OBSERVED"
        item["runtime_evidence_sha256"] = data["runtime_evidence_sha256"]
    elif kind == "identity_start_requested":
        parent = owned.get("network-isolated")
        if (
            set(data)
            != {
                "role",
                "recipe_sha256",
                "gates_sha256",
                "pki_manifest_sha256",
                "network_resource_id",
                "mode",
            }
            or role != "runner"
            or data["mode"] != "identity-only"
            or item["state"] != "OBSERVED"
            or item["resource_id"] is None
            or "start" in item
            or parent is None
            or parent["state"] != "OBSERVED"
            or parent["resource_id"] != data["network_resource_id"]
            or any(
                key not in {"runner", "network-isolated"} and value["state"] != "ABSENT"
                for key, value in owned.items()
            )
        ):
            raise ActivationError("intent_identity_start_invalid_or_already_requested")
        for key in ("recipe_sha256", "gates_sha256", "pki_manifest_sha256", "network_resource_id"):
            _hash(data[key])
        item["state"] = "START_REQUESTED"
        item["start"] = {key: value for key, value in data.items() if key != "role"}
    elif kind == "identity_runtime_observed":
        if (
            set(data) != {"role", "runtime_evidence_sha256"}
            or role != "runner"
            or item["state"] != "START_REQUESTED"
            or item.get("start", {}).get("mode") != "identity-only"
            or item["resource_id"] is None
            or "runtime_evidence_sha256" in item
        ):
            raise ActivationError("intent_identity_runtime_observation_invalid")
        _hash(data["runtime_evidence_sha256"])
        item["state"] = "OBSERVED"
        item["runtime_evidence_sha256"] = data["runtime_evidence_sha256"]
    elif kind == "identity_client_start_requested":
        runner, network = _identity_parents(owned)
        if (
            set(data)
            != {
                "role",
                "recipe_sha256",
                "gates_sha256",
                "request_context_sha256",
                "runner_resource_id",
                "network_resource_id",
            }
            or role != IDENTITY_CLIENT_ROLE
            or item["state"] != "OBSERVED"
            or item["resource_id"] is None
            or "start" in item
            or data["runner_resource_id"] != runner["resource_id"]
            or data["network_resource_id"] != network["resource_id"]
        ):
            raise ActivationError("intent_identity_client_start_invalid_or_already_requested")
        for key in set(data) - {"role"}:
            _hash(data[key])
        item["state"] = "START_REQUESTED"
        item["start"] = {key: value for key, value in data.items() if key != "role"}
    elif kind == "identity_client_reply_observed":
        if (
            set(data) != {"role", "result_sha256", "runtime_evidence_sha256"}
            or role != IDENTITY_CLIENT_ROLE
            or item["state"] != "START_REQUESTED"
            or "request_context_sha256" not in item.get("start", {})
            or item["resource_id"] is None
        ):
            raise ActivationError("intent_identity_client_reply_observation_invalid")
        for key in ("result_sha256", "runtime_evidence_sha256"):
            _hash(data[key])
            item[key] = data[key]
        item["state"] = "OBSERVED"
    elif kind in {"probe_start_requested", "database_review_start_requested"}:
        database_review = kind == "database_review_start_requested"
        context_field = "request_context_sha256" if database_review else "proof_bundle_sha256"
        allowed_roles = (
            DATABASE_REVIEW_ROLES if database_review else {"journal-before", "journal-after"}
        )
        if (
            set(data) != {"role", "recipe_sha256", "gates_sha256", context_field}
            or role not in allowed_roles
            or item["state"] != "OBSERVED"
            or item["resource_id"] is None
        ):
            raise ActivationError("intent_probe_start_invalid_or_already_requested")
        if database_review and owned["db"]["state"] != "OBSERVED":
            raise ActivationError("intent_observed_database_required")
        for key in ("recipe_sha256", "gates_sha256", context_field):
            _hash(data[key])
        # Durable intent is deliberately not a success record. A resumed
        # START_REQUESTED may have had an effect; only reconciliation/cleanup
        # can follow, never another start.
        item["state"] = "START_REQUESTED"
        item["start"] = {key: data[key] for key in data if key != "role"}
    elif kind == "removal_requested":
        if set(data) != {"role"} or item["state"] not in {
            "REQUESTED",
            "OBSERVED",
            "START_REQUESTED",
        }:
            raise ActivationError("intent_removal_invalid")
        _require_no_dependents(role, owned)
        item["state"] = "REMOVAL_REQUESTED"
    elif kind == "absence_recorded":
        if set(data) != {"role", "evidence_sha256"} or item["state"] != "REMOVAL_REQUESTED":
            raise ActivationError("intent_absence_requires_removal")
        _hash(data["evidence_sha256"])
        _require_no_dependents(role, owned)
        item["state"] = "ABSENT"
    else:
        raise ActivationError("intent_event_not_allowed")


def _load(folder):
    pki.private_directory(folder)
    identifier = _identifier(folder.name)
    names = sorted(os.listdir(folder))
    if not 1 <= len(names) <= MAX_EVENTS or names != [
        f"{index:04}.json" for index in range(len(names))
    ]:
        raise ActivationError("intent_partial_or_unexpected_history")
    events = []
    state = {"header": None, "resources": {}, "closed": False}
    previous = None
    for index, name in enumerate(names):
        path = folder / name
        event = document(pki.read(path, modes=(0o600,), maximum=16384))
        if (
            not isinstance(event, dict)
            or set(event) != {"format", "id", "sequence", "at", "previous_sha256", "kind", "data"}
            or event["format"] != FORMAT
            or event["id"] != identifier
            or type(event["sequence"]) is not int
            or event["sequence"] != index
            or event["previous_sha256"] != previous
            or not isinstance(event["data"], dict)
        ):
            raise ActivationError("intent_history_invalid")
        if datetime.fromisoformat(event["at"]).utcoffset() != timedelta(0):
            raise ActivationError("intent_timestamp_invalid")
        _apply(state, event, identifier)
        events.append(event)
        previous = digest(event)
    return events, state


class ActivationIntents:
    """Caller must independently authorize effects and verify daemon observations."""

    def __init__(self, root: Path = DEFAULT_ROOT):
        self.root = pki.private_directory(root, create=True)
        self.root_info = self.root.stat()
        self.folder = None
        self.events = []
        self.state = None
        self.poisoned = False
        self.fd = os.open(
            self.root / "operation.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
        try:
            info = os.fstat(self.fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size
            ):
                raise ActivationError("intent_lock_unsafe")
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ActivationError("intent_operation_busy") from None
            os.fsync(self.fd)
            pki.sync(self.root)
        except BaseException:
            os.close(self.fd)
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        os.close(self.fd)
        self.fd = None

    def _check(self):
        if self.fd is None or self.poisoned:
            raise ActivationError("intent_session_not_writable")
        current = os.stat(self.root / "operation.lock", follow_symlinks=False)
        locked = os.fstat(self.fd)
        directory = self.root.stat(follow_symlinks=False)
        if (
            (current.st_dev, current.st_ino, current.st_nlink)
            != (
                locked.st_dev,
                locked.st_ino,
                1,
            )
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_uid != os.getuid()
            or current.st_size
            or (
                directory.st_dev,
                directory.st_ino,
                stat.S_IMODE(directory.st_mode),
                directory.st_uid,
            )
            != (self.root_info.st_dev, self.root_info.st_ino, 0o700, os.getuid())
        ):
            raise ActivationError("intent_lock_or_directory_changed")

    def _histories(self):
        names = set(os.listdir(self.root)) - {"operation.lock"}
        if len(names) > 1024:
            raise ActivationError("intent_history_review_limit")
        return {name: _load(self.root / name) for name in names}

    def begin(self, plan_id, plan_sha256, scope_sha256):
        self._check()
        _identifier(plan_id)
        _hash(plan_sha256)
        _hash(scope_sha256)
        if self.folder is not None or any(
            not state["closed"] for _, state in self._histories().values()
        ):
            raise ActivationError("intent_prior_operation_unresolved")
        self.folder = self.root / uuid4().hex
        self.folder.mkdir(mode=0o700)
        self.state = {"header": None, "resources": {}, "closed": False}
        return self.append(
            "begin", {"plan_id": plan_id, "plan_sha256": plan_sha256, "scope_sha256": scope_sha256}
        )

    def has_plan_history(self, plan_sha256):
        """Under the exclusive project lock, include closed/empty attempts too."""
        self._check()
        _hash(plan_sha256)
        return any(
            state["header"]["plan_sha256"] == plan_sha256 for _, state in self._histories().values()
        )

    def resume(self, identifier, expected_begin_sha256):
        self._check()
        _identifier(identifier)
        _hash(expected_begin_sha256)
        histories = self._histories()
        if (
            self.folder is not None
            or identifier not in histories
            or any(
                not state["closed"] for key, (_, state) in histories.items() if key != identifier
            )
        ):
            raise ActivationError("intent_resume_not_exclusive")
        events, state = histories[identifier]
        if digest(events[0]) != expected_begin_sha256:
            raise ActivationError("intent_origin_integrity_mismatch")
        self.folder, self.events, self.state = self.root / identifier, events, state
        # A prior fsync error must not become implicitly durable on retry.
        try:
            for index in range(len(events)):
                fd = os.open(self.folder / f"{index:04}.json", os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            pki.sync(self.folder)
            pki.sync(self.root)
        except BaseException:
            self.poisoned = True
            raise
        return self.summary()

    def append(self, kind, data):
        self._check()
        if self.folder is None or len(self.events) >= MAX_EVENTS:
            raise ActivationError("intent_session_or_limit_invalid")
        if self.events:
            self.review()
        event = {
            "format": FORMAT,
            "id": self.folder.name,
            "sequence": len(self.events),
            "at": pki.clock().isoformat(),
            "previous_sha256": digest(self.events[-1]) if self.events else None,
            "kind": kind,
            "data": json.loads(json.dumps(data)),
        }
        # Validate the prospective event before making an immutable filesystem record.
        state = json.loads(json.dumps(self.state))
        _apply(state, event, self.folder.name)
        try:
            fd = os.open(
                self.folder / f"{len(self.events):04}.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "w") as output:
                json.dump(event, output, sort_keys=True)
                output.flush()
                os.fsync(output.fileno())
            pki.sync(self.folder)
            pki.sync(self.root)
        except BaseException:
            self.poisoned = True
            raise
        self.events.append(event)
        self.state = state
        return {"event_sha256": digest(event), **self.summary()}

    def review(self):
        """Recheck durable ownership before an external effect, without appending."""
        self._check()
        if self.folder is None or not self.events:
            raise ActivationError("intent_header_required")
        events, state = _load(self.folder)
        if events != self.events or digest(state) != digest(self.state):
            raise ActivationError("intent_history_changed")
        return json.loads(json.dumps(state))

    def request(self, role):
        self._check()
        if self.folder is None:
            raise ActivationError("intent_header_required")
        return self.append(
            "create_requested",
            resource(self.folder.name, self.state["header"]["plan_sha256"], role),
        )

    def summary(self):
        if self.folder is None:
            raise ActivationError("intent_header_required")
        return {
            "format": "aegis-activation-intent-summary/1",
            "id": self.folder.name,
            "begin_sha256": digest(self.events[0]),
            "events": len(self.events),
            "status": "publication_unconfirmed_requires_resume"
            if self.poisoned
            else (
                "absence_recorded_not_runtime_verified"
                if self.state["closed"]
                else "resources_require_explicit_reconciliation"
            ),
            "session_write_failed": self.poisoned,
            "resources": json.loads(json.dumps(self.state["resources"])),
            **FLAGS,
        }
