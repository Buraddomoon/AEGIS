"""Read-only identity reconciliation for exactly named activation resources."""

import re
import subprocess

from runner_activation_intents import resource
from runner_activation_metadata import MAX_OUTPUT, ActivationError, _execute, document

CONTAINER_FORMAT = '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"running":{{json .State.Running}},'
NETWORK_FORMAT = '{"id":{{json .Id}},"name":{{json .Name}},"member_count":{{len .Containers}},'
LABELS = {
    "project": "com.docker.compose.project",
    "operation": "io.aegis.activation-id",
    "plan": "io.aegis.activation-plan-sha256",
    "role": "io.aegis.activation-role",
    "ownership": "io.aegis.activation-resource",
}


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch("[a-f0-9]{64}", value):
        raise ActivationError("ownership_full_resource_id_required")
    return value


def command(kind, operation_id, plan_sha256, role, known_id=None):
    expected = resource(operation_id, plan_sha256, role)
    base = ("network", "ls") if expected["kind"] == "network" else ("ps", "--all")
    base += ("--no-trunc", "--quiet")
    if kind == "name":
        # Substring matching is documented for both APIs. Similar names may
        # conservatively block; inspect must still prove the exact name.
        return (*base, "--filter", "name=" + expected["name"])
    if kind == "labels":
        # One composite label avoids depending on AND/OR semantics for repeated
        # label filters. All individual labels are then verified in inspect.
        key = "io.aegis.activation-resource"
        return (*base, "--filter", "label=" + key + "=" + expected["labels"][key])
    if kind == "known":
        return (*base, "--filter", "id=" + identifier(known_id))
    if kind == "inspect" and known_id is None:
        container = expected["kind"] == "container"
        prefix = ".Config.Labels" if container else ".Labels"
        fields = [
            f'"{key}":{{{{json (index {prefix} "{label}")}}}}' for key, label in LABELS.items()
        ]
        template = (CONTAINER_FORMAT if container else NETWORK_FORMAT) + ",".join(fields) + "}"
        return (expected["kind"], "inspect", "--format", template, expected["name"])
    raise ActivationError("ownership_query_not_allowed")


class OwnershipDocker:
    def query(self, kind, operation_id, plan_sha256, role, known_id=None):
        try:
            return _execute(command(kind, operation_id, plan_sha256, role, known_id))
        except ActivationError:
            raise
        except (OSError, subprocess.SubprocessError):
            raise ActivationError("ownership_query_failed") from None


def _ids(raw):
    try:
        if len(raw) > MAX_OUTPUT:
            raise ActivationError("ownership_projection_limit")
        values = raw.decode("ascii").splitlines()
    except (AttributeError, UnicodeError):
        raise ActivationError("ownership_id_projection_invalid") from None
    if len(values) > 1:
        raise ActivationError("ownership_ambiguous_resources")
    return tuple(identifier(value) for value in values)


def observe(operation_id, plan_sha256, role, known_id=None, *, docker=None):
    expected = resource(operation_id, plan_sha256, role)
    if known_id is not None:
        identifier(known_id)
    docker = docker or OwnershipDocker()

    def query(kind, value=None):
        return docker.query(kind, operation_id, plan_sha256, role, value)

    def sample():
        named, labelled = _ids(query("name")), _ids(query("labels"))
        known = _ids(query("known", known_id)) if known_id else named
        if named != labelled or named != known:
            raise ActivationError("ownership_identity_ambiguous")
        if known_id and named and named[0] != known_id:
            raise ActivationError("ownership_recorded_id_changed")
        return named

    first = sample()
    details = None
    if first:
        details = document(query("inspect"))
        fields = {"id", "name", *LABELS}
        fields |= {"image", "running"} if expected["kind"] == "container" else {"member_count"}
        if (
            not isinstance(details, dict)
            or set(details) != fields
            or details["id"] != first[0]
            or details["name"]
            != ("/" if expected["kind"] == "container" else "") + expected["name"]
            or any(details[key] != expected["labels"][label] for key, label in LABELS.items())
        ):
            raise ActivationError("ownership_inspection_mismatch")
        if expected["kind"] == "container":
            if (
                type(details["running"]) is not bool
                or not isinstance(details["image"], str)
                or not re.fullmatch("sha256:[a-f0-9]{64}", details["image"])
            ):
                raise ActivationError("ownership_container_projection_invalid")
        elif type(details["member_count"]) is not int or not 0 <= details["member_count"] <= 1024:
            raise ActivationError("ownership_network_projection_invalid")
    if sample() != first:
        raise ActivationError("ownership_changed_during_review")
    return {
        "format": "aegis-activation-ownership-review/1",
        "operation_id": operation_id,
        "plan_sha256": plan_sha256,
        "role": role,
        "name": expected["name"],
        "kind": expected["kind"],
        "status": "present_owned_snapshot" if first else "absent_snapshot",
        "resource_id": first[0] if first else None,
        "details": details,
        "stopped_or_empty_snapshot": bool(
            details
            and (
                not details["running"]
                if expected["kind"] == "container"
                else details["member_count"] == 0
            )
        ),
        "runtime_mounts_verified": False,
        "network_isolation_verified": False,
        "effects_authorized": False,
        "normal_operation_permitted": False,
    }
