"""Closed, read-only Docker queries for Linux PKI planning; never a lifecycle API."""

import json
import os
import re
import selectors
import subprocess
import tempfile
import time
from datetime import datetime

PROJECT = "aegis-linux-lab"
VOLUMES = ("journal", "postgres-data")
IMAGES = ("application", "runner", "postgres", "redis")
NETWORKS = ("backend", "ingress", "isolated")
MAX_OUTPUT = 65536
TIMEOUT = 10
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
DAEMON_FORMAT = '{"id":{{json .ID}},"os":{{json .OSType}},"architecture":{{json .Architecture}}}'
IMAGE_FORMAT = (
    '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}},'
    '"user":{{json (index .Config "User")}}}'
)
VOLUME_FORMAT = (
    '{"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}},'
    '"options":{{json .Options}},"created_at":{{json .CreatedAt}},'
    '"project":{{json (index .Labels "com.docker.compose.project")}},'
    '"volume":{{json (index .Labels "com.docker.compose.volume")}}}'
)


class ActivationError(ValueError):
    """Static, safe diagnostics only; never include daemon/file contents."""


def image_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
        raise ActivationError("explicit_local_image_id_required")
    return value


def command(kind, value=None):
    """No caller-supplied Docker arguments, format strings, project or endpoint."""
    if kind == "daemon" and value is None:
        return ("info", "--format", DAEMON_FORMAT)
    if kind == "image":
        return ("image", "inspect", "--format", IMAGE_FORMAT, image_id(value))
    if kind == "volume" and value in VOLUMES:
        return ("volume", "inspect", "--format", VOLUME_FORMAT, PROJECT + "_" + value)
    if kind == "containers" and value is None:
        return (
            "ps",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            "label=com.docker.compose.project=" + PROJECT,
        )
    if kind == "consumers" and value in VOLUMES:
        return (
            "ps",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            "volume=" + PROJECT + "_" + value,
        )
    if kind == "networks" and value is None:
        return (
            "network",
            "ls",
            "--quiet",
            "--no-trunc",
            "--filter",
            "label=com.docker.compose.project=" + PROJECT,
        )
    if kind == "network_name" and value in NETWORKS:
        return (
            "network",
            "ls",
            "--quiet",
            "--no-trunc",
            "--filter",
            "name=^" + PROJECT + "_" + value + "$",
        )
    raise ActivationError("docker_query_not_allowed")


def _execute(arguments, *, payload=None, timeout=None):
    # Private shared transport. Public read-only query adapters never supply stdin.
    # Only the closed journal lifecycle adapter supplies a proof bundle.
    if payload is not None and (type(payload) is not bytes or len(payload) > 4 * 1024**2):
        raise ActivationError("docker_input_invalid_or_excessive")
    budget = TIMEOUT if timeout is None else timeout
    if type(budget) not in (int, float) or not 0 < budget <= 20:
        raise ActivationError("docker_time_budget_invalid")
    # Never inherit contexts, DOCKER_HOST, plugins, proxies or CLI credentials.
    with tempfile.TemporaryDirectory(prefix="aegis-activation-docker-") as config:
        process = subprocess.Popen(
            [
                "/usr/bin/docker",
                "--config",
                config,
                "--host",
                "unix:///var/run/docker.sock",
                *arguments,
            ],
            stdin=subprocess.DEVNULL if payload is None else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=ENV,
        )
        try:
            output = bytearray()
            count = 0
            deadline = time.monotonic() + budget
            sent = 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                selector.register(process.stderr, selectors.EVENT_READ, "stderr")
                if payload:
                    os.set_blocking(process.stdin.fileno(), False)
                    selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                elif payload is not None:
                    process.stdin.close()
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ActivationError("docker_query_timed_out")
                    for key, _ in selector.select(remaining):
                        if key.data == "stdin":
                            try:
                                sent += os.write(key.fd, payload[sent : sent + 16384])
                            except BlockingIOError:
                                continue
                            except BrokenPipeError:
                                raise ActivationError("docker_input_delivery_unconfirmed") from None
                            if sent == len(payload):
                                selector.unregister(process.stdin)
                                process.stdin.close()
                            continue
                        chunk = os.read(key.fd, 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        count += len(chunk)
                        if count > MAX_OUTPUT:
                            raise ActivationError("docker_response_too_large")
                        if key.data == "stdout":
                            output.extend(chunk)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ActivationError("docker_query_timed_out")
                if process.wait(timeout=remaining):
                    raise ActivationError("docker_query_failed")
            return bytes(output)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
            process.stdout.close()
            process.stderr.close()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ActivationError("duplicate_json_field")
        result[key] = value
    return result


def document(content):
    if len(content) > MAX_OUTPUT:
        raise ActivationError("excessive_document")
    try:
        return json.loads(content, object_pairs_hook=_unique)
    except (ValueError, RecursionError, UnicodeError):
        raise ActivationError("invalid_json_document") from None


class ReadOnlyDocker:
    def query(self, kind, value=None):
        try:
            return _execute(command(kind, value))
        except ActivationError:
            raise
        except (OSError, subprocess.SubprocessError):
            raise ActivationError("docker_query_failed") from None


def metadata(images, *, docker=None):
    if not isinstance(images, dict) or set(images) != set(IMAGES):
        raise ActivationError("four_explicit_images_required")
    for value in images.values():
        image_id(value)
    if len(set(images.values())) != len(IMAGES):
        raise ActivationError("distinct_images_required")
    docker = docker or ReadOnlyDocker()
    daemon = document(docker.query("daemon"))
    if (
        not isinstance(daemon, dict)
        or set(daemon) != {"id", "os", "architecture"}
        or not isinstance(daemon["id"], str)
        or not re.fullmatch(r"[A-Za-z0-9:-]{16,128}", daemon["id"])
        or daemon["os"] != "linux"
        or daemon["architecture"] not in {"x86_64", "amd64", "aarch64", "arm64"}
    ):
        raise ActivationError("unreviewed_daemon")
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(
        daemon["architecture"], daemon["architecture"]
    )
    # Include stopped/created containers and consumers from other projects too.
    for kind, value in [
        ("containers", None),
        ("networks", None),
        *(("network_name", name) for name in NETWORKS),
        *(("consumers", name) for name in VOLUMES),
    ]:
        if docker.query(kind, value).strip():
            raise ActivationError("project_or_volume_not_quiescent")
    volumes = {}
    for name in VOLUMES:
        item = document(docker.query("volume", name))
        if (
            not isinstance(item, dict)
            or set(item)
            != {"name", "driver", "scope", "options", "created_at", "project", "volume"}
            or item["name"] != PROJECT + "_" + name
            or item["project"] != PROJECT
            or item["volume"] != name
            or item["driver"] != "local"
            or item["scope"] != "local"
            or item["options"] not in (None, {})
            or not isinstance(item["created_at"], str)
        ):
            raise ActivationError("volume_metadata_mismatch")
        try:
            if datetime.fromisoformat(item["created_at"]).utcoffset() is None:
                raise ValueError
        except ValueError:
            raise ActivationError("invalid_volume_creation_time") from None
        volumes[name] = {**item, "options": {}}
    inspected = {}
    for role in IMAGES:
        item = document(docker.query("image", images[role]))
        # Official DB/cache images may omit Config.User entirely. Docker then
        # defaults to root; application/runner must still explicitly be 10001.
        if isinstance(item, dict) and item.get("user") is None and role in {"postgres", "redis"}:
            item = {**item, "user": ""}
        if (
            not isinstance(item, dict)
            or set(item) != {"id", "os", "architecture", "user"}
            or item["id"] != images[role]
            or item["os"] != "linux"
            or item["architecture"] != architecture
            or item["user"]
            not in (
                {"10001:10001"} if role in {"application", "runner"} else {"", "0", "0:0", "root"}
            )
        ):
            raise ActivationError("image_metadata_mismatch")
        inspected[role] = item
    return {"daemon": daemon, "volumes": volumes, "images": inspected}
