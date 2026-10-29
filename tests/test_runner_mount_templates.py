"""Real Docker CLI formatting against a local fake HTTP daemon; no Docker resources."""

import copy
import json
import socketserver
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest
from test_runner_activation_database_inspection import OBJECT, inspection, projection
from test_runner_activation_database_server import IMAGE
from test_runner_activation_database_server import prepared as prepared


@pytest.fixture
def render():
    if not Path("/usr/bin/docker").is_file():
        pytest.skip("Docker CLI absent; fake Unix daemon never uses the real daemon")
    # Short socket path: pytest's nested temporary directory can exceed Unix limits.
    with tempfile.TemporaryDirectory(prefix="aegis-format-") as name:
        root = Path(name)
        calls, documents = [], []

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                calls.append((self.command, self.path))
                if self.path != "/_ping":
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("API-Version", "1.44")
                self.end_headers()

            def do_GET(self):
                calls.append((self.command, self.path))
                if self.path == "/_ping":
                    body = b"OK"
                elif self.path == "/v1.44/containers/" + OBJECT + "/json":
                    body = json.dumps(documents[-1]).encode()
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        with socketserver.UnixStreamServer(str(root / "daemon.sock"), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
            thread.start()

            def invoke(template, mounts=None, *, expect_success=True, document=None):
                documents.append(
                    document
                    if document is not None
                    else {"Id": OBJECT, "HostConfig": {"Mounts": mounts}}
                )
                result = subprocess.run(
                    [
                        "/usr/bin/docker",
                        "--config",
                        str(root),
                        "--host",
                        "unix://" + str(root / "daemon.sock"),
                        "container",
                        "inspect",
                        "--format",
                        template,
                        OBJECT,
                    ],
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "DOCKER_API_VERSION": "1.44"},
                    capture_output=True,
                    timeout=5,
                )
                request = ("GET", "/v1.44/containers/" + OBJECT + "/json")
                assert calls.count(request) == len(documents)
                assert set(calls) <= {request, ("GET", "/_ping"), ("HEAD", "/_ping")}
                if not expect_success:
                    assert result.returncode != 0
                    return None
                assert result.returncode == 0, "Synthetic Docker formatting failed"
                assert result.stderr == b""
                return json.loads(result.stdout)

            try:
                yield invoke
            finally:
                server.shutdown()
                thread.join(timeout=2)
                assert not thread.is_alive()


def mounts(spec):
    return [
        {
            "Type": "volume",
            "Source": inspection.server.VOLUME,
            "Target": inspection.server.DATA,
            "VolumeOptions": {"NoCopy": True},
            # ReadOnly=false and BindOptions are omitted by the mount API.
        },
        {
            "Type": "bind",
            "Source": spec["policy_path"],
            "Target": inspection.server.HBA,
            "ReadOnly": True,
            "BindOptions": {"Propagation": "rprivate"},
            # VolumeOptions is omitted for this bind.
        },
    ]


@pytest.mark.parametrize("selector", ["ReadOnly", "BindOptions", "VolumeOptions"])
def test_real_cli_reproduces_legacy_missing_selector_failure(prepared, render, selector):
    store, root = prepared
    spec = inspection.server.recipe(store, IMAGE, policy_root=root)
    # All three optional fields are missing from at least one legitimate mount.
    # index .HostConfig selects the CLI's raw-map formatter, just as the real
    # projection does. Typed struct formatting would supply zero defaults.
    legacy = '{{range $m := (index .HostConfig "Mounts")}}{{json $m.' + selector + "}}{{end}}"
    render(legacy, mounts(spec), expect_success=False)


@pytest.mark.parametrize("explicit_false", [False, True])
def test_cli_renders_omitted_mount_options_without_relaxing_policy(
    prepared, render, explicit_false
):
    store, root = prepared
    spec = inspection.server.recipe(store, IMAGE, policy_root=root)
    raw = mounts(spec)
    if explicit_false:
        raw[0]["ReadOnly"] = False
    result = render(inspection._mounts(spec, effective=False), raw)
    item = projection(spec, "created")
    assert result == item["configured_mounts"]
    item["configured_mounts"] = result
    inspection.validate(spec, item, OBJECT, "created")
    assert spec["policy_path"] not in json.dumps(result)


@pytest.mark.parametrize(
    "scene", ["copy", "empty_options", "readonly_data", "writable_hba", "shared"]
)
def test_cli_defaults_do_not_accept_unsafe_mounts(prepared, render, scene):
    store, root = prepared
    spec = inspection.server.recipe(store, IMAGE, policy_root=root)
    raw = copy.deepcopy(mounts(spec))
    if scene == "copy":
        del raw[0]["VolumeOptions"]
    elif scene == "empty_options":
        raw[0]["VolumeOptions"] = {}
    elif scene == "readonly_data":
        raw[0]["ReadOnly"] = True
    elif scene == "writable_hba":
        del raw[1]["ReadOnly"]
    else:
        raw[1]["BindOptions"]["Propagation"] = "rshared"
    item = projection(spec, "created")
    item["configured_mounts"] = render(inspection._mounts(spec, effective=False), raw)
    with pytest.raises(inspection.ActivationError, match="mount_mismatch"):
        inspection.validate(spec, item, OBJECT, "created")


@pytest.mark.parametrize("phase", ["created", "running"])
def test_complete_database_projection_uses_real_cli_with_synthetic_metadata(
    prepared, render, phase
):
    store, root = prepared
    spec = inspection.server.recipe(store, IMAGE, policy_root=root)
    expected = projection(spec, phase)
    effective = []
    for mount in mounts(spec):
        effective.append(
            {
                "Type": mount["Type"],
                "Name": mount["Source"] if mount["Type"] == "volume" else "",
                "Source": mount["Source"],
                "Destination": mount["Target"],
                "RW": not mount.get("ReadOnly", False),
                "Propagation": mount.get("BindOptions", {}).get("Propagation", ""),
            }
        )
    raw = {
        "Id": OBJECT,
        "Name": expected["name"],
        "Image": IMAGE,
        "Config": {
            "Image": IMAGE,
            "User": "70:70",
            "Entrypoint": spec["entrypoint"],
            "Cmd": spec["arguments"],
            "WorkingDir": "/",
            "OpenStdin": False,
            "Tty": False,
            "Healthcheck": {"Test": ["NONE"]},
            "StopTimeout": 5,
            "StopSignal": "SIGTERM",
            "ExposedPorts": {"5432/tcp": {}},
            "Volumes": {inspection.server.DATA: {}},
            "Labels": spec["labels"],
            "Env": [key + "=" + values[0] for key, values in inspection.ENV_FIXED.items()],
        },
        "HostConfig": {
            **spec["host"],
            **dict.fromkeys(inspection.probe.HOST_EMPTY),
            "Mounts": mounts(spec),
        },
        "State": {
            "Status": phase,
            "Running": phase == "running",
            "Restarting": False,
            "Paused": False,
            "OOMKilled": False,
            "ExitCode": 0,
            "Error": "",
        },
        "Mounts": effective,
        "NetworkSettings": {"Ports": None, "Networks": {"none": {}}},
    }
    item = render(inspection.container_format(spec), document=raw)
    expected["ports"] = None
    assert item == expected
    inspection.validate(spec, item, OBJECT, phase)
    assert spec["policy_path"] not in json.dumps(item)
