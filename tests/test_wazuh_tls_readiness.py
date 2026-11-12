import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import wazuh_tls_readiness as readiness  # noqa: E402

CONTROL = {"error": 0, "data": {"id": "001", "name": "aegis-marker", "status": "Active"}}
HEADER = "  sl  local_address rem_address st tx_queue rx_queue\n"


def test_connected_agent_with_no_management_listener_is_ready_without_claiming_api_liveness():
    result = readiness.readiness(
        CONTROL, "# state\nstatus='connected'\nlast_ack='fixture'\n", HEADER
    )
    assert result["ready"]
    assert result["management"] == {
        "management_api_listening": False,
        "management_api_no_lan_listener": True,
        "management_api_loopback_verified": False,
    }


@pytest.mark.parametrize("address", ["0100007F", "00000000000000000000000001000000"])
def test_loopback_listener_is_recorded_separately(address):
    result = readiness.management_listeners(HEADER + f"0: {address}:D6D8 00000000:0000 0A\n")
    assert result["management_api_listening"] and result["management_api_loopback_verified"]


@pytest.mark.parametrize("address", ["00000000", "1300A8C0", "00000000000000000000000000000000"])
def test_any_management_lan_listener_still_blocks_readiness(address):
    with pytest.raises(ValueError, match="outside_loopback"):
        readiness.readiness(
            CONTROL, "status='connected'", HEADER + f"0: {address}:D6D8 00000000:0000 0A\n"
        )


@pytest.mark.parametrize(
    "mutation", ["error", "bool-error", "id", "name", "unknown-status", "missing-data"]
)
def test_missing_or_wrong_agent_facts_are_never_filled_from_context(mutation):
    value = copy.deepcopy(CONTROL)
    if mutation == "error":
        value["error"] = 1
    elif mutation == "bool-error":
        value["error"] = False
    elif mutation == "id":
        value["data"]["id"] = "002"
    elif mutation == "name":
        value["data"]["name"] = "other"
    elif mutation == "unknown-status":
        value["data"]["status"] = "unknown"
    else:
        value.pop("data")
    with pytest.raises(ValueError):
        readiness.agent_control(value)


@pytest.mark.parametrize("state", ["status='pending'", "status='disconnected'"])
def test_active_manager_record_does_not_override_disconnected_endpoint(state):
    assert not readiness.readiness(CONTROL, state, HEADER)["ready"]


@pytest.mark.parametrize(
    "state",
    [
        "",
        "status=connected",
        "status='connected'\nstatus='pending'",
        "status='unknown'",
        "status=__import__('os').system('false')",
    ],
)
def test_missing_duplicate_or_executable_state_input_is_rejected(state):
    with pytest.raises(ValueError):
        readiness.agent_state(state)


@pytest.mark.parametrize(
    "content", ["", "unavailable", "0: 0100007F:D6D8 00000000:0000 0A\n", HEADER + "garbled\n"]
)
def test_unavailable_or_malformed_listener_inventory_cannot_be_called_absent(content):
    with pytest.raises(ValueError):
        readiness.management_listeners(content)


def reader():
    return {
        "name": "/aegis-wazuh-tls-reader-" + "a" * 32,
        "project": "aegis-wazuh-lab",
        "assay": "a" * 32,
        "image_id": "sha256:" + "b" * 64,
        "service": "migrate",
        "entrypoint": ["python"],
        "command": ["/review/probe.py"],
    }


def test_inherited_image_build_label_does_not_change_the_verified_probe_command():
    value = reader()
    original = copy.deepcopy(value)
    result = readiness.reader_identity(value, review_id="a" * 32, image_id="sha256:" + "b" * 64)
    assert result == {
        "role": "tls-reader",
        "identity_verified": True,
        "inherited_service_label": "migrate",
    }
    assert value == original


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "/other-reader"),
        ("project", "other-project"),
        ("assay", "c" * 32),
        ("image_id", "sha256:" + "c" * 64),
        ("entrypoint", ["alembic"]),
        ("command", ["upgrade", "head"]),
        ("command", ["/review/probe.py", "--unreviewed"]),
        ("service", "worker"),
    ],
)
def test_reader_identity_never_accepts_actual_migration_or_unreviewed_resources(field, value):
    item = reader()
    item[field] = value
    with pytest.raises(ValueError):
        readiness.reader_identity(item, review_id="a" * 32, image_id="sha256:" + "b" * 64)
