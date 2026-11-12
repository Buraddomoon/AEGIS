"""Parse independent readiness observations; never execute commands or infer missing facts."""

import re


def reader_identity(value: dict, *, review_id: str, image_id: str) -> dict:
    """Identify the explicit probe command, retaining inherited build labels.

    Runtime limits, mounts, source hash and results require separate checks.
    A cached Compose-built image can carry service=migrate even when Docker run
    explicitly overrides its entrypoint with the read-only probe.
    """
    if (
        not isinstance(review_id, str)
        or not re.fullmatch(r"[a-f0-9]{32}", review_id)
        or not isinstance(image_id, str)
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id)
    ):
        raise ValueError("reader_review_identity_invalid")
    if (
        not isinstance(value, dict)
        or value.get("name") != "/aegis-wazuh-tls-reader-" + review_id
        or value.get("project") != "aegis-wazuh-lab"
        or value.get("assay") != review_id
        or value.get("image_id") != image_id
        or value.get("entrypoint") != ["python"]
        or value.get("command") != ["/review/probe.py"]
        or value.get("service") not in {None, "", "migrate"}
    ):
        raise ValueError("reader_identity_or_command_mismatch")
    return {
        "role": "tls-reader",
        "identity_verified": True,
        "inherited_service_label": value.get("service"),
    }


def agent_control(value: dict) -> dict:
    if not isinstance(value, dict) or type(value.get("error")) is not int or value["error"] != 0:
        raise ValueError("agent_control_unconfirmed")
    item = value.get("data")
    if not isinstance(item, dict) or item.get("id") != "001" or item.get("name") != "aegis-marker":
        raise ValueError("agent_identity_mismatch")
    status = item.get("status")
    if status not in {"Active", "Disconnected", "Never connected", "Pending"}:
        raise ValueError("agent_status_unknown")
    return {"id": "001", "name": "aegis-marker", "status": status, "active": status == "Active"}


def agent_state(content: str) -> dict:
    # Wazuh's documented state file is updated every five seconds. No eval/source.
    if not isinstance(content, str) or len(content) > 65536:
        raise ValueError("agent_state_invalid")
    statuses = []
    for line in content.splitlines():
        if line.strip().startswith("#") or not line.strip():
            continue
        if line.strip().startswith("status"):
            match = re.fullmatch(r"status='(connected|pending|disconnected)'", line.strip())
            if not match:
                raise ValueError("agent_state_status_invalid")
            statuses.append(match.group(1))
    if len(statuses) != 1:
        raise ValueError("agent_state_status_missing_or_duplicated")
    return {"status": statuses[0], "connected": statuses[0] == "connected"}


def management_listeners(content: str) -> dict:
    """Require absence of LAN exposure; an unnecessary API need not be running.

    An absent listener and a verified loopback listener are separate observations.
    Neither proves management API functionality or renews its certificate.
    """
    if not isinstance(content, str) or not content.strip() or len(content) > 65536:
        raise ValueError("listener_inventory_unavailable")
    listeners = []
    headers = 0
    for line in content.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == "sl":
            if len(parts) < 4 or parts[1] != "local_address" or parts[3] != "st":
                raise ValueError("listener_inventory_header_invalid")
            headers += 1
            continue
        if (
            len(parts) < 4
            or not re.fullmatch(r"\d+:", parts[0])
            or not re.fullmatch(r"(?:[0-9A-F]{8}|[0-9A-F]{32}):[0-9A-F]{4}", parts[1])
            or not re.fullmatch(r"[0-9A-F]{2}", parts[3])
        ):
            raise ValueError("listener_inventory_invalid")
        address, port = parts[1].split(":")
        if port == "D6D8" and parts[3] == "0A":
            if address not in {"0100007F", "00000000000000000000000001000000"}:
                raise ValueError("management_api_exposed_outside_loopback")
            listeners.append(address)
    if not headers:
        raise ValueError("listener_inventory_header_missing")
    return {
        "management_api_listening": bool(listeners),
        "management_api_no_lan_listener": True,
        "management_api_loopback_verified": bool(listeners),
    }


def readiness(control: dict, state: str, listeners: str) -> dict:
    manager = agent_control(control)
    endpoint = agent_state(state)
    management = management_listeners(listeners)
    return {
        "manager": manager,
        "agent": endpoint,
        "management": management,
        "ready": manager["active"] and endpoint["connected"],
    }
