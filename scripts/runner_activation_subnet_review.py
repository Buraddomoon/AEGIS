"""Read-only local IPv4 subnet collision preflight; no route or Docker mutations."""

import ipaddress
import os
import selectors
import subprocess
import time

import runner_activation_metadata as metadata
from aegis.domain.validation import digest
from runner_activation_isolated_network import SUBNET
from runner_activation_ownership import identifier

ActivationError = metadata.ActivationError
MAX_NETWORKS = 128
ROUTE_COMMAND = ("/usr/bin/ip", "-json", "-4", "route", "show", "table", "all")
NETWORK_FORMAT = (
    '{"id":{{json .Id}},"driver":{{json .Driver}},"scope":{{json .Scope}},'
    '"ipam_driver":{{json .IPAM.Driver}},"config":{{json .IPAM.Config}}}'
)


class RouteReader:
    def query(self, *, timeout):
        if type(timeout) not in (int, float) or not 0 < timeout <= 5:
            raise ActivationError("subnet_route_budget_invalid")
        try:
            process = subprocess.Popen(
                ROUTE_COMMAND,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=metadata.ENV,
            )
        except OSError:
            raise ActivationError("subnet_route_tool_unavailable") from None
        try:
            output, count = bytearray(), 0
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, True)
                selector.register(process.stderr, selectors.EVENT_READ, False)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ActivationError("subnet_route_query_timed_out")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        count += len(chunk)
                        if count > metadata.MAX_OUTPUT:
                            raise ActivationError("subnet_route_response_too_large")
                        if key.data:
                            output.extend(chunk)
                remaining = deadline - time.monotonic()
                if remaining <= 0 or process.wait(timeout=remaining) != 0:
                    raise ActivationError("subnet_route_query_unconfirmed")
            return bytes(output)
        except subprocess.TimeoutExpired:
            raise ActivationError("subnet_route_query_timed_out") from None
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
            process.stderr.close()


class NetworkReader:
    def query(self, known_id=None, *, timeout):
        command = (
            ("network", "ls", "--quiet", "--no-trunc")
            if known_id is None
            else ("network", "inspect", "--format", NETWORK_FORMAT, identifier(known_id))
        )
        return metadata._execute(command, timeout=timeout)


def _ids(raw):
    try:
        if type(raw) is not bytes or len(raw) > metadata.MAX_OUTPUT:
            raise ValueError
        items = raw.decode("ascii").splitlines()
        if len(items) > MAX_NETWORKS or len(items) != len(set(items)):
            raise ValueError
        return sorted(identifier(item) for item in items)
    except (ValueError, UnicodeError):
        raise ActivationError("subnet_network_inventory_invalid") from None


def _cidr(value):
    try:
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError
        return ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise ActivationError("subnet_address_metadata_invalid") from None


def _network(raw, known_id, *, planned=(SUBNET,)):
    item = metadata.document(raw)
    if (
        not isinstance(item, dict)
        or set(item) != {"id", "driver", "scope", "ipam_driver", "config"}
        or item["id"] != known_id
        or item["scope"] != "local"
        or type(item["driver"]) is not str
        or item["driver"] not in {"bridge", "host", "null"}
        or type(item["ipam_driver"]) is not str
        or item["ipam_driver"] not in {"default", ""}
    ):
        raise ActivationError("subnet_network_profile_unsupported")
    config = item["config"]
    if item["driver"] in {"host", "null"}:
        if config not in (None, []):
            raise ActivationError("subnet_network_profile_unsupported")
        return {"id": known_id, "driver": item["driver"], "subnets": []}
    if (
        item["ipam_driver"] != "default"
        or not isinstance(config, list)
        or not 1 <= len(config) <= 16
    ):
        raise ActivationError("subnet_network_profile_unsupported")
    subnets = []
    for entry in config:
        if not isinstance(entry, dict) or "Subnet" not in entry:
            raise ActivationError("subnet_network_profile_unsupported")
        subnet = _cidr(entry["Subnet"])
        if subnet.version == 4 and any(
            subnet.overlaps(ipaddress.ip_network(value)) for value in planned
        ):
            raise ActivationError("subnet_docker_overlap_observed")
        subnets.append(str(subnet))
    return {"id": known_id, "driver": "bridge", "subnets": sorted(subnets)}


def _routes(raw, *, planned=(SUBNET,)):
    items = metadata.document(raw)
    if not isinstance(items, list) or len(items) > 2048:
        raise ActivationError("subnet_route_inventory_invalid")
    reviewed, defaults = [], 0
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("dst"), str):
            raise ActivationError("subnet_route_inventory_invalid")
        subnet = _cidr("0.0.0.0/0" if item["dst"] == "default" else item["dst"])
        if subnet.version != 4:
            raise ActivationError("subnet_route_inventory_invalid")
        if subnet.prefixlen == 0:
            defaults += 1
        elif any(subnet.overlaps(ipaddress.ip_network(value)) for value in planned):
            raise ActivationError("subnet_host_route_overlap_observed")
        table, kind = item.get("table", "main"), item.get("type", "unicast")
        if type(table) not in (str, int) or not isinstance(kind, str):
            raise ActivationError("subnet_route_inventory_invalid")
        # Compare collision-relevant destinations/tables/types, not volatile
        # expiry/cache counters. This is not a review of routing/reachability.
        reviewed.append({"destination": str(subnet), "table": table, "type": kind})
    return {
        "count": len(items),
        "defaults": defaults,
        "sha256": digest(sorted(reviewed, key=digest)),
    }


def review(*, docker=None, routes=None):
    return _review((SUBNET,), docker=docker, routes=routes)


def _review(planned, *, docker=None, routes=None):
    """Two fresh local snapshots, no owned-network exclusion and no execution grant.

    Intended before network creation. An existing matching subnet blocks even if
    its labels claim ownership; later stages need their own concrete runtime gates.
    """
    deadline = time.monotonic() + 20
    docker, routes = docker or NetworkReader(), routes or RouteReader()

    def budget():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ActivationError("subnet_review_deadline")
        return min(5, remaining)

    def snapshot():
        ids = _ids(docker.query(timeout=budget()))
        networks = [
            _network(docker.query(known_id, timeout=budget()), known_id, planned=planned)
            for known_id in ids
        ]
        routing = _routes(routes.query(timeout=budget()), planned=planned)
        if _ids(docker.query(timeout=budget())) != ids:
            raise ActivationError("subnet_network_membership_changed")
        return {"networks": networks, "routes": routing}

    before, after = snapshot(), snapshot()
    budget()
    if digest(before) != digest(after):
        raise ActivationError("subnet_snapshot_changed")
    return {
        "format": "aegis-local-subnet-preflight/1",
        "subnet": planned[0],
        "status": "no_observed_fixed_ipv4_subnet_overlap",
        "networks_reviewed": len(after["networks"]),
        "routes_reviewed": after["routes"]["count"],
        "default_routes_ignored": after["routes"]["defaults"],
        "snapshot_sha256": digest(after),
        "observed_ipv4_overlap_absent": True,
        "network_reachability_verified": False,
        "effects_authorized": False,
        "activation_verified": False,
        "normal_operation_permitted": False,
    }
