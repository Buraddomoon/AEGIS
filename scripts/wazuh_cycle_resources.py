"""Closed resource profiles for the standard cycle and an explicit bounded trial."""

MIB = 1024**2
BOUNDED = "bounded-3360m/1"
BOUNDED_MEMORY = {
    "db": 256,
    "redis": 64,
    "api": 256,
    "worker": 160,
    "runner": 128,
    "observer": 64,
    "wazuh.indexer": 1536,
    "wazuh.manager": 768,
    "wazuh.agent": 128,
}
RESERVE = 512 * MIB
HEAP = "-Xms512m -Xmx512m"
DB_COMMAND = [
    "postgres",
    "-c",
    "shared_buffers=32MB",
    "-c",
    "work_mem=1MB",
    "-c",
    "maintenance_work_mem=32MB",
    "-c",
    "max_connections=20",
]
REDIS_COMMAND = [
    "/bin/sh",
    "-c",
    'exec redis-server --requirepass "$$REDIS_PASSWORD" --maxmemory 32mb --maxmemory-policy noeviction',
]


def memory(profile, standard):
    if profile == "standard":
        return {name: value for name, value in standard.items() if name != "migrate"}
    if profile == BOUNDED:
        return dict(BOUNDED_MEMORY)
    raise ValueError("cycle_resource_profile_unknown")


def review(resources, profile):
    """Resource observation only. Never grants native or marker authorization."""
    if profile not in {"standard", BOUNDED}:
        raise ValueError("cycle_resource_profile_unknown")
    floor = 8 * 1024**3 if profile == "standard" else sum(BOUNDED_MEMORY.values()) * MIB + RESERVE
    blockers = []
    if resources.available_bytes < floor:
        blockers.append("cycle_available_memory_below_profile_and_reserve")
    if resources.cpus < 4:
        blockers.append("cycle_cpu_floor_not_met")
    if resources.docker_free_bytes < 50 * 1024**3:
        blockers.append("cycle_storage_floor_not_met")
    if resources.max_map_count < 262144:
        blockers.append("cycle_map_count_floor_not_met")
    return {
        "format": "aegis-wazuh-cycle-resource-review/1",
        "profile": profile,
        "available_bytes": resources.available_bytes,
        "required_available_bytes": floor,
        "container_ceiling_bytes": sum(BOUNDED_MEMORY.values()) * MIB
        if profile == BOUNDED
        else None,
        "reserve_bytes": RESERVE if profile == BOUNDED else None,
        "blockers": blockers,
        "effects_authorized": False,
        "marker_permitted": False,
    }
