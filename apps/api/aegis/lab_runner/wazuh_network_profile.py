"""ADR0034 fixed Wazuh networks; no operator/API-selected subnets or destinations."""

EXECUTION_SUBNET = "192.168.253.8/29"
TELEMETRY_SUBNET = "192.168.253.16/29"
RUNNER_IP = "192.168.253.10"
RUNNER_URL = "https://192.168.253.10:8443"
INDEXER_IP = "192.168.253.18"
INDEXER_URL = "https://wazuh.indexer:9200"
LEGACY_RUNNER_IP = "172.30.89.2"
LEGACY_RUNNER_URL = "https://172.30.89.2:8443"
LEGACY_INDEXER_IP = "172.30.90.2"
SUBNETS = {"isolated": EXECUTION_SUBNET, "telemetry": TELEMETRY_SUBNET}
GATEWAYS = {"isolated": "192.168.253.9", "telemetry": "192.168.253.17"}
ADDRESSES = {
    ("runner", "isolated"): RUNNER_IP,
    ("controller", "isolated"): "192.168.253.11",
    ("api", "isolated"): "192.168.253.12",
    ("worker", "isolated"): "192.168.253.13",
    ("wazuh.indexer", "telemetry"): INDEXER_IP,
    ("wazuh.manager", "telemetry"): "192.168.253.19",
    ("wazuh.agent", "telemetry"): "192.168.253.20",
    ("api", "telemetry"): "192.168.253.21",
    ("worker", "telemetry"): "192.168.253.22",
}
