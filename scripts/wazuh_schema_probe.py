"""Read-only #63 probe of the retained #59 alert, never a new campaign.

Run only in the reviewed isolated reader. Credentials arrive as one newline-
terminated JSON object on stdin. No Docker/lifecycle operations or free destination.
"""

import json
import ssl
import sys
import time
from dataclasses import replace
from datetime import datetime

import httpx
from aegis.domain.contracts import ExecutionContext
from aegis.domain.validation import digest
from aegis.integrations.wazuh import WazuhIndexerProvider
from aegis.integrations.wazuh_config import WazuhCollectionConfig
from wazuh_tls_probe import CA, HOSTNAME, IP, URL, peer_identity, unique_fields
from wazuh_tls_probe import probe as tls_probe

REFERENCE = {
    "laboratory_id": "cbf6e0ec-962c-450e-861e-ba7a313c2a5a",
    "asset_id": "40ba5412-0034-4096-b88f-78a2ccdb789a",
    "execution_id": "2f858fc9-e59c-46d0-ab9a-5d1b45bb0e1c",
    "marker": "aegis-17392bfa-18e8-4de3-a2f0-a2051725e2bc",
    "behavior": "temporary-marker",
    "timestamp": "2026-11-16T20:18:57.553+0000",
    "source_id": "jWQD5qEBm7izxmUqYd4q",
    "index": "wazuh-alerts-4.x-2026.11.16",
    "raw_sha256": "1181e2d800bd99e3117b22b760f30223ff88c1243e0462328f2137889c2276c5",
}


class AuditedReader(WazuhIndexerProvider):
    def __init__(self, *args, audit, **kwargs):
        super().__init__(*args, **kwargs)
        self.audit = audit

    def _request(self, method, path, body=None):
        record = {"method": method, "path": path}
        if method == "DELETE":
            record["requested_cursor_sha256"] = [digest(item) for item in body["scroll_id"]]
        self.audit.append(record)
        try:
            value = super()._request(method, path, body)
        except httpx.HTTPStatusError as exc:
            record["http_status"] = exc.response.status_code
            raise
        record["http_status"] = 200
        if "_shards" in value:
            record["shards"] = value["_shards"]
            record["timed_out"] = value.get("timed_out")
            record["total"] = value.get("hits", {}).get("total")
            record["returned"] = len(value.get("hits", {}).get("hits", []))
        if "_scroll_id" in value:
            record["cursor_sha256"] = digest(value["_scroll_id"])
        if method == "DELETE":
            record["succeeded"] = value.get("succeeded")
            record["num_freed"] = value.get("num_freed")
        return value


def probe(payload, *, provider_factory=AuditedReader, peer=None):
    audit = []

    def factory(*args, **kwargs):
        return provider_factory(*args, audit=audit, **kwargs)

    tls = tls_probe(payload, provider_factory=factory, peer=peer)
    policy = WazuhCollectionConfig(
        schema_id="wazuh-4.14.9/1",
        laboratory_id=REFERENCE["laboratory_id"],
        asset_id=REFERENCE["asset_id"],
        agent_id="001",
        expected_rule="100200",
    )
    instant = datetime.fromisoformat(REFERENCE["timestamp"])
    # This is a bounded historical query window around an independently retained
    # event, not a replacement execution receipt or a new detection verdict.
    context = ExecutionContext(
        REFERENCE["execution_id"],
        REFERENCE["laboratory_id"],
        REFERENCE["asset_id"],
        REFERENCE["marker"],
        REFERENCE["behavior"],
        instant,
        instant,
        False,
        "100200",
    )

    def collect(ctx, cfg):
        reader = factory(
            URL,
            payload["username"],
            payload["password"],
            IP,
            ca_bundle=CA,
            policy=cfg,
            budget_end=time.monotonic() + 20,
        )
        return reader.collect(ctx)

    positive = collect(context, policy)
    if not positive.complete or not positive.alerts_available or len(positive.events) != 1:
        raise ValueError("historical_alert_query_incomplete")
    (event,) = positive.events
    if (
        event.source_id != REFERENCE["source_id"]
        or event.source != "wazuh-indexer:" + REFERENCE["index"]
        or digest(event.raw) != REFERENCE["raw_sha256"]
        or event.raw["_source"]["timestamp"] != REFERENCE["timestamp"]
        or event.timestamp.utcoffset() != instant.utcoffset()
        or event.rule_id != "100200"
    ):
        raise ValueError("historical_alert_identity_or_content_changed")
    negative = collect(replace(context, marker=context.marker + "-not-this-event"), policy)
    if not negative.complete or not negative.alerts_available or negative.events:
        raise ValueError("negative_marker_query_not_verified")
    optional = collect(
        context, policy.model_copy(update={"archives_index": "wazuh-archives-4.x-*"})
    )
    if (
        optional.complete
        or optional.telemetry_available
        or not optional.alerts_available
        or not optional.error
        or "Archives: permissão negada (HTTP 403)" not in optional.error
    ):
        raise ValueError("archive_read_denial_not_verified")
    cursors = {call["cursor_sha256"] for call in audit if "cursor_sha256" in call}
    cleanup = [call for call in audit if call["method"] == "DELETE"]
    if (
        not cursors
        or len(cleanup) != 3
        or any(call.get("succeeded") is not True for call in cleanup)
        or any(not set(call["requested_cursor_sha256"]) <= cursors for call in cleanup)
    ):
        raise ValueError("scroll_cleanup_not_verified")
    return {
        "format": "aegis-wazuh-schema-probe/1",
        "status": "historical_native_profile_query_verified",
        "schema_id": policy.schema_id,
        "policy_sha256": digest(policy.model_dump(mode="json")),
        "tls": tls,
        "reference": REFERENCE,
        "positive_complete": positive.complete,
        "negative_marker_complete_empty": True,
        "archives": {"available": False, "http_status": 403, "reason": optional.error},
        "diagnostics": positive.diagnostics,
        "requests": audit,
        "scroll_cleanup_verified": True,
        "new_marker_executed": False,
        "new_run_requested": False,
        "new_detection_verdict_created": False,
        "document_write_request_performed": False,
    }


def main():
    try:
        # Compose keeps stdin open (StdinOnce=false). Do not wait for pipe EOF.
        raw = sys.stdin.buffer.readline(4097)
        if len(raw) > 4096:
            raise ValueError("probe_input_too_large")
        result = probe(json.loads(raw, object_pairs_hook=unique_fields), peer=wait_for_peer)
    except (OSError, ValueError, TypeError, KeyError, TimeoutError, httpx.HTTPError) as error:
        public_codes = {
            "historical_alert_query_incomplete",
            "historical_alert_identity_or_content_changed",
            "negative_marker_query_not_verified",
            "archive_read_denial_not_verified",
            "scroll_cleanup_not_verified",
            "probe_input_too_large",
            "indexer_tls_readiness_timeout",
            "invalid_probe_scope",
            "tls_peer_identity_mismatch",
            "indexer_version_unavailable",
            "reader_principal_or_role_mismatch",
            "reader_security_api_access_not_denied",
            "alert_index_read_incomplete",
            "security_index_denial_unconfirmed",
            "security_index_read_was_not_denied",
            "indexer_http_readiness_unexpected",
        }
        print(
            json.dumps(
                {
                    "status": "inconclusive",
                    "error_type": type(error).__name__,
                    "error_code": str(error)
                    if str(error) in public_codes
                    else "probe_not_verified",
                    "reason": "Consulta nativa não verificada; preservar artefatos e executar cleanup.",
                }
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def wait_for_peer():
    # Handshake can precede security-index initialization. Read readiness without
    # credentials before the authenticated TLS/ACL probe, keeping the same budget.
    deadline = time.monotonic() + 90
    while True:
        try:
            observed = peer_identity()
            status = readiness_status()
            print(
                json.dumps({"stage": "http_readiness", "status": status}),
                file=sys.stderr,
                flush=True,
            )
            if status in (200, 401):
                return observed
            if status != 503:
                raise ValueError("indexer_http_readiness_unexpected")
        except (
            ConnectionRefusedError,
            ConnectionResetError,
            TimeoutError,
            ssl.SSLEOFError,
            httpx.TimeoutException,
        ):
            pass
        if time.monotonic() >= deadline:
            raise TimeoutError("indexer_tls_readiness_timeout") from None
        time.sleep(1)


def readiness_status():
    with httpx.Client(
        verify=ssl.create_default_context(cafile=CA),
        timeout=3,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        request = client.build_request(
            "GET",
            f"https://{IP}:9200/",
            headers={"Host": HOSTNAME + ":9200"},
            extensions={"sni_hostname": HOSTNAME},
        )
        response = client.send(request, stream=True)
        try:
            return response.status_code
        finally:
            response.close()


if __name__ == "__main__":
    raise SystemExit(main())
