"""Read-only Wazuh Indexer adapter. Not a Wazuh management API client.

Outbound destination is deployment configuration, never request input. IP pinning
prevents DNS rebinding; TLS SNI and certificate hostname remain the configured host.
"""
import ipaddress
import re
import ssl
from datetime import datetime, timedelta
from urllib.parse import urlsplit

import httpx

from aegis.config import settings
from aegis.domain.contracts import Collection, Event, ExecutionContext


class WazuhIndexerProvider:
    def __init__(self, url: str, username: str, password: str, allowed_ip: str,
                 ca_bundle: str | None = None, alerts_index: str = "wazuh-alerts-4.x-*",
                 archives_index: str | None = None, transport: httpx.BaseTransport | None = None):
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            raise ValueError("Indexer exige origem HTTPS sem caminho ou credenciais na URL.")
        ip = ipaddress.ip_address(allowed_ip)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError("Destino de integração não permitido.")
        for index in [alerts_index, archives_index]:
            if index is not None and not re.fullmatch(r"[a-z0-9][a-z0-9._*-]{0,150}", index):
                raise ValueError("Padrão de índice inválido.")
        if not username or not password:
            raise ValueError("Credenciais ausentes.")
        self.hostname = parsed.hostname
        self.authority = parsed.netloc
        address = f"[{ip}]" if ip.version == 6 else str(ip)
        self.base = f"https://{address}:{parsed.port or 9200}"
        self.alerts_index, self.archives_index = alerts_index, archives_index
        self.client = httpx.Client(auth=(username, password),
            verify=ssl.create_default_context(cafile=ca_bundle), transport=transport,
            timeout=httpx.Timeout(10, connect=3), follow_redirects=False, trust_env=False,
            limits=httpx.Limits(max_connections=2))

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        request = self.client.build_request(method, self.base + path, json=body,
                        headers={"Host": self.authority},
                        extensions={"sni_hostname": self.hostname.encode()})
        response = self.client.send(request, stream=True)
        try:
            response.raise_for_status()
            if 300 <= response.status_code < 400:
                raise ValueError("Redirects de integração são proibidos.")
            chunks, size = [], 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > 8_000_000:
                    raise ValueError("Resposta excede limite de tamanho.")
                chunks.append(chunk)
            import json
            value = json.loads(b"".join(chunks))
        finally:
            response.close()
        if not isinstance(value, dict):
            raise ValueError("Schema de resposta inesperado.")
        return value

    def test_connection(self) -> str:
        try:
            response = self._request("GET", "/")
            return str(response.get("version", {}).get("number", "unknown"))
        finally:
            self.client.close()

    @staticmethod
    def normalize(hit: dict, kind: str) -> Event:
        raw = hit["_source"]
        fields = raw.get("data", {}).get("aegis", {})
        timestamp = datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            raise ValueError("Timestamp Wazuh sem timezone.")
        # Missing identity remains missing; never fill it from requested scope.
        return Event(source_id=hit["_id"], source="wazuh-indexer:" + hit["_index"],
                     timestamp=timestamp, laboratory_id=str(fields.get("laboratory_id", "")),
                     asset_id=str(raw.get("agent", {}).get("id", "")),
                     execution_id=str(fields.get("execution_id", "")),
                     marker=str(fields.get("marker", "")), behavior=str(fields.get("behavior", "")),
                     kind=kind, rule_id=str(raw["rule"]["id"]) if raw.get("rule", {}).get("id") else None,
                     synthetic=False, raw={"_id": hit["_id"], "_index": hit["_index"], "_source": raw})

    def _search(self, index: str, context: ExecutionContext, kind: str) -> tuple[list[Event], bool]:
        query = {"size": 200, "sort": ["_doc"], "query": {"bool": {"filter": [
            {"term": {"agent.id": context.asset_id}},
            {"range": {"timestamp": {"gte": (context.started_at - timedelta(seconds=5)).isoformat(),
                                      "lte": (context.ended_at + timedelta(seconds=120)).isoformat()}}},
            {"match_phrase": {"data.aegis.marker": context.marker}},
        ]}}}
        scroll_id, events, complete = None, [], True
        try:
            response = self._request("POST", f"/{index}/_search?scroll=1m", query)
            for _ in range(25):  # bounded pagination, at most 5000 hits per index
                scroll_id = response.get("_scroll_id", scroll_id)
                if response.get("timed_out") or response.get("_shards", {}).get("failed", 0):
                    complete = False
                hits = response["hits"]["hits"]
                if not hits:
                    break
                for hit in hits:
                    try:
                        events.append(self.normalize(hit, kind))
                    except (KeyError, TypeError, ValueError):
                        complete = False
                if not scroll_id:
                    complete = False
                    break
                response = self._request("POST", "/_search/scroll", {"scroll": "1m", "scroll_id": scroll_id})
            else:
                complete = False
            return events, complete
        finally:
            if scroll_id:
                try:
                    self._request("DELETE", "/_search/scroll", {"scroll_id": [scroll_id]})
                except Exception:
                    pass  # Context expires; no index/document is changed.

    def collect(self, context: ExecutionContext) -> Collection:
        events, alerts_ok, telemetry_ok, complete = [], False, False, True
        try:
            try:
                hits, ok = self._search(self.alerts_index, context, "alert")
                events.extend(hits)
                alerts_ok = ok
                complete = complete and ok
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                complete = False
            if self.archives_index:
                try:
                    hits, ok = self._search(self.archives_index, context, "telemetry")
                    events.extend(hits)
                    telemetry_ok = ok
                    complete = complete and ok
                except (httpx.HTTPError, ValueError, KeyError, TypeError):
                    complete = False
            return Collection(tuple(events), telemetry_ok, alerts_ok, complete,
                               None if complete else "Coleta Indexer incompleta ou indisponível.")
        finally:
            self.client.close()

    def alerts(self, context: ExecutionContext) -> Collection:
        return self.collect(context)


def configured_provider() -> WazuhIndexerProvider:
    cfg = settings()
    if not all([cfg.wazuh_url, cfg.wazuh_username, cfg.wazuh_password, cfg.wazuh_allowed_ip]):
        raise ValueError("Wazuh não configurado.")
    return WazuhIndexerProvider(cfg.wazuh_url, cfg.wazuh_username, cfg.wazuh_password,
                                cfg.wazuh_allowed_ip, cfg.wazuh_ca_bundle)
