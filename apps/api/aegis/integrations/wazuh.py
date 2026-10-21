"""Read-only Wazuh Indexer adapter. Not a Wazuh management API client.

Outbound destination is deployment configuration, never request input. IP pinning
prevents DNS rebinding; TLS SNI and certificate hostname remain the configured host.
"""

import asyncio
import ipaddress
import json
import re
import ssl
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from fnmatch import fnmatchcase
from urllib.parse import urlsplit

import httpx

from aegis.config import settings
from aegis.domain.contracts import Collection, Event, ExecutionContext
from aegis.domain.validation import correlates
from aegis.integrations.wazuh_config import WazuhCollectionConfig


def validate_destination(url: str, allowed_ip: str, alerts_index: str, archives_index: str | None):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Indexer exige origem HTTPS sem caminho ou credenciais na URL.")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Porta Indexer inválida.")
    ip = ipaddress.ip_address(allowed_ip)
    checked_ip = getattr(ip, "ipv4_mapped", None) or ip
    if (
        checked_ip.is_loopback
        or checked_ip.is_link_local
        or checked_ip.is_multicast
        or checked_ip.is_unspecified
    ):
        raise ValueError("Destino de integração não permitido.")
    for index in [alerts_index, archives_index]:
        if index is not None and not re.fullmatch(r"[a-z0-9][a-z0-9._*-]{0,150}", index):
            raise ValueError("Padrão de índice inválido.")
    return parsed, ip


class WazuhIndexerProvider:
    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        allowed_ip: str,
        ca_bundle: str | None = None,
        alerts_index: str = "wazuh-alerts-4.x-*",
        archives_index: str | None = None,
        transport: httpx.BaseTransport | None = None,
        policy: WazuhCollectionConfig | None = None,
        guard: Callable[[], None] = lambda: None,
        budget_end: float | None = None,
    ):
        if policy:
            alerts_index, archives_index = policy.alerts_index, policy.archives_index
        parsed, ip = validate_destination(url, allowed_ip, alerts_index, archives_index)
        if not username or not password:
            raise ValueError("Credenciais ausentes.")
        self.policy, self.guard, self.budget_end = policy, guard, budget_end
        self.bytes_read = 0
        self.hostname = parsed.hostname
        self.authority = parsed.netloc
        address = f"[{ip}]" if ip.version == 6 else str(ip)
        self.base = f"https://{address}:{parsed.port or 443}"
        self.alerts_index, self.archives_index = alerts_index, archives_index
        self.loop, self.closed = asyncio.Runner(), False
        self.client = httpx.AsyncClient(
            auth=(username, password),
            verify=ssl.create_default_context(cafile=ca_bundle),
            transport=transport,
            timeout=httpx.Timeout(10, connect=3),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=2),
        )

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        return self.loop.run(self._request_async(method, path, body))

    async def _request_async(self, method: str, path: str, body: dict | None) -> dict:
        cleanup = method == "DELETE"
        if not cleanup:
            self.guard()
        timeout = 0.5 if cleanup else (self.policy.request_timeout_seconds if self.policy else 5)
        if self.budget_end is not None:
            timeout = min(timeout, self.budget_end + (1 if cleanup else 0) - time.monotonic())
            if timeout <= 0:
                raise TimeoutError("Orçamento de consulta esgotado.")
        request_end = time.monotonic() + timeout
        # Total timeout covers pool/connect/TLS/headers and even a trickling body.
        async with asyncio.timeout(timeout):
            request = self.client.build_request(
                method,
                self.base + path,
                json=body,
                timeout=httpx.Timeout(timeout, connect=min(timeout, 2)),
                headers={"Host": self.authority, "Accept-Encoding": "identity"},
                extensions={"sni_hostname": self.hostname},
            )
            response = await self.client.send(request, stream=True)
            try:
                response.raise_for_status()
                if 300 <= response.status_code < 400:
                    raise ValueError("Redirects de integração são proibidos.")
                if response.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError("Resposta comprimida não aceita neste contrato limitado.")
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    if not cleanup:
                        self.guard()
                    size += len(chunk)
                    self.bytes_read += len(chunk)
                    if size > 8_000_000 or self.bytes_read > 16_000_000:
                        raise ValueError("Resposta excede limite de tamanho.")
                    chunks.append(chunk)
                try:
                    value = json.loads(b"".join(chunks))
                except RecursionError:
                    raise ValueError("Documento JSON excessivamente aninhado.") from None
                if time.monotonic() > request_end:
                    raise TimeoutError("Orçamento esgotado durante parsing.")
            finally:
                try:
                    async with asyncio.timeout(0.5):
                        await response.aclose()
                except TimeoutError:
                    pass
        if not isinstance(value, dict):
            raise ValueError("Schema de resposta inesperado.")
        return value

    def test_connection(self) -> str:
        try:
            response = self._request("GET", "/")
            return str(response.get("version", {}).get("number", "unknown"))
        finally:
            self.close()

    @staticmethod
    def normalize(hit: dict, kind: str, policy: WazuhCollectionConfig | None = None) -> Event:
        raw = hit["_source"]
        if kind not in ("alert", "telemetry") or not isinstance(raw, dict):
            raise ValueError("Tipo de documento inesperado.")
        fields = raw
        for part in (policy.identity_prefix if policy else "data.aegis").split("."):
            fields = fields.get(part, {})
            if not isinstance(fields, dict):
                raise ValueError("Campos de identidade inválidos.")
        timestamp = datetime.fromisoformat(
            raw[policy.timestamp_field if policy else "timestamp"].replace("Z", "+00:00")
        )
        if timestamp.tzinfo is None:
            raise ValueError("Timestamp Wazuh sem timezone.")
        external = raw.get("agent", {}).get("id", "")
        # Only an exact, reviewed external identity may be translated to internal UUID.
        if policy and (not isinstance(external, str) or external != policy.agent_id):
            raise ValueError("Agente de origem difere do mapping aprovado.")
        asset_id = str(policy.asset_id) if policy else str(external)
        identifier, index = hit["_id"], hit["_index"]
        if (
            not isinstance(identifier, str)
            or not identifier
            or not isinstance(index, str)
            or not index
        ):
            raise ValueError("Identificador de origem ausente.")
        return Event(
            source_id=identifier,
            source="wazuh-indexer:" + index,
            timestamp=timestamp,
            laboratory_id=str(fields.get("laboratory_id", "")),
            asset_id=asset_id,
            execution_id=str(fields.get("execution_id", "")),
            marker=str(fields.get("marker", "")),
            behavior=str(fields.get("behavior", "")),
            kind=kind,
            rule_id=str(raw["rule"]["id"]) if raw.get("rule", {}).get("id") else None,
            synthetic=False,
            raw={"_id": identifier, "_index": index, "_source": raw},
        )

    def _search(self, index: str, context: ExecutionContext, kind: str) -> tuple[list[Event], bool]:
        policy = self.policy
        prefix, timestamp = (
            (policy.identity_prefix, policy.timestamp_field)
            if policy
            else ("data.aegis", "timestamp")
        )
        skew, ingestion = (
            (policy.clock_skew_seconds, policy.ingestion_window_seconds) if policy else (5, 120)
        )
        filters = [
            {"term": {"agent.id": policy.agent_id if policy else context.asset_id}},
            {
                "range": {
                    timestamp: {
                        "gte": (context.started_at - timedelta(seconds=skew)).isoformat(),
                        "lte": (context.ended_at + timedelta(seconds=ingestion)).isoformat(),
                    }
                }
            },
        ]
        filters.extend(
            {"match_phrase": {prefix + "." + key: getattr(context, key)}}
            for key in ("marker", "laboratory_id", "execution_id", "behavior")
        )
        query = {
            "size": 200,
            "sort": ["_doc"],
            "track_total_hits": True,
            "timeout": "2000ms",
            "query": {"bool": {"filter": filters}},
        }
        scroll_id, complete = None, True
        events, total, seen = [], None, set()
        try:
            response = self._request(
                "POST",
                f"/{index}/_search?scroll=1m&allow_no_indices=false&ignore_unavailable=false",
                query,
            )
            for _ in range(25):
                scroll_id = response.get("_scroll_id", scroll_id)
                shards = response.get("_shards", {})
                if (
                    response.get("timed_out") is not False
                    or response.get("terminated_early")
                    or not isinstance(shards.get("total"), int)
                    or shards["total"] <= 0
                    or shards.get("failed") != 0
                    or shards.get("successful") != shards["total"]
                ):
                    complete = False
                hits = response["hits"]["hits"]
                if not isinstance(hits, list) or len(hits) > 200:
                    raise ValueError("Lista de hits inválida.")
                reported = response["hits"].get("total")
                if total is None:
                    if (
                        isinstance(reported, dict)
                        and reported.get("relation") == "eq"
                        and isinstance(reported.get("value"), int)
                    ):
                        total = reported["value"]
                    elif isinstance(reported, int) and not isinstance(reported, bool):
                        total = reported
                    else:
                        complete = False
                for hit in hits:
                    try:
                        if not fnmatchcase(hit["_index"], index):
                            raise ValueError("Índice devolvido fora do escopo.")
                        event = self.normalize(hit, kind, policy)
                        seen.add((event.source, event.source_id))
                        if correlates(context, event, skew, ingestion):
                            events.append(event)
                        else:
                            complete = False  # Source failed the exact scope, not a clean negative.
                    except (KeyError, TypeError, ValueError, AttributeError):
                        complete = False
                if not hits:
                    break
                if not scroll_id:
                    complete = complete and total == len(seen)
                    break
                response = self._request(
                    "POST", "/_search/scroll", {"scroll": "1m", "scroll_id": scroll_id}
                )
            else:
                complete = False
            if total is None or len(seen) != total:
                complete = False
            return events, complete
        finally:
            if scroll_id:
                try:
                    self._request("DELETE", "/_search/scroll", {"scroll_id": [scroll_id]})
                except Exception:
                    pass  # Cursor expires; no index/document is modified.

    def collect_once(self, context: ExecutionContext) -> Collection:
        if self.policy and (
            context.synthetic
            or context.asset_id != str(self.policy.asset_id)
            or context.laboratory_id != str(self.policy.laboratory_id)
        ):
            raise ValueError("Contexto difere do mapping aprovado.")
        events, alerts_ok, telemetry_ok, complete = [], False, False, True
        for index, kind in [(self.alerts_index, "alert"), (self.archives_index, "telemetry")]:
            if index is None:
                continue
            try:
                hits, ok = self._search(index, context, kind)
                events.extend(hits)
                if kind == "alert":
                    alerts_ok = ok
                else:
                    telemetry_ok = ok
                complete = complete and ok
            except (httpx.HTTPError, ValueError, KeyError, TypeError, TimeoutError):
                complete = False
        return Collection(
            tuple(events),
            telemetry_ok,
            alerts_ok,
            complete,
            None if complete else "Coleta Indexer incompleta ou indisponível.",
        )

    async def _close(self):
        async with asyncio.timeout(0.5):
            await self.client.aclose()

    def close(self):
        if not self.closed:
            self.closed = True
            try:
                self.loop.run(self._close())
            except TimeoutError:
                pass
            finally:
                self.loop.close()

    def collect(self, context: ExecutionContext) -> Collection:
        try:
            return self.collect_once(context)
        finally:
            self.close()

    def alerts(self, context: ExecutionContext) -> Collection:
        return self.collect(context)


def configured_provider(
    policy: WazuhCollectionConfig | None = None, **kwargs
) -> WazuhIndexerProvider:
    cfg = settings()
    if not all([cfg.wazuh_url, cfg.wazuh_username, cfg.wazuh_password, cfg.wazuh_allowed_ip]):
        raise ValueError("Wazuh não configurado.")
    return WazuhIndexerProvider(
        cfg.wazuh_url,
        cfg.wazuh_username,
        cfg.wazuh_password,
        cfg.wazuh_allowed_ip,
        cfg.wazuh_ca_bundle,
        alerts_index=policy.alerts_index if policy else "wazuh-alerts-4.x-*",
        archives_index=policy.archives_index if policy else None,
        policy=policy,
        **kwargs,
    )
