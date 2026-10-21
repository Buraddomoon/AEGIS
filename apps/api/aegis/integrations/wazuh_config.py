"""Public, versioned collection policy; credentials are never part of snapshots."""

import hashlib
import math
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis.config import settings
from aegis.domain.validation import digest


class WazuhCollectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    laboratory_id: UUID
    asset_id: UUID
    agent_id: str = Field(pattern=r"^[0-9]{3,12}$")
    expected_rule: str = Field(pattern=r"^[1-9][0-9]{0,9}$")
    schema_id: Literal["aegis-json/1"] = "aegis-json/1"
    alerts_index: str = Field(
        default="wazuh-alerts-4.x-*", pattern=r"^[a-z0-9][a-z0-9._*-]{0,150}$"
    )
    archives_index: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._*-]{0,150}$")
    timestamp_field: Literal["timestamp", "@timestamp"] = "timestamp"
    identity_prefix: str = Field(
        default="data.aegis", pattern=r"^data\.[a-zA-Z][a-zA-Z0-9_]{0,39}$"
    )
    clock_skew_seconds: int = Field(default=5, ge=0, le=30)
    ingestion_window_seconds: int = Field(default=10, ge=1, le=120)
    ingestion_wait_seconds: float = Field(default=10, ge=0.1, le=120)
    poll_interval_seconds: float = Field(default=1, ge=0.1, le=10)
    request_timeout_seconds: float = Field(default=3, ge=0.1, le=5)

    @field_validator("agent_id")
    @classmethod
    def endpoint_agent(cls, value: str) -> str:
        if int(value) == 0:
            raise ValueError("Agente manager não é endpoint de laboratório.")
        return value

    @model_validator(mode="after")
    def limits(self):
        if self.ingestion_wait_seconds < self.ingestion_window_seconds:
            raise ValueError(
                "Espera de ingestão deve cobrir a janela temporal antes de concluir ausência de alerta."
            )
        if self.poll_interval_seconds > self.ingestion_wait_seconds:
            raise ValueError("Intervalo de polling excede a janela de espera.")
        if math.ceil(self.ingestion_wait_seconds / self.poll_interval_seconds) + 1 > 64:
            raise ValueError("Política excede 64 rodadas; aumente o intervalo de polling.")
        if self.archives_index == self.alerts_index:
            raise ValueError("Alertas e archives precisam de índices distintos.")
        if self.archives_index:
            alert_prefix = self.alerts_index.split("*", 1)[0]
            archive_prefix = self.archives_index.split("*", 1)[0]
            if alert_prefix.startswith(archive_prefix) or archive_prefix.startswith(alert_prefix):
                raise ValueError("Padrões de alertas e archives precisam de prefixos distintos.")
        return self


def load_config() -> WazuhCollectionConfig:
    path = settings().wazuh_collection_config
    if path is None:
        raise ValueError("Política Wazuh opt-in não configurada.")
    try:
        with path.open("rb") as stream:
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise ValueError("Política excede 16 KiB.")
        return WazuhCollectionConfig.model_validate_json(raw)
    except Exception:
        raise ValueError("Política Wazuh inválida ou inacessível na implantação.") from None


def descriptor() -> dict:
    from aegis.integrations.wazuh import validate_destination

    cfg, connection = load_config(), settings()
    validate_destination(
        connection.wazuh_url or "",
        connection.wazuh_allowed_ip or "",
        cfg.alerts_index,
        cfg.archives_index,
    )
    if not connection.wazuh_username or not connection.wazuh_password:
        raise ValueError("Credenciais Wazuh ausentes.")
    trust = (
        hashlib.sha256(Path(connection.wazuh_ca_bundle).read_bytes()).hexdigest()
        if connection.wazuh_ca_bundle
        else "system"
    )
    return {
        "provider": "wazuh-indexer",
        "policy": cfg.model_dump(mode="json"),
        "destination": {
            "url": connection.wazuh_url,
            "allowed_ip": connection.wazuh_allowed_ip,
            "trust_sha256": trust,
            "principal_sha256": digest(connection.wazuh_username),
        },
    }


def configured_hash() -> str | None:
    try:
        return digest(descriptor())
    except (ValueError, OSError):
        return None
