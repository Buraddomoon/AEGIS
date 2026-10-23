from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_ignore_empty=True)
    database_url: str = "postgresql+psycopg://aegis@localhost:18782/aegis"
    redis_url: str = "redis://localhost:18783/0"
    public_origin: str = "http://localhost:18780"
    secure_cookies: bool = False  # Loopback HTTP demo; HTTPS deployments must enable.
    session_hours: int = Field(default=8, ge=1, le=24)
    worker_poll_seconds: float = 0.5
    demo_step_seconds: float = Field(default=0.15, ge=0, le=5)
    web_dist: Path = Path("apps/web/dist")
    fixtures_path: Path = Path("fixtures")
    wazuh_url: str | None = None
    wazuh_username: str | None = None
    wazuh_password: str | None = None
    wazuh_ca_bundle: str | None = None
    wazuh_allowed_ip: str | None = None
    linux_runner_config: Path | None = None
    wazuh_collection_config: Path | None = None
    operating_mode: Literal["normal", "recovery"] = "normal"
    recovery_access_token: SecretStr | None = Field(default=None, repr=False)
    recovery_reconciliation_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    recovery_reconciliation_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


@lru_cache
def settings() -> Settings:
    return Settings()


def require_normal_operation() -> None:
    if settings().operating_mode != "normal":
        raise RuntimeError("Operação bloqueada: aplicação em quarentena de recuperação.")
