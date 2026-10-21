from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

PROTOCOL = "aegis-linux-runner/1"
TEST_ID = "linux-file-marker/v1"
MAX_EFFECT_SECONDS = 5
LEASE_SECONDS = 2


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class JobSpec(Message):
    protocol: Literal["aegis-linux-runner/1"] = PROTOCOL
    test_id: Literal["linux-file-marker/v1"] = TEST_ID
    job_id: UUID
    laboratory_id: UUID
    asset_id: UUID
    runner_id: UUID
    marker: str = Field(pattern=r"^aegis-[0-9a-f-]{36}$")
    scope_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    deadline_at: AwareDatetime

    @field_validator("deadline_at")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        return value.astimezone(UTC)

    @field_validator("marker")
    @classmethod
    def marker_uuid(cls, value: str) -> str:
        if str(UUID(value[6:])) != value[6:]:
            raise ValueError("Marcador deve usar UUID canônico.")
        return value


class BoundRequest(Message):
    spec_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation: UUID


class JobState(StrEnum):
    PREPARED = "PREPARED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    INTERRUPTED = "INTERRUPTED"


class ExecutionReceipt(Message):
    kind: Literal["execution_receipt"] = "execution_receipt"
    synthetic: Literal[False] = False
    source: Literal["aegis-linux-runner"] = "aegis-linux-runner"
    job_id: UUID
    runner_id: UUID
    laboratory_id: UUID
    asset_id: UUID
    test_id: Literal["linux-file-marker/v1"] = TEST_ID
    marker: str
    scope_hash: str
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_bytes: int = Field(ge=1, le=256)
    started_at: AwareDatetime
    ended_at: AwareDatetime
    exit_code: Literal[0] = 0


class JobView(Message):
    spec: JobSpec
    spec_hash: str
    generation: UUID
    state: JobState
    cleanup_state: Literal["PENDING", "CLEANED", "FAILED"]
    reason: str | None
    receipt: ExecutionReceipt | None
    receipt_sha256: str | None


class RunnerIdentity(Message):
    protocol: Literal["aegis-linux-runner/1"] = PROTOCOL
    runner_id: UUID
    laboratory_id: UUID
    asset_id: UUID
    platform: Literal["Linux"] = "Linux"
    tests: tuple[Literal["linux-file-marker/v1"], ...] = (TEST_ID,)
    max_concurrency: Literal[1] = 1
    max_effect_seconds: Literal[5] = 5
    lease_seconds: Literal[2] = 2
    limitation: str = "Comprovante do executor não é evidência de coleta ou detecção por SIEM."
