from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis.lab_runner import atomic_policy

PROTOCOL = "aegis-linux-runner/1"
TEST_ID = "linux-file-marker/v1"
MAX_EFFECT_SECONDS = 5
LEASE_SECONDS = 2
TestId = Literal[
    "linux-file-marker/v1",
    "atomic-file-permissions/v1@9e283889776cbd42ebf9b7b25bc1ebfbad452157398ecbe0ab77415136c35673",
]


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class JobSpec(Message):
    protocol: Literal["aegis-linux-runner/1"] = PROTOCOL
    test_id: TestId = TEST_ID
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


class AtomicExecutionReceipt(ExecutionReceipt):
    test_id: Literal[
        "atomic-file-permissions/v1@9e283889776cbd42ebf9b7b25bc1ebfbad452157398ecbe0ab77415136c35673"
    ] = atomic_policy.TEST_ID
    mode_before: Literal[256]
    mode_after: Literal[384]


class JobView(Message):
    spec: JobSpec
    spec_hash: str
    generation: UUID
    state: JobState
    cleanup_state: Literal["PENDING", "CLEANED", "FAILED"]
    reason: str | None
    receipt: AtomicExecutionReceipt | ExecutionReceipt | None
    receipt_sha256: str | None

    @model_validator(mode="after")
    def receipt_test(self):
        if self.receipt is not None and self.receipt.test_id != self.spec.test_id:
            raise ValueError("Recibo de outro teste.")
        return self


class RunnerIdentity(Message):
    protocol: Literal["aegis-linux-runner/1"] = PROTOCOL
    runner_id: UUID
    laboratory_id: UUID
    asset_id: UUID
    platform: Literal["Linux"] = "Linux"
    tests: tuple[TestId, ...] = (TEST_ID,)
    max_concurrency: Literal[1] = 1
    max_effect_seconds: Literal[5] = 5
    lease_seconds: Literal[2] = 2
    limitation: str = "Comprovante do executor não é evidência de coleta ou detecção por SIEM."
