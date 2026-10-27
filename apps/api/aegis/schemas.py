from datetime import datetime
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Login(Input):
    # Password whitespace is significant, including for interactive CLI bootstrap.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)
    username: str = Field(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9_.@-]+$")
    password: str = Field(min_length=1, max_length=128)


class UserCreate(Login):
    password: str = Field(min_length=12, max_length=128)
    role: Literal["administrator", "operator", "viewer"]


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    username: str
    role: str
    active: bool


class CampaignCreate(Input):
    name: str = Field(min_length=3, max_length=160)
    objective: str = Field(min_length=5, max_length=4000)
    laboratory_id: str = Field(min_length=36, max_length=36)
    test_ids: list[str] = Field(min_length=1, max_length=20)


class RunRequest(Input):
    idempotency_key: str = Field(min_length=16, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")


class Approve(Input):
    confirm_scope_hash: str = Field(min_length=64, max_length=64)
    validity_minutes: int = Field(default=15, ge=1, le=60)
    max_duration_seconds: int = Field(default=60, ge=10, le=300)
    confirm_real_execution: bool = False


class Confirm(Input):
    confirm: Literal[True]


class LabAuthorization(Input):
    authorized: bool


class LinuxRegistration(Input):
    name: str = Field(min_length=3, max_length=120)
    owner: str = Field(min_length=3, max_length=120)
    isolation_review: str = Field(min_length=20, max_length=4000)
    confirm_isolation_review: Literal[True]


class BindingReviewRead(BaseModel):
    format: Literal["aegis-linux-binding-review/1"]
    laboratory_id: str
    environment_version: int
    reviewed_at: AwareDatetime
    status: Literal["blocked", "persisted_prerequisites_satisfied"]
    blockers: list[str]
    nonterminal_runs: int
    nonterminal_tests: int
    dispatches_examined: int
    dispatch_history_complete: bool
    unconfirmed_cleanup_count: int
    unconfirmed_execution_ids: list[str]
    unconfirmed_sample_truncated: bool
    runner_contacted: Literal[False]
    journal_verified: Literal[False]
    activation_permitted: Literal[False]
    normal_operation_permitted: Literal[False]


class WazuhBindingReview(Input):
    review: str = Field(min_length=20, max_length=4000)
    confirm_read_only_scope: Literal[True]


class SigmaImport(Input):
    content: str = Field(min_length=10, max_length=65536)


class RuleTestReview(Input):
    rule_version_id: str = Field(min_length=36, max_length=36)
    test_id: str = Field(min_length=1, max_length=60)
    confirm_rule_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm_test_version: int = Field(ge=1)
    rationale: str = Field(min_length=20, max_length=4000)
    replaces_id: str | None = Field(default=None, min_length=36, max_length=36)


class RunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    campaign_id: str
    laboratory_id: str
    requested_by: str
    schedule_id: str | None
    state: str
    scope_hash: str
    scope: dict
    synthetic: bool
    cancel_requested: bool
    error: str | None
    created_at: datetime
    started_at: datetime | None
    ended_at: datetime | None
    deadline_at: datetime | None


class ScheduleCreate(Input):
    campaign_id: str = Field(min_length=36, max_length=36)
    interval_seconds: int = Field(ge=60, le=2592000)
    max_occurrences: int = Field(ge=1, le=100)
    max_duration_seconds: int = Field(default=60, ge=10, le=300)
    starts_at: AwareDatetime
    ends_at: AwareDatetime

    @model_validator(mode="after")
    def window(self):
        if self.ends_at <= self.starts_at:
            raise ValueError("Fim deve ser posterior ao início.")
        if self.interval_seconds < self.max_duration_seconds:
            raise ValueError("Intervalo deve comportar a duração máxima.")
        return self


class ScheduleApprove(Input):
    confirm_plan_hash: str = Field(min_length=64, max_length=64)
    confirm_automatic_execution: Literal[True]
