from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class ExecutionContext:
    execution_id: str
    laboratory_id: str
    asset_id: str
    marker: str
    behavior: str
    started_at: datetime
    ended_at: datetime
    synthetic: bool
    expected_rule: str


@dataclass(frozen=True)
class Event:
    source_id: str
    source: str
    timestamp: datetime
    laboratory_id: str
    asset_id: str
    execution_id: str
    marker: str
    behavior: str
    kind: str
    rule_id: str | None
    synthetic: bool
    raw: dict[str, Any]


@dataclass(frozen=True)
class Collection:
    events: tuple[Event, ...]
    telemetry_available: bool
    alerts_available: bool
    complete: bool = True
    error: str | None = None


class ExecutionAdapter(Protocol):
    def prepare(self, context: ExecutionContext) -> None: ...
    def execute(self, context: ExecutionContext) -> bool: ...
    def cleanup(self, context: ExecutionContext) -> None: ...


class TelemetryProvider(Protocol):
    def collect(self, context: ExecutionContext) -> Collection: ...


class DetectionProvider(Protocol):
    def alerts(self, context: ExecutionContext) -> Collection: ...


class TestCatalogProvider(Protocol):
    def import_metadata(self, content: str) -> list[dict[str, Any]]: ...


class ReportExporter(Protocol):
    def export(self, report: dict[str, Any]) -> str: ...
