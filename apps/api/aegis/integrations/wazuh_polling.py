"""Bounded ingestion polling. A positive alert does not require a negative-search window."""

import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime

from aegis.domain.contracts import Collection, ExecutionContext
from aegis.domain.validation import Outcome, digest, validate
from aegis.integrations.wazuh import WazuhIndexerProvider


class WazuhPollingProvider:
    def __init__(
        self,
        provider: WazuhIndexerProvider,
        deadline: datetime,
        guard: Callable[[], None],
        *,
        clock=time.monotonic,
        sleep=time.sleep,
    ):
        if provider.policy is None:
            raise ValueError("Polling exige política revisada.")
        self.provider, self.deadline, self.guard = provider, deadline, guard
        self.clock, self.sleep = clock, sleep
        self.summary = {"attempts": 0, "window_satisfied": False, "reason": "Coleta não iniciada."}

    def collect(self, context: ExecutionContext) -> Collection:
        policy = self.provider.policy
        started = datetime.now(UTC)
        begin = self.clock()
        horizon = begin + policy.ingestion_wait_seconds
        budget = begin + max(0, (self.deadline - started).total_seconds() - 5)
        self.provider.budget_end = min(horizon + policy.request_timeout_seconds * 2, budget)
        self.provider.guard = self.guard
        events, fingerprints, conflicts = {}, {}, set()
        last = Collection((), False, False, False, "Orçamento insuficiente para coleta.")
        self.summary["started_at"] = started
        try:
            for _ in range(64):
                self.guard()
                if self.clock() >= self.provider.budget_end:
                    break
                snapshot_started = self.clock()
                last = self.provider.collect_once(context)
                self.summary["attempts"] += 1
                for event in last.events:
                    key, fingerprint = (event.source, event.source_id), digest(event.raw)
                    if key in fingerprints and fingerprints[key] != fingerprint:
                        conflicts.add(key)
                        events.pop(key, None)
                    elif key not in conflicts:
                        events[key] = event
                    fingerprints[key] = fingerprint
                if len(fingerprints) > 5000:
                    last = replace(
                        last, complete=False, error="Limite de documentos da coleta atingido."
                    )
                    break
                window = snapshot_started >= horizon
                self.summary["window_satisfied"] = window
                combined = replace(last, events=tuple(events.values()))
                if (
                    validate(
                        context,
                        combined,
                        True,
                        policy.clock_skew_seconds,
                        policy.ingestion_window_seconds,
                    ).outcome
                    == Outcome.DETECTED
                ):
                    return combined
                if window:
                    break
                wait = min(
                    policy.poll_interval_seconds,
                    horizon - self.clock(),
                    self.provider.budget_end - self.clock(),
                )
                if wait > 0:
                    # Keep cancellation/deadline responsive even with a long polling interval.
                    end = self.clock() + wait
                    while self.clock() < end:
                        self.guard()
                        # Ownership/approval checks may outlast this slice.
                        remaining = end - self.clock()
                        if remaining > 0:
                            self.sleep(min(0.1, remaining))
            complete = (
                last.complete
                and self.summary["window_satisfied"]
                and not conflicts
                and len(fingerprints) <= 5000
            )
            last = replace(
                last,
                events=tuple(events.values()),
                complete=bool(complete),
                error=None
                if complete
                else "Janela de ingestão ou consulta incompleta; ausência de alerta é inconclusiva.",
            )
            return last
        finally:
            self.provider.close()
            self.summary.update(
                {
                    "ended_at": datetime.now(UTC),
                    "reason": "Coleta finalizada; inspecione disponibilidade e janela.",
                }
            )
