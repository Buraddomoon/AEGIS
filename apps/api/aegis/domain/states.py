from enum import StrEnum


class State(StrEnum):
    CREATED = "CREATED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    QUEUED = "QUEUED"
    PREPARING = "PREPARING"
    RUNNING = "RUNNING"
    COLLECTING = "COLLECTING"
    VALIDATING = "VALIDATING"
    CLEANING_UP = "CLEANING_UP"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    CLEANUP_FAILED = "CLEANUP_FAILED"


TERMINAL = {
    State.COMPLETED,
    State.REJECTED,
    State.FAILED,
    State.TIMED_OUT,
    State.CANCELLED,
    State.CLEANUP_FAILED,
}
ACTIVE = {State.PREPARING, State.RUNNING, State.COLLECTING, State.VALIDATING, State.CLEANING_UP}
ALLOWED: dict[State, set[State]] = {
    State.CREATED: {State.PENDING_APPROVAL},
    State.PENDING_APPROVAL: {State.QUEUED, State.REJECTED, State.CANCELLED},
    State.QUEUED: {State.PREPARING, State.CANCELLED, State.TIMED_OUT, State.REJECTED},
    State.PREPARING: {State.RUNNING, State.CLEANING_UP},
    State.RUNNING: {State.COLLECTING, State.CLEANING_UP},
    State.COLLECTING: {State.VALIDATING, State.CLEANING_UP},
    State.VALIDATING: {State.CLEANING_UP},
    State.CLEANING_UP: TERMINAL - {State.REJECTED},
}


def check_transition(old: str, new: str) -> None:
    if State(new) not in ALLOWED.get(State(old), set()):
        raise ValueError(f"Transição inválida: {old} → {new}")
