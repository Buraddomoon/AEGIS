"""Account maintenance. Serialize identity writes, including login, in PostgreSQL."""

from fastapi import HTTPException, Request
from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from aegis.models import Approval, CampaignRun, LoginSession, User
from aegis.security import audit, current_user, hasher, rate_limit, verify_password


def lock(db: Session) -> None:
    # Same order for login/create/edit/password/revoke. No lock on run/lab rows.
    db.execute(text("SELECT pg_advisory_xact_lock(16490872)"))


def actor(db: Session, request: Request, *, admin: bool = False) -> User:
    lock(db)
    # Dependencies may have read the identity before waiting for another writer.
    db.expire_all()
    user = current_user(request, db)
    if admin and user.role != "administrator":
        raise HTTPException(403, "Seu papel não permite esta operação.")
    rate_limit("identity-write:" + user.id, 30, 3600)
    return user


def target(db: Session, identifier: str) -> User:
    user = db.get(User, identifier)
    if not user:
        raise HTTPException(404, "Usuário não encontrado.")
    return user


def revoke(db: Session, user: User) -> int:
    result = db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    return result.rowcount


def update(db: Session, user: User, item: User, role: str, active: bool) -> None:
    if item.role == role and item.active == active:
        return
    if item.active and item.role == "administrator" and (not active or role != "administrator"):
        admins = db.scalar(
            select(func.count()).select_from(User).where(User.active, User.role == "administrator")
        )
        if admins <= 1:
            raise HTTPException(409, "O último administrador ativo deve ser preservado.")
    before = {"role": item.role, "active": item.active}
    item.role, item.active = role, active
    count = revoke(db, item)
    audit(
        db,
        user.id,
        "user.update",
        item.id,
        before=before,
        role=role,
        active=active,
        revoked_sessions=count,
    )


def password(db: Session, user: User, item: User, value: str, current: str | None = None) -> None:
    if current is not None and not verify_password(item.password_hash, current):
        audit(db, user.id, "user.password_failed", item.id)
        db.commit()
        raise HTTPException(403, "Senha atual inválida.")
    item.password_hash = hasher.hash(value)
    count = revoke(db, item)
    audit(
        db,
        user.id,
        "user.password_change" if current is not None else "user.password_reset",
        item.id,
        revoked_sessions=count,
    )


def approval_identities_valid(db: Session, run: CampaignRun, approval: Approval | None) -> bool:
    requester = db.get(User, run.requested_by)
    approver = db.get(User, approval.approved_by) if approval else None
    return bool(
        requester
        and requester.active
        and requester.role in ("operator", "administrator")
        and approver
        and approver.active
        and approver.role == "administrator"
    )
