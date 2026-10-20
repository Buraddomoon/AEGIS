import hashlib
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy.orm import Session

from aegis.config import settings
from aegis.db import get_db
from aegis.models import AuditEvent, LoginSession, User, now

hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_HASH = hasher.hash(secrets.token_urlsafe(32))


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def redis_client() -> Redis:
    return Redis.from_url(settings().redis_url, socket_timeout=2, socket_connect_timeout=2)


def audit(db: Session, actor: str | None, action: str, resource: str, **details) -> None:
    db.add(AuditEvent(actor_id=actor, action=action, resource_id=resource, details=details))


def rate_limit(key: str, limit: int = 10, seconds: int = 300) -> None:
    script = """
    local count = redis.call('INCR', KEYS[1])
    if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
    return count
    """
    try:
        count = redis_client().eval(script, 1, "aegis:limit:" + token_hash(key), seconds)
    except RedisError:
        raise HTTPException(503, "Limitador de autenticação indisponível.") from None
    if int(count) > limit:
        raise HTTPException(429, "Muitas tentativas; aguarde antes de tentar novamente.",
                            headers={"Retry-After": str(seconds)})


def verify_password(stored: str, password: str) -> bool:
    try:
        return hasher.verify(stored, password)
    except (VerificationError, InvalidHashError):
        return False


def create_session(db: Session, user: User) -> tuple[str, str]:
    token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    db.add(LoginSession(token_hash=token_hash(token), user_id=user.id,
                        csrf_hash=token_hash(csrf),
                        expires_at=now() + timedelta(hours=settings().session_hours)))
    return token, csrf


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get("aegis_session", "")
    session = db.get(LoginSession, token_hash(token)) if token else None
    if not session or session.expires_at <= now():
        raise HTTPException(401, "Autenticação necessária.")
    user = db.get(User, session.user_id)
    if not user or not user.active:
        raise HTTPException(401, "Sessão inválida.")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        supplied = request.headers.get("x-csrf-token", "")
        if not supplied or not secrets.compare_digest(token_hash(supplied), session.csrf_hash):
            raise HTTPException(403, "Token CSRF inválido.")
    request.state.session = session
    return user


def require_roles(*roles: str):
    def dependency(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "Seu papel não permite esta operação.")
        return user
    return dependency


operator = require_roles("administrator", "operator")
administrator = require_roles("administrator")
