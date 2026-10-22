"""Human planning reviews; never used to decide detection verdicts."""

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.models import DetectionRule, RuleTestLink, RuleVersion, TestDefinition, User, now
from aegis.schemas import RuleTestReview
from aegis.security import audit


def link_query():
    return (
        select(RuleTestLink, RuleVersion, DetectionRule, TestDefinition)
        .join(RuleVersion, RuleVersion.id == RuleTestLink.rule_version_id)
        .join(DetectionRule, DetectionRule.id == RuleTestLink.rule_id)
        .join(TestDefinition, TestDefinition.id == RuleTestLink.test_id)
    )


def describe(link: RuleTestLink, version: RuleVersion, rule: DetectionRule, test: TestDefinition):
    return {
        "id": link.id,
        "rule_id": rule.id,
        "current_rule_title": rule.title,
        "sigma_id": rule.sigma_id,
        "rule_version_id": version.id,
        "rule_version": version.version,
        "rule_sha256": version.sha256,
        "latest_rule_version": rule.latest_version,
        "test_id": test.id,
        "test_name": test.name,
        "test_version": link.test_version,
        "current_test_version": test.version,
        "rationale": link.rationale,
        "created_by": link.created_by,
        "created_at": link.created_at.isoformat(),
        "retired_at": link.retired_at.isoformat() if link.retired_at else None,
        "retired_by": link.retired_by,
        "review_required": version.version != rule.latest_version
        or link.test_version != test.version,
        "purpose": "planning_only_not_deployed",
    }


def list_links(
    db: Session,
    *,
    rule_id: str | None = None,
    test_id: str | None = None,
    include_retired: bool = False,
    offset: int = 0,
    limit: int = 50,
) -> dict:
    query = link_query()
    if rule_id:
        query = query.where(RuleTestLink.rule_id == rule_id)
    if test_id:
        query = query.where(RuleTestLink.test_id == test_id)
    if not include_retired:
        query = query.where(RuleTestLink.retired_at.is_(None))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.execute(
        query.order_by(RuleTestLink.created_at.desc(), RuleTestLink.id).offset(offset).limit(limit)
    )
    return {
        "items": [describe(*row) for row in rows],
        "total": total,
        "offset": offset,
        "limit": limit,
    }


def snapshot_links(db: Session, test_ids: list[str]) -> list[dict]:
    rows = db.execute(
        link_query()
        .where(
            RuleTestLink.test_id.in_(test_ids),
            RuleTestLink.retired_at.is_(None),
        )
        .order_by(RuleTestLink.rule_id, RuleTestLink.test_id)
    )
    return [describe(*row) for row in rows]


def lock_rule(db: Session, rule_id: str) -> DetectionRule:
    rule = db.scalar(select(DetectionRule).where(DetectionRule.id == rule_id).with_for_update())
    if not rule:
        raise HTTPException(404, "Regra não encontrada.")
    return rule


def review(db: Session, rule_id: str, data: RuleTestReview, actor: User) -> RuleTestLink:
    rule = lock_rule(db, rule_id)
    version = db.get(RuleVersion, data.rule_version_id)
    test = db.get(TestDefinition, data.test_id)
    if not version or version.rule_id != rule.id or not test:
        raise HTTPException(404, "Versão da regra ou teste não encontrado.")
    if (
        version.sha256 != data.confirm_rule_sha256
        or version.version != rule.latest_version
        or test.version != data.confirm_test_version
    ):
        raise HTTPException(409, "Versões mudaram; atualize e revise o vínculo novamente.")
    current = db.scalar(
        select(RuleTestLink).where(
            RuleTestLink.rule_id == rule.id,
            RuleTestLink.test_id == test.id,
            RuleTestLink.retired_at.is_(None),
        )
    )
    if (current.id if current else None) != data.replaces_id:
        raise HTTPException(409, "Vínculo alterado por outra revisão; atualize a lista.")
    if current:
        current.retired_at, current.retired_by = now(), actor.id
        db.flush()
    link = RuleTestLink(
        rule_id=rule.id,
        rule_version_id=version.id,
        test_id=test.id,
        test_version=test.version,
        rationale=data.rationale,
        created_by=actor.id,
    )
    db.add(link)
    db.flush()
    audit(
        db,
        actor.id,
        "sigma.test_link.review",
        link.id,
        rule_id=rule.id,
        rule_version_id=version.id,
        test_id=test.id,
        test_version=test.version,
        replaces_id=data.replaces_id,
    )
    db.commit()
    return link


def retire(db: Session, rule_id: str, link_id: str, actor: User) -> RuleTestLink:
    lock_rule(db, rule_id)
    link = db.get(RuleTestLink, link_id)
    if not link or link.rule_id != rule_id:
        raise HTTPException(404, "Vínculo não encontrado.")
    if not link.retired_at:
        link.retired_at, link.retired_by = now(), actor.id
        audit(db, actor.id, "sigma.test_link.retire", link.id, rule_id=rule_id)
        db.commit()
    return link
