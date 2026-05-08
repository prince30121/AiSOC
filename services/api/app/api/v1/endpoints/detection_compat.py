"""Frontend-compat detection rule endpoints under /api/v1/detection.

The analyst console (`apps/web/src/lib/api.ts → detectionApi`) talks to
``/api/v1/detection/rules`` and ``/api/v1/detection/test`` with a camelCase,
``enabled``-flag payload shape that pre-dates the v1 ``/api/v1/rules`` router
defined in :mod:`detection_rules`.

Rather than break the canonical backend contract (which other internal
callers, including the MCP server in ``services/mcp``, already rely on) we
publish a thin façade here that:

* GET  /api/v1/detection/rules            → list rules ``{ rules, total }``
* POST /api/v1/detection/rules            → create with frontend shape
* GET  /api/v1/detection/rules/{id}       → single rule frontend shape
* PATCH /api/v1/detection/rules/{id}      → update with frontend shape
* DELETE /api/v1/detection/rules/{id}     → delete tenant-owned rule
* POST /api/v1/detection/test             → execute body+language vs sample

The shim re-uses the SQLAlchemy ORM model and rule-engine helpers so storage,
permissions, and execution semantics stay identical to the canonical router.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, or_, select, update

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.detection_rule import DetectionRule
from app.services.rule_engine import execute_rule

router = APIRouter(prefix="/detection", tags=["detection_rules"])


# ─── Frontend wire models ────────────────────────────────────────────────────


class FrontendDetectionRule(BaseModel):
    """Mirrors `DetectionRule` in apps/web/src/lib/api.ts."""

    id: str
    name: str
    description: str | None = None
    language: str
    body: str
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    severity: str = "medium"
    createdAt: str
    updatedAt: str
    lastTriggeredAt: str | None = None
    hitCount: int = 0


class ListResponse(BaseModel):
    rules: list[FrontendDetectionRule]
    total: int


class CreateBody(BaseModel):
    name: str
    description: str | None = None
    language: str
    body: str
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    severity: str = "medium"
    category: str = "custom"


class UpdateBody(BaseModel):
    name: str | None = None
    description: str | None = None
    language: str | None = None
    body: str | None = None
    enabled: bool | None = None
    tags: list[str] | None = None
    mitre: list[str] | None = None
    severity: str | None = None


class TestBody(BaseModel):
    language: str
    body: str
    sample: str | None = None


class HuntPreviewItem(BaseModel):
    id: str
    timestamp: str
    source: str
    severity: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)


class TestResponse(BaseModel):
    matches: int
    preview: list[HuntPreviewItem]


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _to_frontend(rule: DetectionRule) -> FrontendDetectionRule:
    """Map ORM row → frontend shape."""
    mitre: list[str] = []
    if rule.mitre_techniques:
        mitre.extend(str(t) for t in rule.mitre_techniques)
    if rule.mitre_tactics:
        mitre.extend(str(t) for t in rule.mitre_tactics)

    return FrontendDetectionRule(
        id=str(rule.id),
        name=rule.name,
        description=rule.description,
        language=rule.rule_language,
        body=rule.rule_body,
        enabled=(rule.status == "active"),
        tags=list(rule.tags or []),
        mitre=mitre,
        severity=rule.severity,
        createdAt=rule.created_at.isoformat() if rule.created_at else datetime.now(UTC).isoformat(),
        updatedAt=rule.updated_at.isoformat() if rule.updated_at else datetime.now(UTC).isoformat(),
        lastTriggeredAt=rule.last_triggered.isoformat() if rule.last_triggered else None,
        hitCount=rule.total_hits or 0,
    )


def _parse_sample_events(sample: str | None) -> list[dict[str, Any]]:
    """Best-effort parse of the optional sample blob into events.

    Accepts JSON arrays, NDJSON, or plain text (treated as a single event).
    The detection engine just needs a list of dicts; missing fields are fine.
    """
    if not sample:
        return [{}]

    text = sample.strip()
    if not text:
        return [{}]

    # Try JSON array first.
    if text.startswith("["):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [d if isinstance(d, dict) else {"_raw": d} for d in data]
        except Exception:
            pass

    # Try NDJSON (one JSON object per line).
    events: list[dict[str, Any]] = []
    parsed_any = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            parsed_any = True
            events.append(obj if isinstance(obj, dict) else {"_raw": obj})
        except Exception:
            events.append({"message": line})

    if not parsed_any and not events:
        events = [{"message": text}]

    return events or [{}]


# ─── Routes ──────────────────────────────────────────────────────────────────


@router.get("/rules", response_model=ListResponse)
async def list_rules_compat(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> ListResponse:
    """List detection rules visible to the current tenant (built-ins + tenant-owned)."""
    tid = current_user.tenant_id
    stmt = (
        select(DetectionRule)
        .where(
            or_(
                DetectionRule.tenant_id == tid,
                and_(DetectionRule.tenant_id.is_(None), DetectionRule.is_builtin.is_(True)),
            )
        )
        .order_by(DetectionRule.name)
    )
    result = await db.execute(stmt)
    rules = result.scalars().all()
    items = [_to_frontend(r) for r in rules]
    return ListResponse(rules=items, total=len(items))


@router.post("/rules", response_model=FrontendDetectionRule, status_code=status.HTTP_201_CREATED)
async def create_rule_compat(
    body: CreateBody,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> FrontendDetectionRule:
    """Create a tenant-owned detection rule using the frontend shape."""
    rule = DetectionRule(
        tenant_id=current_user.tenant_id,
        name=body.name,
        description=body.description,
        rule_language=body.language,
        rule_body=body.body,
        category=body.category or "custom",
        severity=body.severity or "medium",
        confidence=50,
        mitre_tactics=[],
        mitre_techniques=list(body.mitre or []),
        tags=list(body.tags or []),
        status="active" if body.enabled else "inactive",
        created_by_id=current_user.user_id,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return _to_frontend(rule)


@router.get("/rules/{rule_id}", response_model=FrontendDetectionRule)
async def get_rule_compat(
    rule_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> FrontendDetectionRule:
    """Fetch a single rule by ID in the frontend shape."""
    stmt = select(DetectionRule).where(
        DetectionRule.id == rule_id,
        or_(
            DetectionRule.tenant_id == current_user.tenant_id,
            DetectionRule.tenant_id.is_(None),
        ),
    )
    rule = (await db.execute(stmt)).scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return _to_frontend(rule)


@router.patch("/rules/{rule_id}", response_model=FrontendDetectionRule)
async def update_rule_compat(
    rule_id: uuid.UUID,
    body: UpdateBody,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> FrontendDetectionRule:
    """Update a tenant-owned rule using the frontend shape."""
    stmt = select(DetectionRule).where(
        DetectionRule.id == rule_id,
        DetectionRule.tenant_id == current_user.tenant_id,
    )
    rule = (await db.execute(stmt)).scalar_one_or_none()
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found or cannot be modified",
        )

    updates: dict[str, Any] = {}
    if body.name is not None:
        updates["name"] = body.name
    if body.description is not None:
        updates["description"] = body.description
    if body.language is not None:
        updates["rule_language"] = body.language
    if body.body is not None:
        updates["rule_body"] = body.body
    if body.severity is not None:
        updates["severity"] = body.severity
    if body.tags is not None:
        updates["tags"] = list(body.tags)
    if body.mitre is not None:
        updates["mitre_techniques"] = list(body.mitre)
    if body.enabled is not None:
        updates["status"] = "active" if body.enabled else "inactive"

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        updates["version"] = (rule.version or 1) + 1
        await db.execute(update(DetectionRule).where(DetectionRule.id == rule_id).values(**updates))
        await db.commit()
        await db.refresh(rule)

    return _to_frontend(rule)


@router.delete(
    "/rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
)
async def delete_rule_compat(
    rule_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> None:
    """Delete a tenant-owned rule."""
    stmt = select(DetectionRule).where(
        DetectionRule.id == rule_id,
        DetectionRule.tenant_id == current_user.tenant_id,
    )
    rule = (await db.execute(stmt)).scalar_one_or_none()
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found or cannot be deleted",
        )
    await db.delete(rule)
    await db.commit()


@router.post("/test", response_model=TestResponse)
async def test_rule_compat(
    body: TestBody,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
) -> TestResponse:
    """Run an ad-hoc rule body against an optional sample event blob.

    The detection IDE in the analyst console hits this with the rule body
    the user is actively editing, which has not been persisted yet, so the
    rule never needs to live in the database.
    """
    events = _parse_sample_events(body.sample)
    rid = f"adhoc-{uuid.uuid4()}"

    match = execute_rule(
        rule_id=rid,
        rule_name="ad-hoc",
        rule_language=body.language or "sigma",
        rule_body=body.body or "",
        severity="medium",
        events=events,
    )

    matched_events: list[dict[str, Any]] = match.match_details.get("matched_events", []) or []

    preview: list[HuntPreviewItem] = []
    now_iso = datetime.now(UTC).isoformat()
    for idx, evt in enumerate(matched_events[:25]):
        if not isinstance(evt, dict):
            evt = {"_raw": evt}
        ts = evt.get("@timestamp") or evt.get("timestamp") or now_iso
        src = evt.get("source") or evt.get("event", {}).get("module") or "sample"
        sev = evt.get("severity") or evt.get("event", {}).get("severity") or "medium"
        preview.append(
            HuntPreviewItem(
                id=str(evt.get("id") or evt.get("_id") or f"sample-{idx}"),
                timestamp=str(ts),
                source=str(src),
                severity=str(sev),
                fields=evt,
            )
        )

    if match.error and not preview:
        # Surface parser errors as a synthetic preview row so the IDE
        # tells the analyst something useful instead of "0 matches".
        preview.append(
            HuntPreviewItem(
                id="rule-error",
                timestamp=now_iso,
                source="rule-engine",
                severity="info",
                fields={"error": match.error, "engine_ms": match.execution_time_ms},
            )
        )

    return TestResponse(matches=len(matched_events), preview=preview)
