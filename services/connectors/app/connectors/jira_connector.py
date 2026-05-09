"""
Jira connector.
Fetches security-relevant issues from Jira Cloud via the REST API.
"""

from __future__ import annotations

from base64 import b64encode
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_PRIORITY_SEVERITY = {
    "Highest": "high",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Lowest": "info",
}


class JiraConnector(BaseConnector):
    connector_id = "jira"
    connector_name = "Jira"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Jira Cloud issues via the REST API v3.",
            docs_url="/docs/connectors/jira",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Jira Base URL",
                    placeholder="https://yourorg.atlassian.net",
                ),
                Field("email", "string", "Email"),
                Field("api_token", "secret", "API Token"),
            ],
            # Hosted OAuth (Workstream 2): Atlassian 3LO. We map a Jira
            # Cloud site to the {site_id} placeholder by hitting the
            # accessible-resources endpoint after the token exchange.
            # Atlassian mandates PKCE + the audience=api.atlassian.com
            # parameter; the /oauth/start handler injects both.
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://auth.atlassian.com/authorize",
                token_url="https://auth.atlassian.com/oauth/token",
                scopes=[
                    "read:jira-work",
                    "read:jira-user",
                    "write:jira-work",
                    "manage:jira-webhook",
                    "offline_access",
                ],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Today the Jira connector only pulls security-tagged issues as alerts.
        # Bidirectional ticketing (PUSH_CASE / PUSH_STATUS) lands in WS8.
        return (Capability.PULL_ALERTS,)

    def __init__(self, base_url: str, email: str, api_token: str):
        self._base_url = base_url.rstrip("/")
        self._email = email
        self._api_token = api_token

    def _auth_header(self) -> dict[str, str]:
        creds = b64encode(f"{self._email}:{self._api_token}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base_url}/rest/api/3/myself",
                    headers=self._auth_header(),
                )
                resp.raise_for_status()
                user = resp.json()
            return {
                "success": True,
                "connector": self.connector_id,
                "user": user.get("displayName"),
            }
        except Exception as exc:
            logger.warning("jira.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        minutes_ago = max(since_seconds // 60, 1)
        jql = f"updated >= -{minutes_ago}m ORDER BY updated DESC"

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self._base_url}/rest/api/3/search",
                headers=self._auth_header(),
                params={
                    "jql": jql,
                    "maxResults": 100,
                    "fields": "summary,description,priority,status,creator,created,updated",
                },
            )
            resp.raise_for_status()
            issues = resp.json().get("issues", [])

        return [self.normalize(i) for i in issues]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        fields = raw.get("fields", {})
        priority_name = (fields.get("priority") or {}).get("name", "Medium")
        creator = fields.get("creator") or {}
        description_body = fields.get("description")
        if isinstance(description_body, dict):
            description_body = description_body.get("text", str(description_body))

        return {
            "source": self.connector_id,
            "external_id": raw.get("key", raw.get("id", "")),
            "title": fields.get("summary", "Jira Issue"),
            "description": str(description_body or "")[:500],
            "severity": _PRIORITY_SEVERITY.get(priority_name, "medium"),
            "src_ip": None,
            "hostname": None,
            "actor": creator.get("displayName") or creator.get("emailAddress"),
            "raw_event": raw,
            "created_at": fields.get("created"),
        }
