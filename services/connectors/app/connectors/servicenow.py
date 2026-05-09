"""
ServiceNow connector.
Fetches security-relevant incidents from the ServiceNow Table API.
"""

from __future__ import annotations

from base64 import b64encode
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_IMPACT_SEVERITY = {
    "1": "high",
    "2": "medium",
    "3": "low",
}


class ServiceNowConnector(BaseConnector):
    connector_id = "servicenow"
    connector_name = "ServiceNow"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="ServiceNow incidents via the Table API.",
            docs_url="/docs/connectors/servicenow",
            fields=[
                Field(
                    "instance_url",
                    "string",
                    "Instance URL",
                    placeholder="https://yourinstance.service-now.com",
                ),
                Field("username", "string", "Username"),
                Field("password", "secret", "Password"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Today the runtime only pulls incidents (alerts). Bidirectional ITSM
        # — PUSH_CASE / PUSH_STATUS — lands in WS8 once we wire writebacks.
        return (Capability.PULL_ALERTS,)

    def __init__(self, instance_url: str, username: str, password: str):
        self._base_url = instance_url.rstrip("/")
        self._username = username
        self._password = password

    def _auth_header(self) -> dict[str, str]:
        creds = b64encode(f"{self._username}:{self._password}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base_url}/api/now/table/incident",
                    headers=self._auth_header(),
                    params={"sysparm_limit": 1},
                )
                resp.raise_for_status()
            return {"success": True, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("servicenow.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self._base_url}/api/now/table/incident",
                headers=self._auth_header(),
                params={
                    "sysparm_query": f"sys_created_on>={since}^ORsys_updated_on>={since}",
                    "sysparm_limit": 100,
                    "sysparm_display_value": "true",
                },
            )
            resp.raise_for_status()
            incidents = resp.json().get("result", [])

        return [self.normalize(i) for i in incidents]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        impact = str(raw.get("impact", "3"))
        if isinstance(impact, dict):
            impact = impact.get("value", "3")

        return {
            "source": self.connector_id,
            "external_id": raw.get("sys_id", ""),
            "title": raw.get("short_description", "ServiceNow Incident"),
            "description": raw.get("description", "")[:500],
            "severity": _IMPACT_SEVERITY.get(str(impact), "low"),
            "src_ip": None,
            "hostname": raw.get("cmdb_ci", {}).get("display_value") if isinstance(raw.get("cmdb_ci"), dict) else raw.get("cmdb_ci"),
            "actor": raw.get("opened_by", {}).get("display_value") if isinstance(raw.get("opened_by"), dict) else raw.get("opened_by"),
            "raw_event": raw,
            "created_at": raw.get("sys_created_on"),
        }
