"""
Tests for ``app.interactions``.

Covered branches
----------------

* approve / deny route to the matching client method
* upstream errors translate to ephemeral error blocks (no traceback leaks)
* malformed button values translate to ephemeral error blocks
* unknown action ids translate to ephemeral error blocks
* successful decisions emit ``replace_original=True`` so the approval card
  can't be clicked twice
* the post-decision message records the deciding user (audit trail)
* the post-decision message survives a sparse upstream response (we
  fall back to the routing-decoded action id)
"""

from __future__ import annotations

from typing import Any

import pytest
from app.interactions import (
    APPROVE_ACTION_ID,
    DENY_ACTION_ID,
    handle_action_decision,
)
from app.services.aisoc_clients import AisocClientError


class FakeActionsClient:
    """Minimal stand-in for :class:`AisocActionsClient` for interaction tests."""

    def __init__(
        self,
        *,
        approve_response: dict[str, Any] | None = None,
        reject_response: dict[str, Any] | None = None,
        raise_on: str | None = None,
    ) -> None:
        self._approve_response = approve_response or {
            "id": "act-1",
            "status": "approved",
            "action_type": "isolate_host",
            "target": "host-1",
        }
        self._reject_response = reject_response or {
            "id": "act-1",
            "status": "rejected",
            "action_type": "isolate_host",
            "target": "host-1",
        }
        self._raise_on = raise_on
        self.approve_calls: list[str] = []
        self.reject_calls: list[str] = []

    async def approve_action(self, action_id: str) -> dict[str, Any]:
        if self._raise_on == "approve":
            raise AisocClientError("upstream approve boom", status_code=502)
        self.approve_calls.append(action_id)
        return self._approve_response

    async def reject_action(self, action_id: str) -> dict[str, Any]:
        if self._raise_on == "reject":
            raise AisocClientError("upstream reject boom", status_code=502)
        self.reject_calls.append(action_id)
        return self._reject_response


def _flatten(blocks: list[dict[str, Any]]) -> str:
    return str(blocks)


# ────────────────────────────────────────────────────────────────────────────
# Happy paths
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_approve_replaces_card_and_records_decider():
    actions = FakeActionsClient()
    res = await handle_action_decision(
        action_id_event=APPROVE_ACTION_ID,
        button_value="act-7|case-3",
        user_id="U42",
        actions_client=actions,
    )
    assert actions.approve_calls == ["act-7"]
    assert actions.reject_calls == []
    # Replace original guarantees the buttons can't be clicked twice.
    assert res["replace_original"] is True
    assert res["response_type"] == "in_channel"
    rendered = _flatten(res["blocks"])
    assert "U42" in rendered
    assert "approved" in rendered.lower()


@pytest.mark.asyncio
async def test_deny_replaces_card_and_calls_reject_client():
    actions = FakeActionsClient()
    res = await handle_action_decision(
        action_id_event=DENY_ACTION_ID,
        button_value="act-9|case-3",
        user_id="U42",
        actions_client=actions,
    )
    assert actions.reject_calls == ["act-9"]
    assert actions.approve_calls == []
    assert res["replace_original"] is True
    rendered = _flatten(res["blocks"])
    assert "denied" in rendered.lower() or "rejected" in rendered.lower()


@pytest.mark.asyncio
async def test_value_without_case_id_is_accepted():
    """
    The case id in the routing value is informational only — we still want to
    let the analyst's decision land if Slack ever truncates or reformats the
    value. The action id is the only required field.
    """
    actions = FakeActionsClient()
    res = await handle_action_decision(
        action_id_event=APPROVE_ACTION_ID,
        button_value="act-only",
        user_id="U1",
        actions_client=actions,
    )
    assert actions.approve_calls == ["act-only"]
    assert res.get("replace_original") is True


# ────────────────────────────────────────────────────────────────────────────
# Defensive / error paths
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unknown_action_id_returns_ephemeral_error_without_calling_client():
    actions = FakeActionsClient()
    res = await handle_action_decision(
        action_id_event="aisoc_action_open_case",  # not approve/deny
        button_value="act-7|case-3",
        user_id="U42",
        actions_client=actions,
    )
    assert res["response_type"] == "ephemeral"
    assert "Unknown interactive action" in _flatten(res["blocks"])
    assert actions.approve_calls == []
    assert actions.reject_calls == []


@pytest.mark.asyncio
async def test_empty_button_value_returns_ephemeral_error():
    actions = FakeActionsClient()
    res = await handle_action_decision(
        action_id_event=APPROVE_ACTION_ID,
        button_value="",
        user_id="U42",
        actions_client=actions,
    )
    assert res["response_type"] == "ephemeral"
    assert "approval button" in _flatten(res["blocks"])
    assert actions.approve_calls == []


@pytest.mark.asyncio
async def test_button_value_with_no_action_id_returns_ephemeral_error():
    actions = FakeActionsClient()
    res = await handle_action_decision(
        action_id_event=APPROVE_ACTION_ID,
        button_value="|case-3",  # action_id half is empty
        user_id="U42",
        actions_client=actions,
    )
    assert res["response_type"] == "ephemeral"
    assert "approval button" in _flatten(res["blocks"])
    assert actions.approve_calls == []


@pytest.mark.asyncio
async def test_upstream_failure_translates_to_ephemeral_error():
    actions = FakeActionsClient(raise_on="approve")
    res = await handle_action_decision(
        action_id_event=APPROVE_ACTION_ID,
        button_value="act-7|case-3",
        user_id="U42",
        actions_client=actions,
    )
    assert res["response_type"] == "ephemeral"
    rendered = _flatten(res["blocks"])
    assert "act-7" in rendered
    assert "Could not record decision" in rendered
    # The original approval card must NOT be replaced when the call fails —
    # otherwise the analyst loses the buttons and can't retry.
    assert "replace_original" not in res


@pytest.mark.asyncio
async def test_sparse_upstream_response_falls_back_to_routing_action_id():
    """
    If services/actions returns a payload missing ``id``/``action_id``, we
    must still surface a useful audit-trail line. We fall back to the id
    decoded from the routing value.
    """
    actions = FakeActionsClient(
        approve_response={"status": "approved"}  # no id/action_id/target
    )
    res = await handle_action_decision(
        action_id_event=APPROVE_ACTION_ID,
        button_value="act-fallback|case-3",
        user_id="U42",
        actions_client=actions,
    )
    assert res.get("replace_original") is True
    assert "act-fallback" in _flatten(res["blocks"])
