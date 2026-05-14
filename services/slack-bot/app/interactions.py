"""
Interactive component handlers for the AiSOC Slack bot.

Slack delivers a single ``block_actions`` payload whenever the analyst
clicks a button on a message we sent. This module isolates the *logic*
side of those events — the decoding of the routing token, the call into
``services/actions``, and the construction of the reply blocks — from
the Bolt transport layer in :mod:`app.main`.

Why a pure-Python module again
==============================

Same reasoning as :mod:`app.commands`:

* the Bolt wrapper stays a 5-line shim (``ack`` → ``handle_action_decision``
  → ``respond``)
* every branch — happy path, malformed value, upstream failure — is
  covered by a fast hermetic unit test
* error messages never leak a stack trace into a public Slack channel

Action ids
----------

The approval card emits two button ids that this module knows how to
handle:

* ``aisoc_action_approve``
* ``aisoc_action_deny``

The button ``value`` is encoded by :func:`app.blocks.approval_card_blocks`
as ``"<action_id>|<case_id>"``. We decode that here so the dispatcher
can avoid a database lookup just to know which case the button belonged
to (handy for the audit-trail message we post after the decision).
"""

from __future__ import annotations

from typing import Any

from app.blocks import action_decision_blocks, error_blocks
from app.services.aisoc_clients import AisocActionsClient, AisocClientError

#: Action id emitted by the *Approve* button on the approval card.
APPROVE_ACTION_ID = "aisoc_action_approve"

#: Action id emitted by the *Deny* button on the approval card.
DENY_ACTION_ID = "aisoc_action_deny"

#: Decision strings we send back to ``services/actions``. Kept in a constant
#: so a typo can't slip into the network payload.
_DECISION_APPROVE = "approved"
_DECISION_REJECT = "rejected"


def _decode_routing_value(value: str) -> tuple[str, str]:
    """
    Pull ``action_id`` and ``case_id`` out of the button ``value``.

    The encoder is :func:`app.blocks.approval_card_blocks`, which uses the
    format ``"<action_id>|<case_id>"``. We accept a missing case id (the
    case id is informational on the audit-trail line and not strictly
    required to call ``services/actions``), but a missing action id is
    fatal — the upstream call is meaningless without it.

    Raises
    ------
    ValueError
        If ``value`` is empty or does not contain a non-empty action id.
    """
    if not value:
        raise ValueError("missing routing value on action button")
    parts = value.split("|", 1)
    action_id = parts[0].strip()
    case_id = parts[1].strip() if len(parts) > 1 else ""
    if not action_id:
        raise ValueError("routing value is missing the action id")
    return action_id, case_id


def _ephemeral(blocks: list[dict[str, Any]], *, fallback: str) -> dict[str, Any]:
    """
    Private follow-up message visible only to the analyst who clicked.

    Used for parser/upstream errors so we don't pollute the channel with
    failure noise.
    """
    return {"response_type": "ephemeral", "text": fallback, "blocks": blocks}


def _replace_card(blocks: list[dict[str, Any]], *, fallback: str) -> dict[str, Any]:
    """
    Replace the original approval card in-place with the post-decision
    audit-trail line.

    ``replace_original=True`` tells Slack to swap the message we sent
    earlier rather than append a new one — that way the buttons can't be
    clicked twice (defence in depth on top of the idempotency guarantees
    in ``services/actions``).
    """
    return {
        "replace_original": True,
        "response_type": "in_channel",
        "text": fallback,
        "blocks": blocks,
    }


async def handle_action_decision(
    *,
    action_id_event: str,
    button_value: str,
    user_id: str,
    actions_client: AisocActionsClient,
) -> dict[str, Any]:
    """
    Resolve an approve/deny click into a Slack response payload.

    Parameters
    ----------
    action_id_event
        The Slack ``action_id`` of the button — one of
        :data:`APPROVE_ACTION_ID` or :data:`DENY_ACTION_ID`.
    button_value
        The button's ``value`` field, encoded by
        :func:`app.blocks.approval_card_blocks` as
        ``"<action_id>|<case_id>"``.
    user_id
        The Slack user id of the analyst who clicked. Recorded on the
        post-decision message so the audit trail in chat matches the
        case timeline.
    actions_client
        Client for ``services/actions``.

    Returns
    -------
    dict
        A Slack response payload. Successful decisions use
        ``replace_original=True`` to swap the approval card with an
        audit-trail line so the buttons can't be clicked again.

    Notes
    -----
    The function never raises — every failure path is converted into an
    ephemeral error block so the analyst always gets actionable feedback
    in Slack and we never leak a stack trace.
    """
    if action_id_event not in {APPROVE_ACTION_ID, DENY_ACTION_ID}:
        # Defensive: Bolt should never route an unrelated action here, but
        # keep the surface honest if a future refactor changes the wiring.
        return _ephemeral(
            error_blocks(f"Unknown interactive action `{action_id_event}`"),
            fallback="Unknown interactive action",
        )

    try:
        action_id, _case_id = _decode_routing_value(button_value)
    except ValueError as exc:
        return _ephemeral(
            error_blocks(f"Couldn't decode the approval button: {exc}"),
            fallback="Bad approval payload",
        )

    is_approve = action_id_event == APPROVE_ACTION_ID
    decision_label = _DECISION_APPROVE if is_approve else _DECISION_REJECT

    try:
        action = await actions_client.approve_action(action_id) if is_approve else await actions_client.reject_action(action_id)
    except AisocClientError as exc:
        return _ephemeral(
            error_blocks(f"Could not record decision for action `{action_id}`: {exc}"),
            fallback="Decision failed",
        )

    # Make sure the audit-trail line shows the action context even if the
    # backend response is sparse. Falling back to the routing-decoded id
    # guarantees we always show *something* useful.
    if not action.get("id") and not action.get("action_id"):
        action = {**action, "id": action_id}

    blocks = action_decision_blocks(
        decision=decision_label,
        action=action,
        decided_by_slack_id=user_id,
    )
    fallback = f"Action {action_id} {decision_label} by <@{user_id}>"
    return _replace_card(blocks, fallback=fallback)
