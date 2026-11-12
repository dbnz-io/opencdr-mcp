from unittest.mock import Mock

import pytest

from opencdr_mcp import server


@pytest.fixture
def api(monkeypatch):
    resolve = Mock(return_value=("url", "target"))
    send = Mock(return_value=(200, {"state": "planned", "rev": 1}))
    monkeypatch.setattr(server, "_resolve_api", resolve)
    monkeypatch.setattr(server.opencdr, "_request", send)
    monkeypatch.setattr(
        server.opencdr, "_load_config", lambda: {"auth_mode": "iam", "access": "delivery"}
    )
    return resolve, send


def test_backfill_tools_use_selected_member_and_exact_review_guard(api):
    resolve, send = api
    server.opencdr_detection_backfill_update("job", "plan", reason="repair", agent_id="member")
    resolve.assert_called_once_with("member")
    send.assert_called_once_with(
        "POST", "/detections/backfills/job", "url", "target", json={"reason": "repair"}
    )
    send.reset_mock()
    server.opencdr_detection_backfill_update(
        "job", "step", expected_rev=3, plan_digest="a" * 64, limit=7, agent_id="member"
    )
    send.assert_called_once_with(
        "POST",
        "/detections/backfills/job/step",
        "url",
        "target",
        json={"expected_rev": 3, "plan_digest": "a" * 64, "limit": 7},
    )
    send.reset_mock()
    server.opencdr_detection_backfill_status(
        "job", results=True, after="42", limit=5, agent_id="member"
    )
    send.assert_called_once_with(
        "GET", "/detections/backfills/job/results?after=42&limit=5", "url", "target"
    )


@pytest.mark.parametrize(
    "args",
    [
        {"action": "plan"},
        {"action": "step", "expected_rev": True, "plan_digest": "a" * 64},
        {"action": "step", "expected_rev": 1, "plan_digest": "wrong"},
        {"action": "step", "expected_rev": 1, "plan_digest": "a" * 64, "limit": 26},
    ],
)
def test_invalid_backfill_never_sends(api, args):
    with pytest.raises(ValueError):
        server.opencdr_detection_backfill_update("job", **args)
    api[1].assert_not_called()


def test_reconciliation_requires_explicit_acceptance_and_preserves_request_identity(api):
    body = dict(
        consumer_id="consumer",
        expected_rev=4,
        job_id="job",
        plan_digest="a" * 64,
        reason="reviewed findings",
        request_id="b" * 32,
    )
    with pytest.raises(ValueError):
        server.opencdr_detection_consumer_reconcile(**body)
    api[1].assert_not_called()
    server.opencdr_detection_consumer_reconcile(**body, accept_unrecoverable=True)
    payload = api[1].call_args.kwargs["json"]
    assert payload["expected_rev"] == 4 and payload["request_id"] == "b" * 32
    assert payload["backfill_job_id"] == "job" and payload["accept_unrecoverable"]
    api[1].reset_mock()
    server.opencdr_detection_consumer_status("consumer", audit=True, after="-2", limit=5)
    api[1].assert_called_once_with(
        "GET", "/detections/consumers/consumer/reconciliations?after=-2&limit=5", "url", "target"
    )


def test_fleet_reconciliation_uses_worker_route_and_administrator_profile(monkeypatch):
    send = Mock(return_value={"state": "accepted"})
    monkeypatch.setattr(server, "_fleet_call", send)
    server.opencdr_fleet_detection_reconcile(
        "member", 8, 2, "job", "a" * 64, "reviewed", "b" * 32, True
    )
    assert send.call_args.args[:2] == ("POST", "/v1/agents/member/detections/reconcile")
    assert send.call_args.args[2]["expected_generation"] == 8
    for profile in ("observer", "operator", "responder"):
        assert "opencdr_fleet_detection_reconcile" not in server.allowed_tools(profile, "fleet")
        assert "opencdr_detection_backfill_update" not in server.allowed_tools(profile)
    assert "opencdr_detection_backfill_update" in server.allowed_tools("administrator")
    assert "opencdr_fleet_detection_reconcile" in server.allowed_tools("administrator", "fleet")
