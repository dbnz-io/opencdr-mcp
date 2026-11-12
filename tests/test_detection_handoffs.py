from unittest.mock import Mock

import pytest

from opencdr_mcp import server

OLD = "aws:111111111111:AROAABCDEFGHIJKLMNOP"
NEW = "aws:111111111111:AROAQRSTUVWXYZABCDEF"


@pytest.fixture
def transport(monkeypatch):
    send = Mock(return_value=(200, {"state": "planned"}))
    monkeypatch.setattr(server, "_resolve_api", lambda *a: ("url", "target"))
    monkeypatch.setattr(server.opencdr, "_request", send)
    monkeypatch.setattr(
        server.opencdr,
        "_load_config",
        lambda: {"auth_mode": "iam", "access": "delivery", "mode": "core"},
    )
    return send


def test_handoff_tools_preserve_reviewed_identity_and_checkpoint(transport):
    server.opencdr_detection_handoff_plan(
        "replace", "fleet", OLD, NEW, "cursor", 5, "reviewed", "a" * 32, "member"
    )
    assert transport.call_args.args[:2] == ("POST", "/detections/handoffs/replace")
    assert transport.call_args.kwargs["json"]["checkpoint"] == {
        "cursor": "cursor",
        "sequence": 5,
        "receipt_id": "a" * 32,
    }
    server.opencdr_detection_handoff_accept("fleet", "replace", "b" * 64)
    assert transport.call_args.args[:2] == ("POST", "/detections/consumers/fleet/handoff")
    assert transport.call_args.kwargs["json"] == {"handoff_id": "replace", "plan_digest": "b" * 64}
    server.opencdr_detection_handoff_status("replace", "member")
    assert transport.call_args.args[:2] == ("GET", "/detections/handoffs/replace")


@pytest.mark.parametrize(
    "previous,target,sequence",
    [(OLD, OLD, 0), ("role-arn", NEW, 0), (OLD, NEW, True), (OLD, NEW, -1)],
)
def test_invalid_handoff_never_sends(transport, previous, target, sequence):
    with pytest.raises(ValueError):
        server.opencdr_detection_handoff_plan(
            "replace", "fleet", previous, target, "cursor", sequence, "reviewed"
        )
    transport.assert_not_called()


def test_fleet_handoff_is_administrator_only_and_uses_dedicated_worker_route(monkeypatch):
    send = Mock(return_value={"state": "accepted"})
    monkeypatch.setattr(server, "_fleet_call", send)
    server.opencdr_fleet_detection_handoff_context("member")
    assert send.call_args.args == ("GET", "/v1/agents/member/detections/handoff")
    server.opencdr_fleet_detection_handoff(
        "member", 8, 2, "replace", "b" * 64, NEW, "reviewed", "c" * 32
    )
    assert send.call_args.args[:2] == ("POST", "/v1/agents/member/detections/handoff")
    assert send.call_args.args[2]["expected_generation"] == 8
    for profile in ("observer", "operator", "responder"):
        assert "opencdr_fleet_detection_handoff" not in server.allowed_tools(profile, "fleet")
        assert "opencdr_detection_handoff_plan" not in server.allowed_tools(profile)
    assert "opencdr_fleet_detection_handoff" in server.allowed_tools("administrator", "fleet")
    assert "opencdr_detection_handoff_plan" in server.allowed_tools("administrator")


def test_fleet_cannot_accept_using_the_management_callers_identity(transport, monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {"mode": "fleet"})
    with pytest.raises(ValueError):
        server.opencdr_detection_handoff_accept("fleet", "replace", "b" * 64)
    transport.assert_not_called()
