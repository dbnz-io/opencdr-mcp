from unittest.mock import Mock

import pytest

from opencdr_mcp import server

OWNER = "aws:111111111111:AROAABCDEFGHIJKLMNOP"
CHECKPOINT = {"cursor": "old-cursor", "sequence": 8, "receipt_id": None, "principal": OWNER}


@pytest.fixture
def transport(monkeypatch):
    send = Mock(return_value=(200, {"state": "applied"}))
    monkeypatch.setattr(server, "_resolve_api", lambda *args: ("url", "target"))
    monkeypatch.setattr(server.opencdr, "_request", send)
    monkeypatch.setattr(
        server.opencdr,
        "_load_config",
        lambda: {"auth_mode": "iam", "access": "delivery", "mode": "core"},
    )
    return send


def test_storage_plan_and_apply_preserve_separate_review_digests(transport):
    server.opencdr_detection_recovery_status(agent_id="member")
    assert transport.call_args.args[:2] == ("GET", "/detections/storage")
    server.opencdr_detection_recovery_update(
        "restore", "plan", "a" * 64, "reviewed", True, "member"
    )
    assert transport.call_args.kwargs["json"] == {
        "storage_digest": "a" * 64,
        "reason": "reviewed",
        "accept_unrecoverable": True,
    }
    server.opencdr_detection_recovery_status("restore", "member")
    assert transport.call_args.args[:2] == ("GET", "/detections/recoveries/restore")
    server.opencdr_detection_recovery_update("restore", "apply", "b" * 64, agent_id="member")
    assert transport.call_args.args[:2] == ("POST", "/detections/recoveries/restore/apply")
    assert transport.call_args.kwargs["json"] == {"plan_digest": "b" * 64}


def test_consumer_recovery_uses_fresh_namespace_and_rejects_fleet_identity(transport, monkeypatch):
    args = ("history", "b" * 64, "c" * 32, OWNER, CHECKPOINT, "reviewed", "d" * 32, True)
    server.opencdr_detection_consumer_recover(*args)
    assert transport.call_args.args[:2] == (
        "POST",
        "/detections/consumers/recovery-" + "d" * 32 + "/recover",
    )
    assert transport.call_args.kwargs["json"]["previous_checkpoint"] == CHECKPOINT
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {"mode": "fleet"})
    transport.reset_mock()
    with pytest.raises(ValueError):
        server.opencdr_detection_consumer_recover(*args)
    transport.assert_not_called()


@pytest.mark.parametrize(
    "action,digest,accept",
    [("plan", "a" * 64, False), ("unknown", "a" * 64, True), ("apply", "bad", True)],
)
def test_invalid_recovery_never_mutates(transport, action, digest, accept):
    with pytest.raises(ValueError):
        server.opencdr_detection_recovery_update("restore", action, digest, "reviewed", accept)
    transport.assert_not_called()


def test_fleet_recovery_requires_admin_and_preserves_guards(monkeypatch):
    send = Mock(return_value={"state": "accepted"})
    monkeypatch.setattr(server, "_fleet_call", send)
    server.opencdr_fleet_detection_recovery_context("member")
    assert send.call_args.args[:2] == ("GET", "/v1/agents/member/detections/recover")
    server.opencdr_fleet_detection_recover(
        "member", 8, 2, "history", "a" * 64, "b" * 32, OWNER, "reviewed", "c" * 32, True
    )
    assert send.call_args.args[:2] == ("POST", "/v1/agents/member/detections/recover")
    assert send.call_args.args[2]["target_owner"] == OWNER
    assert send.call_args.args[2]["expected_generation"] == 8
    for profile in ("observer", "operator", "responder"):
        assert "opencdr_fleet_detection_recover" not in server.allowed_tools(profile, "fleet")
        assert "opencdr_detection_recovery_update" not in server.allowed_tools(profile)
        assert "opencdr_detection_consumer_recover" not in server.allowed_tools(profile)
