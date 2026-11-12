from unittest.mock import MagicMock

import pytest

from opencdr_mcp import server


def test_review_inbox_and_decisions_use_owner_once(monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "fleet")
    call = MagicMock(return_value={"items": [], "next_after": "next"})
    monkeypatch.setattr(server, "_fleet_call", call)
    monkeypatch.setattr(
        server, "_resolve_api", MagicMock(side_effect=AssertionError("No Core proxy"))
    )
    assert server.opencdr_reviews_read(limit=5)["next_after"] == "next"
    call.assert_called_once_with("GET", "/v1/reviews?limit=5", None)
    call.reset_mock()
    body = {
        "request_id": "a" * 32,
        "expected_rev": 1,
        "reason": "Exact review",
        "approve": True,
        "mode": "peer",
    }
    server.opencdr_review_decide("b" * 32, body)
    call.assert_called_once_with("POST", "/v1/reviews/" + "b" * 32 + "/decisions", body)
    assert "opencdr_reviews_read" in server.allowed_tools("observer")
    assert "opencdr_review_decide" not in server.allowed_tools("observer")
    assert "opencdr_review_decide" in server.allowed_tools("operator")


def test_core_legacy_denied_and_conflicts_not_retried(monkeypatch):
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "core")
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {})
    with pytest.raises(Exception, match="IAM"):
        server.opencdr_reviews_read()
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {"auth_mode": "iam"})
    monkeypatch.setattr(server, "_resolve_api", lambda: ("url", "iam"))
    call = MagicMock(return_value=(409, {"code": "approval_revision_conflict"}))
    monkeypatch.setattr(server.opencdr, "_request", call)
    with pytest.raises(RuntimeError, match="409"):
        server.opencdr_review_decide(
            "b" * 32,
            {"request_id": "a" * 32, "expected_rev": 1, "reason": "Withdraw"},
            withdraw=True,
        )
    assert call.call_count == 1


@pytest.mark.parametrize(
    "change", [{"actor": "forged"}, {"expected_rev": True}, {"mode": "auto"}, {"request_id": "../"}]
)
def test_forged_review_fields_rejected_before_transport(monkeypatch, change):
    call = MagicMock()
    monkeypatch.setattr(server, "_review_call", call)
    body = {
        "request_id": "a" * 32,
        "expected_rev": 1,
        "reason": "Reviewed",
        "approve": True,
        "mode": "peer",
        **change,
    }
    with pytest.raises(ValueError):
        server.opencdr_review_decide("b" * 32, body)
    call.assert_not_called()


def test_execution_is_core_only_and_uses_one_request(monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "fleet")
    call = MagicMock(return_value={"execution": {"state": "succeeded"}})
    monkeypatch.setattr(server, "_review_call", call)
    payload = {"expected_rev": 2, "request_id": "a" * 32, "reason": "Approved atomic package"}
    with pytest.raises(Exception, match="Fleet distribution"):
        server.opencdr_review_execute("b" * 32, payload)
    call.assert_not_called()
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "core")
    server.opencdr_review_execute("b" * 32, payload)
    call.assert_called_once_with("POST", "/reviews/" + "b" * 32 + "/execute", payload)
    assert "opencdr_review_execute" not in server.allowed_tools("observer")
    with pytest.raises(ValueError):
        server.opencdr_review_execute("b" * 32, {**payload, "actor": "forged"})
    assert call.call_count == 1


def test_distribution_uses_existing_job_and_separate_reconciliation(monkeypatch):
    call = MagicMock(return_value={"state": "unknown", "retry_allowed": False})
    monkeypatch.setattr(server, "_fleet_call", call)
    identity = "operator-" + "c" * 32
    targets = [{"agent_id": "a", "approval_id": "b" * 32, "expected_rev": 2}]
    server.opencdr_fleet_distribution_plan(targets, "a" * 32, "Frozen selection")
    call.assert_called_once_with(
        "POST",
        "/v1/rollouts/plan",
        {"targets": targets, "request_id": "a" * 32, "reason": "Frozen selection"},
    )
    call.reset_mock()
    result = server.opencdr_fleet_distribution_reconcile(identity, "a")
    assert not result["retry_allowed"]
    call.assert_called_once_with("POST", "/v1/rollouts/" + identity + "/reconcile/a", {})
    assert "opencdr_fleet_distribution_apply" not in server.allowed_tools("observer")


def test_owner_routing_and_fleet_groups_do_not_proxy_core(monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "fleet")
    call = MagicMock(return_value={"worker_connected": False})
    monkeypatch.setattr(server, "_fleet_call", call)
    monkeypatch.setattr(
        server, "_resolve_api", MagicMock(side_effect=AssertionError("No member proxy"))
    )
    body = {"expected_rev": 2, "request_id": "a" * 32, "reason": "Approved exact policy"}
    assert server.opencdr_routing_activate("b" * 32, body)["worker_connected"] is False
    call.assert_called_once_with("POST", "/v1/reviews/" + "b" * 32 + "/activate", body)
    call.reset_mock()
    server.opencdr_fleet_group_resolve("canary", 3)
    call.assert_called_once_with("POST", "/v1/groups/canary/resolve", {"expected_rev": 3})
    call.reset_mock()
    server.opencdr_fleet_review_execute("b" * 32, body)
    call.assert_called_once_with("POST", "/v1/reviews/" + "b" * 32 + "/execute", body)
    assert "opencdr_fleet_review_execute" not in server.allowed_tools("observer", mode="fleet")
    assert "opencdr_routing_activate" not in server.allowed_tools("observer", mode="fleet")
    assert "opencdr_fleet_group_resolve" in server.allowed_tools("observer", mode="fleet")


@pytest.mark.parametrize("group,revision", [("../core", 1), ("canary", True), ("canary", 0)])
def test_invalid_group_resolution_stops_before_transport(monkeypatch, group, revision):
    call = MagicMock()
    monkeypatch.setattr(server, "_fleet_call", call)
    with pytest.raises(ValueError):
        server.opencdr_fleet_group_resolve(group, revision)
    call.assert_not_called()


def test_uncertain_activation_is_one_request_with_no_retry(monkeypatch):
    call = MagicMock(side_effect=TimeoutError("unknown"))
    monkeypatch.setattr(server, "_review_call", call)
    with pytest.raises(TimeoutError):
        server.opencdr_routing_activate(
            "b" * 32, {"expected_rev": 2, "request_id": "a" * 32, "reason": "Exact"}
        )
    assert call.call_count == 1
