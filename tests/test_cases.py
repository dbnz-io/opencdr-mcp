from unittest.mock import MagicMock

import pytest

from opencdr_mcp import server


def test_cases_use_central_fleet_authority_without_member_proxy(monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "fleet")
    call = MagicMock(return_value={"case": {"rev": 2}})
    monkeypatch.setattr(server, "_fleet_call", call)
    monkeypatch.setattr(
        server, "_resolve_api", MagicMock(side_effect=AssertionError("Core proxy forbidden"))
    )
    body = {
        "expected_rev": 1,
        "request_id": "a" * 32,
        "reason": "reviewed",
        "changes": {"status": "contained"},
    }
    server.opencdr_case_mutate("update", body, "b" * 32)
    call.assert_called_once_with("PUT", "/v1/cases/" + "b" * 32, body)
    call.reset_mock()
    server.opencdr_cases_list(["a", "b"], limit=10)
    call.assert_called_once_with("GET", "/v1/cases?agent_ids=a%2Cb&limit=10", None)


def test_cases_profiles_separate_read_write_and_grant_admin():
    assert {"opencdr_cases_list", "opencdr_case_read"} <= server.allowed_tools("observer")
    assert "opencdr_case_mutate" not in server.allowed_tools("observer")
    assert "opencdr_case_mutate" in server.allowed_tools("triage")
    assert server._FLEET_TOOL_CAPS["opencdr_fleet_case_access"] == server.CAP_FLEET_ADMIN


def test_core_requires_case_capability_and_does_not_retry_conflicts(monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {"auth_mode": "iam"})
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "core")
    monkeypatch.setattr(server, "_resolve_api", lambda: ("url", "iam"))
    send = MagicMock(side_effect=[(200, {"capabilities": {}})])
    monkeypatch.setattr(server.opencdr, "_request", send)
    with pytest.raises(RuntimeError, match="unavailable"):
        server.opencdr_case_read(case_id="b" * 32)
    assert send.call_count == 1
    send.reset_mock()
    send.side_effect = [
        (200, {"capabilities": {"operational_cases": "1.0.0"}}),
        (409, {"code": "case_revision_conflict"}),
    ]
    with pytest.raises(RuntimeError, match="409"):
        server.opencdr_case_mutate(
            "note",
            {"expected_rev": 1, "request_id": "a" * 32, "reason": "test", "text": "note"},
            "b" * 32,
        )
    assert send.call_count == 2


@pytest.mark.parametrize(
    "body", [{"actor": "forged"}, {"expected_rev": True}, {"request_id": "random"}, {"reason": ""}]
)
def test_case_mutation_rejects_spoofed_fields_before_transport(monkeypatch, body):
    call = MagicMock()
    monkeypatch.setattr(server, "_case_call", call)
    with pytest.raises(ValueError):
        server.opencdr_case_mutate(
            "note",
            {"expected_rev": 1, "request_id": "a" * 32, "reason": "test", "text": "note", **body},
            "b" * 32,
        )
    call.assert_not_called()


def test_case_evidence_and_history_are_explicit_bounded_reads(monkeypatch):
    call = MagicMock()
    monkeypatch.setattr(server, "_case_call", call)
    server.opencdr_case_read("evidence", "b" * 32, "a" * 64)
    call.assert_called_once_with(
        "GET", "/cases/" + "b" * 32 + "/evidence?attachment_id=" + "a" * 64
    )
    with pytest.raises(ValueError):
        server.opencdr_case_read("history", "b" * 32, limit=51)
    with pytest.raises(ValueError):
        server.opencdr_case_read("evidence", "b" * 32, "../secret")


def test_active_case_and_connector_binding_use_owner_and_correct_profile(monkeypatch):
    call = MagicMock()
    monkeypatch.setattr(server, "_case_call", call)
    server.opencdr_case_active("a", "same/id", ["b", "a"])
    call.assert_called_once_with(
        "GET", "/cases/active?agent_id=a&detection_id=same%2Fid&agent_ids=a%2Cb"
    )
    assert "opencdr_case_active" in server.allowed_tools("observer")
    assert "opencdr_case_integration" not in server.allowed_tools("responder")
    assert "opencdr_case_integration" in server.allowed_tools("administrator")
    with pytest.raises(ValueError):
        server.opencdr_case_active("x", "d", ["a"])


def test_response_outcomes_use_selected_fleet_route_and_bounded_pagination(monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "fleet")
    call = MagicMock()
    monkeypatch.setattr(server, "_fleet_call", call)
    server.opencdr_response_outcomes("d", "agent", attempt_id="b" * 32, after="2")
    call.assert_called_once_with(
        "GET",
        "/v1/agents/agent/detections/outcomes/history?detection_id=d&attempt_id="
        + "b" * 32
        + "&after=2&limit=20",
    )
    assert "opencdr_response_outcomes" in server.allowed_tools("observer")
    with pytest.raises(ValueError):
        server.opencdr_response_outcomes("d", "agent", limit=51)
    with pytest.raises(ValueError):
        server.opencdr_response_outcomes("d", "agent", after="../")


def test_routing_preview_uses_case_owner_once_and_never_mutates(monkeypatch):
    call = MagicMock(return_value={"preview": {"action": "manual", "side_effects": False}})
    monkeypatch.setattr(server, "_case_call", call)
    policy = {"mode": "manual"}
    assert (
        server.opencdr_case_routing_preview(policy, "a", "d/1")["preview"]["side_effects"] is False
    )
    call.assert_called_once_with(
        "POST", "/cases/routing/preview", {"policy": policy, "agent_id": "a", "detection_id": "d/1"}
    )
    assert "opencdr_case_routing_preview" in server.allowed_tools("triage")
    assert "opencdr_case_routing_preview" not in server.allowed_tools("observer")
    call.reset_mock()
    with pytest.raises(ValueError):
        server.opencdr_case_routing_preview(policy, "a", "d", "../outside")
    call.assert_not_called()


def test_extension_history_is_scoped_bounded_and_never_executes(monkeypatch):
    call = MagicMock(return_value={"execution_authorized": False})
    monkeypatch.setattr(server, "_case_call", call)
    server.opencdr_case_extensions("b" * 32, "provider-results", "opaque")
    call.assert_called_once_with("GET", "/cases/" + "b" * 32 + "/extensions/provider-results?after=opaque")
    assert "opencdr_case_extensions" in server.allowed_tools("observer")
    assert "opencdr_case_extension_save" not in server.allowed_tools("observer")
    assert "opencdr_case_extension_save" in server.allowed_tools("triage")
    with pytest.raises(ValueError):
        server.opencdr_case_extension_save("b" * 32, "execute", {})
    assert call.call_count == 1
