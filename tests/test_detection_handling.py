from unittest.mock import MagicMock

import pytest

from opencdr_mcp import server


def test_triage_profile_has_handling_but_no_configuration_response_or_maintenance():
    allowed = server.allowed_tools("triage")
    assert "opencdr_detection_handling" in allowed
    assert "opencdr_detection_handling_update" in allowed
    assert all(server._TOOL_CAPS[name] in {"read", "triage"} for name in allowed)
    assert "opencdr_detection_handling_update" not in server.allowed_tools("observer")


def test_fleet_handling_uses_dedicated_target_not_generic_proxy(monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "fleet")
    call = MagicMock(return_value={"projection_state": "pending", "handling": {"rev": 4}})
    monkeypatch.setattr(server, "_fleet_call", call)
    monkeypatch.setattr(
        server, "_resolve_api", MagicMock(side_effect=AssertionError("generic proxy"))
    )
    result = server.opencdr_detection_handling_update(
        "id/one", 3, "a" * 32, "reviewed", {"status": "resolved"}, "member"
    )
    assert result["projection_state"] == "pending"
    call.assert_called_once_with(
        "PUT",
        "/v1/agents/member/detections/handling?detection_id=id%2Fone",
        {
            "expected_rev": 3,
            "request_id": "a" * 32,
            "reason": "reviewed",
            "changes": {"status": "resolved"},
        },
    )
    with pytest.raises(ValueError):
        server.opencdr_detection_handling("id", history=True, after=-1)


def test_core_requires_iam_and_versioned_capability_and_preserves_conflict(monkeypatch):
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "core")
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {})
    call = MagicMock()
    monkeypatch.setattr(server.opencdr, "_request", call)
    with pytest.raises(server.OpenCDRConfigError):
        server.opencdr_detection_handling("id")
    call.assert_not_called()
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {"auth_mode": "iam"})
    monkeypatch.setattr(server, "_resolve_api", lambda _: ("url", "iam"))
    call.side_effect = [
        (200, {"capabilities": {"detection_handling": "1.0.0"}}),
        (409, {"code": "handling_revision_conflict"}),
    ]
    with pytest.raises(RuntimeError, match="409"):
        server.opencdr_detection_handling_update(
            "id", 0, "a" * 32, "reviewed", {"status": "acknowledged"}
        )
    assert call.call_count == 2


@pytest.mark.parametrize(
    "body",
    [
        {"expected_rev": True},
        {"request_id": "new"},
        {"reason": ""},
        {"changes": {"actor": "forged"}},
    ],
)
def test_bad_edits_are_rejected_before_transport(monkeypatch, body):
    call = MagicMock()
    monkeypatch.setattr(server, "_handling_call", call)
    with pytest.raises(ValueError):
        server.opencdr_detection_handling_update(
            **{
                "detection_id": "id",
                "expected_rev": 0,
                "request_id": "a" * 32,
                "reason": "reviewed",
                "changes": {"status": "open"},
                **body,
            }
        )
    call.assert_not_called()
