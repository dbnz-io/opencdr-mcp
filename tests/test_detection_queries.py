from unittest.mock import MagicMock

import pytest

from opencdr_mcp import server


def test_fleet_search_uses_central_index_and_preserves_partial_summary(monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "fleet")
    call = MagicMock(return_value={"total": 10, "complete": False, "coverage": {"stale": True}})
    monkeypatch.setattr(server, "_fleet_call", call)
    monkeypatch.setattr(
        server, "_resolve_api", MagicMock(side_effect=AssertionError("member proxy"))
    )
    result = server.opencdr_detections_query(agent_ids=["b", "a"], kind="correlation", summary=True)
    assert result["complete"] is False and result["coverage"]["stale"]
    call.assert_called_once_with(
        "GET", "/v1/detections/summary?limit=50&agent_ids=a%2Cb&kind=correlation"
    )


def test_direct_query_and_detail_use_only_core(monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "core")
    monkeypatch.setattr(server, "_resolve_api", lambda: ("url", "iam"))
    request = MagicMock(return_value=(200, {"items": []}))
    monkeypatch.setattr(server.opencdr, "_request", request)
    server.opencdr_detections_query(limit=1, next_token="opaque")
    request.assert_called_once_with("GET", "/detections?limit=1&next_token=opaque", "url", "iam")
    request.reset_mock()
    server.opencdr_detection_detail("event/with space")
    request.assert_called_once_with(
        "GET", "/detections/detail?detection_id=event%2Fwith+space", "url", "iam"
    )


@pytest.mark.parametrize(
    "options",
    [
        {"limit": True},
        {"limit": 101},
        {"agent_ids": []},
        {"agent_ids": ["a/../b"]},
        {"account_ids": ["123"]},
        {"next_token": "x" * 4097},
    ],
)
def test_invalid_index_request_is_rejected_before_transport(options, monkeypatch):
    request = MagicMock(side_effect=AssertionError("should not send"))
    monkeypatch.setattr(server, "_indexed_detection_read", request)
    with pytest.raises(ValueError):
        server.opencdr_detections_query(**options)
    request.assert_not_called()
