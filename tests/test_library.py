from unittest.mock import MagicMock

import pytest

from opencdr_mcp import server


def payload():
    return {
        "kind": "signal",
        "runtime_id": "r1",
        "title": "Draft",
        "description": "",
        "request_id": "a" * 32,
        "reason": "reviewed",
    }


def test_fleet_library_never_proxies_or_selects_a_member(monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {})
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "fleet")
    call = MagicMock(return_value={"ok": True})
    monkeypatch.setattr(server, "_fleet_call", call)
    monkeypatch.setattr(
        server, "_resolve_api", MagicMock(side_effect=AssertionError("No member transport"))
    )
    server.opencdr_library_write("create", payload())
    call.assert_called_once_with("POST", "/v1/library/items", payload())
    call.reset_mock()
    server.opencdr_library_read("artifact", content_id="b" * 32, version=2)
    call.assert_called_once_with(
        "GET", "/v1/library/items/" + "b" * 32 + "/versions/2/artifact", None
    )


def test_library_profiles_separate_observation_from_authoring():
    assert "opencdr_library_read" in server.allowed_tools("observer")
    assert "opencdr_library_write" not in server.allowed_tools("observer")
    assert "opencdr_library_write" not in server.allowed_tools("triage")
    assert "opencdr_library_write" in server.allowed_tools("operator")


def test_core_library_requires_iam_and_capability_and_never_retries(monkeypatch):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {"auth_mode": "iam"})
    monkeypatch.setattr(server.opencdr, "connection_mode", lambda _: "core")
    monkeypatch.setattr(server, "_resolve_api", lambda: ("url", "iam"))
    send = MagicMock(side_effect=[(200, {"capabilities": {}})])
    monkeypatch.setattr(server.opencdr, "_request", send)
    with pytest.raises(RuntimeError, match="unavailable"):
        server.opencdr_library_read()
    send.reset_mock()
    send.side_effect = [
        (200, {"capabilities": {"content_library": "1.0.0"}}),
        (409, {"code": "library_request_conflict"}),
    ]
    with pytest.raises(RuntimeError, match="409"):
        server.opencdr_library_write("create", payload())
    assert send.call_count == 2
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: {"auth_mode": "api_key"})
    with pytest.raises(server.OpenCDRConfigError, match="IAM"):
        server.opencdr_library_read()
    assert send.call_count == 2


@pytest.mark.parametrize(
    "fields",
    [{"actor": "forged"}, {"request_id": "bad"}, {"reason": ""}, {"reason": " " + "x" * 1000}],
)
def test_invalid_write_never_reaches_transport(monkeypatch, fields):
    send = MagicMock()
    monkeypatch.setattr(server, "_library_call", send)
    with pytest.raises(ValueError):
        server.opencdr_library_write("create", {**payload(), **fields})
    send.assert_not_called()


@pytest.mark.parametrize(
    "query",
    [
        {"view": "deploy"},
        {"view": "items", "content_id": "a" * 32},
        {"view": "item", "content_id": "../x"},
        {"view": "version", "content_id": "a" * 32, "version": True},
        {"view": "history", "content_id": "a" * 32, "after": "../x"},
        {"view": "manifest", "release_id": "b" * 32, "after": "a" * 32},
    ],
)
def test_invalid_selectors_never_reach_transport(monkeypatch, query):
    send = MagicMock()
    monkeypatch.setattr(server, "_library_call", send)
    with pytest.raises(ValueError):
        server.opencdr_library_read(**query)
    send.assert_not_called()


def test_quality_tools_keep_profile_and_owner_boundaries(monkeypatch):
    assert "opencdr_library_evidence" in server.allowed_tools("observer")
    assert "opencdr_library_quality" not in server.allowed_tools("observer")
    assert "opencdr_library_quality" not in server.allowed_tools("triage")
    assert "opencdr_library_quality" in server.allowed_tools("operator")
    call = MagicMock(return_value={"record": {}})
    monkeypatch.setattr(server, "_library_call", call)
    body = {"request_id": "b" * 32, "reason": "compile", "artifact_sha256": "f" * 64}
    server.opencdr_library_quality("compile", "a" * 32, body)
    call.assert_called_once_with("POST", "/library/releases/" + "a" * 32 + "/compilations", body)
    call.reset_mock()
    with pytest.raises(ValueError):
        server.opencdr_library_quality("compile", "a" * 32, {**body, "actor": "forged"})
    call.assert_not_called()
    server.opencdr_library_evidence("tests", "a" * 32, record_id="c" * 32)
    call.assert_called_once_with("GET", "/library/items/" + "a" * 32 + "/tests/" + "c" * 32)
