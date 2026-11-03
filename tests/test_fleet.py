from __future__ import annotations

import inspect
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import Mock

import pytest
import requests
from botocore.credentials import Credentials

from opencdr_mcp import client, fleet, server

CONFIG = {
    "mode": "fleet",
    "fleet": {
        "url": "https://abcdefghij.execute-api.us-east-1.amazonaws.com/prod",
        "aws_profile": "fleet-reader",
        "security_account_id": "111111111111",
        "region": "us-east-1",
        "stage": "prod",
    },
}
STATUS = {
    "product": "OpenCDR Fleet Manager",
    "fleet_contract_version": "1.0.0",
    "version": "0.1.1",
    "deployment": {"account_id": "111111111111", "home_region": "us-east-1", "stage": "prod"},
}
AGENT = {
    "agent_id": "member-prod",
    "name": "Member",
    "account_id": "222222222222",
    "region": "us-east-1",
    "stage": "prod",
    "api_url": "https://core.example/prod",
    "enabled": True,
    "allow_writes": False,
    "settings_ids": ["global"],
    "integration_ids": [],
}


@pytest.fixture
def fleet_config(tmp_path, monkeypatch):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(CONFIG))
    monkeypatch.setenv("OPENCDR_CONFIG_FILE", str(path))
    monkeypatch.setenv("OPENCDR_CONNECTION_MODE", "fleet")
    monkeypatch.setenv("OPENCDR_API_URL", "https://must-not-use-core.example")
    monkeypatch.setenv("OPENCDR_API_KEY", "must-not-send-core-key")
    for key in (
        "OPENCDR_FLEET_NAME",
        "OPENCDR_FLEET_URL",
        "OPENCDR_FLEET_AWS_PROFILE",
        "OPENCDR_FLEET_ACCOUNT_ID",
        "OPENCDR_FLEET_REGION",
        "OPENCDR_FLEET_STAGE",
    ):
        monkeypatch.delenv(key, raising=False)
    return path


@pytest.fixture
def connection():
    return fleet.FleetConnection.from_config(CONFIG)


def envelope(agent, body, status=200, **fields):
    return status, {
        "agent_id": agent,
        "status_code": status,
        "attempted": True,
        "body": body,
        **fields,
    }


def test_every_existing_core_tool_has_an_explicit_agent_selector():
    assert len(server._TOOL_CAPS) == 35
    for name in server._TOOL_CAPS:
        function = getattr(server, name)
        assert "agent_id" in inspect.signature(function).parameters, name
        assert "fleet mode" in function.__doc__.lower()


def test_fleet_requires_an_agent_and_never_falls_back_to_core(fleet_config, monkeypatch):
    send = Mock(side_effect=AssertionError("Unexpected network request"))
    monkeypatch.setattr(requests, "request", send)
    with pytest.raises(server.OpenCDRConfigError, match="requires agent_id"):
        server.opencdr_rules_list()
    send.assert_not_called()


def test_incomplete_fleet_config_does_not_use_ambient_core_secrets(fleet_config, monkeypatch):
    fleet_config.write_text(json.dumps({"mode": "fleet"}))
    monkeypatch.setattr(requests, "request", Mock(side_effect=AssertionError("network")))
    with pytest.raises(fleet.FleetError, match="security_account_id"):
        server.opencdr_status(agent_id="member-prod")


def test_saved_deploy_cli_fleet_is_consumed_without_cli_or_core_credentials(
    fleet_config,
    tmp_path,
    monkeypatch,
):
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps(
            {
                "version": 1,
                "deployments": {"legacy": {"key": "ignored"}},
                "fleet_managers": {
                    "security-prod": {
                        "api_url": CONFIG["fleet"]["url"],
                        **{k: v for k, v in CONFIG["fleet"].items() if k != "url"},
                    }
                },
            }
        )
    )
    fleet_config.write_text(json.dumps({"mode": "fleet", "fleet": {"name": "security-prod"}}))
    monkeypatch.setenv("OPENCDR_DEPLOY_REGISTRY", str(registry))
    connection = fleet.FleetConnection.from_config(client._load_config())
    assert connection.url == CONFIG["fleet"]["url"]
    assert connection.aws_profile == "fleet-reader"
    assert "ignored" not in repr(connection)
    monkeypatch.setenv("OPENCDR_FLEET_AWS_PROFILE", "more-restricted-reader")
    assert (
        fleet.FleetConnection.from_config(client._load_config()).aws_profile
        == "more-restricted-reader"
    )


def test_unknown_named_fleet_does_not_use_inline_or_core_fallback(
    fleet_config, tmp_path, monkeypatch
):
    monkeypatch.setenv("OPENCDR_DEPLOY_REGISTRY", str(tmp_path / "missing.json"))
    monkeypatch.setenv("OPENCDR_FLEET_NAME", "not-configured")
    with pytest.raises(fleet.FleetError, match="named fleet connection"):
        server.opencdr_status(agent_id="member-prod")


def test_existing_core_methods_forward_parameters_body_and_revision(fleet_config, monkeypatch):
    calls = []

    def send(self, method, path, **kwargs):
        calls.append((method, path, kwargs))
        if path == "/v1/status":
            return 200, STATUS
        return envelope("member-prod", {"rule_id": "r1", "rev": 5})

    monkeypatch.setattr(fleet.FleetClient, "request", send)
    server.opencdr_rules_upsert(
        "r1", "signal", {"enabled": False}, expected_rev=4, agent_id="member-prod"
    )
    assert calls[0][:2] == ("GET", "/v1/status")
    assert calls[-1][1] == "/v1/agents/member-prod/api/rules/r1?rule_kind=signal"
    assert calls[-1][2]["json_body"]["expected_rev"] == 4
    assert calls[-1][2]["json_body"]["enabled"] is False


def test_concurrent_tools_keep_routes_request_scoped(fleet_config, monkeypatch):
    barrier = Barrier(2)

    def send(self, method, path, **kwargs):
        if path == "/v1/status":
            return 200, STATUS
        barrier.wait(timeout=5)
        agent = path.split("/")[3]
        return envelope(agent, {"agent": agent, "status": "ok"})

    monkeypatch.setattr(fleet.FleetClient, "request", send)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda agent: server.opencdr_status(agent_id=agent), ["one", "two"])
        )
    assert results == [{"agent": "one", "status": "ok"}, {"agent": "two", "status": "ok"}]


@pytest.mark.parametrize(
    "operation,kwargs",
    [
        (server.opencdr_lists_add, {"list_id": "admins", "value": "bob"}),
        (server.opencdr_settings_set, {"notifications_enabled": False}),
    ],
)
def test_fleet_conflicts_are_not_silently_rebased(operation, kwargs, fleet_config, monkeypatch):
    writes = []

    def send(self, method, path, **values):
        if path == "/v1/status":
            return 200, STATUS
        if method == "GET":
            return envelope("member-prod", {"list_id": "admins", "values": ["alice"], "rev": 4})
        writes.append(values)
        return envelope("member-prod", {"message": "stale revision"}, 409)

    monkeypatch.setattr(fleet.FleetClient, "request", send)
    with pytest.raises(RuntimeError, match="stale revision"):
        operation(**kwargs, agent_id="member-prod")
    assert len(writes) == 1


def test_unknown_forwarded_write_is_not_retried(fleet_config, monkeypatch):
    send = Mock(side_effect=[(200, STATUS), envelope("member-prod", {}, 504, outcome="unknown")])
    monkeypatch.setattr(fleet.FleetClient, "request", send)
    with pytest.raises(fleet.FleetError, match="unknown"):
        server.opencdr_rules_delete("r1", "signal", agent_id="member-prod")
    assert send.call_count == 2


@pytest.mark.parametrize(
    "change",
    [
        {"agent_id": "another"},
        {"status_code": 403},
        {"attempted": False},
    ],
)
def test_invalid_or_unattempted_envelopes_fail_closed(connection, monkeypatch, change):
    result = envelope("member-prod", {})[1] | change
    monkeypatch.setattr(fleet.FleetClient, "verify", Mock())
    monkeypatch.setattr(fleet.FleetClient, "request", lambda *a, **k: (200, result))
    with pytest.raises(fleet.FleetError):
        fleet.FleetTarget(connection, "member-prod").request("GET", "/status")


class StreamResponse:
    def __init__(self, body, status=200):
        self.body = json.dumps(body).encode()
        self.status_code = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_content(self, _size):
        yield self.body


def test_fleet_http_uses_sigv4_session_token_and_never_core_keys(connection, monkeypatch):
    session = Mock()
    session.get_credentials.return_value = Credentials("AKIATEST", "secret", "session-token")
    factory = Mock(return_value=session)
    monkeypatch.setattr(fleet.boto3, "Session", factory)
    request = Mock(return_value=StreamResponse({"ok": True}))
    monkeypatch.setattr(requests, "request", request)
    fleet.FleetClient(connection).request(
        "PUT", "/v1/agents/member-prod/api/rules/r1?rule_kind=signal", json_body={"expected_rev": 4}
    )
    factory.assert_called_once_with(profile_name="fleet-reader", region_name="us-east-1")
    args, kwargs = request.call_args
    assert args == (
        "PUT",
        CONFIG["fleet"]["url"] + "/v1/agents/member-prod/api/rules/r1?rule_kind=signal",
    )
    headers = {key.lower(): value for key, value in kwargs["headers"].items()}
    assert "/us-east-1/execute-api/aws4_request" in headers["authorization"]
    assert headers["x-amz-security-token"] == "session-token"
    assert "x-api-key" not in headers
    assert kwargs["allow_redirects"] is False
    assert json.loads(kwargs["data"]) == {"expected_rev": 4}


def test_http_write_timeout_has_unknown_outcome_without_retry(connection, monkeypatch):
    session = Mock()
    session.get_credentials.return_value = Credentials("AKIATEST", "secret", "token")
    monkeypatch.setattr(fleet.boto3, "Session", lambda **kw: session)
    send = Mock(side_effect=requests.Timeout("timeout"))
    monkeypatch.setattr(requests, "request", send)
    with pytest.raises(fleet.FleetError, match="outcome is unknown"):
        fleet.FleetClient(connection).request("POST", "/v1/agents", json_body={})
    send.assert_called_once()


@pytest.mark.parametrize(
    "url",
    [
        "http://bad.example/prod",
        "https://bad.example/prod",
        CONFIG["fleet"]["url"] + "?key=bad",
        CONFIG["fleet"]["url"] + "/nested",
        "https://abcdefghij.execute-api.us-west-2.amazonaws.com/prod",
    ],
)
def test_manager_url_is_bound_to_region_and_stage(url):
    with pytest.raises(fleet.FleetError):
        fleet.FleetConnection.from_config({"fleet": {**CONFIG["fleet"], "url": url}})


@pytest.mark.parametrize(
    "path",
    [
        "https://evil/v1/agents",
        "//evil/v1/agents",
        "/v1/../agents",
        "/v1/%2e%2e/agents",
        "/v1/%252e%252e/agents",
        "/v1/agents#fragment",
    ],
)
def test_fleet_paths_cannot_escape_endpoint(path):
    with pytest.raises(fleet.FleetError):
        fleet.relative_path(path)


@pytest.mark.parametrize(
    "identity", [None, {"account_id": "wrong"}, STATUS["deployment"] | {"stage": "dev"}]
)
def test_reported_identity_is_verified_before_any_forward(connection, monkeypatch, identity):
    send = Mock(return_value=(200, {**STATUS, "deployment": identity}))
    monkeypatch.setattr(fleet.FleetClient, "request", send)
    with pytest.raises(fleet.FleetError, match="identity"):
        fleet.FleetTarget(connection, "member-prod").request("GET", "/status")
    send.assert_called_once_with("GET", "/v1/status")


def test_registry_changes_keep_revision_and_reject_secret_fields(fleet_config, monkeypatch):
    send = Mock(side_effect=[(200, STATUS), (200, {"agent": AGENT})])
    monkeypatch.setattr(fleet.FleetClient, "request", send)
    server.opencdr_fleet_agent_update("member-prod", AGENT, expected_rev=3)
    assert send.call_args.kwargs["json_body"] == {**AGENT, "expected_rev": 3}
    send.reset_mock()
    with pytest.raises(ValueError, match="without credentials"):
        server.opencdr_fleet_agent_register({**AGENT, "api_key": "do-not-send"})
    send.assert_not_called()


def test_disable_changes_only_enablement_with_a_revision_guard(fleet_config, monkeypatch):
    calls = []

    def send(self, method, path, **kwargs):
        calls.append((method, path, kwargs))
        if path == "/v1/status":
            return 200, STATUS
        return 200, {"agent": {**AGENT, "rev": 4, "created_at": "metadata"}}

    monkeypatch.setattr(fleet.FleetClient, "request", send)
    server.opencdr_fleet_agent_disable("member-prod", expected_rev=4)
    writes = [call for call in calls if call[0] == "PUT"]
    assert len(writes) == 1
    assert writes[0][2]["json_body"] == {**AGENT, "enabled": False, "expected_rev": 4}


def test_stale_registry_revision_is_not_retried(fleet_config, monkeypatch):
    send = Mock(side_effect=[(200, STATUS), (200, {"agent": {**AGENT, "rev": 5}})])
    monkeypatch.setattr(fleet.FleetClient, "request", send)
    with pytest.raises(fleet.FleetError, match="revision changed"):
        server.opencdr_fleet_agent_disable("member-prod", expected_rev=4)
    assert send.call_count == 2


def test_enablement_keeps_the_same_fleet_connection_through_read_and_write(monkeypatch):
    active = Mock()
    active.verified_request.side_effect = [
        (200, {"agent": {**AGENT, "rev": 4}}),
        (200, {"agent": {**AGENT, "rev": 5, "enabled": False}}),
    ]
    factory = Mock(
        side_effect=[active, AssertionError("Fleet configuration reloaded mid-operation")]
    )
    monkeypatch.setattr(server, "_fleet_client", factory)
    server.opencdr_fleet_agent_disable("member-prod", expected_rev=4)
    factory.assert_called_once()
    assert active.verified_request.call_count == 2


def test_bulk_partial_results_are_preserved_without_claiming_success(fleet_config, monkeypatch):
    result = {
        "atomic": False,
        "results": [
            {"agent_id": "one", "status_code": 200, "attempted": True, "body": {"rev": 4}},
            {"agent_id": "two", "status_code": 504, "attempted": True, "outcome": "unknown"},
        ],
    }
    send = Mock(side_effect=[(200, STATUS), (207, result)])
    monkeypatch.setattr(fleet.FleetClient, "request", send)
    body = server.opencdr_fleet_invoke(["one", "two"], "PUT", "/rules/r1", {"expected_rev": 3})
    assert body["results"] == result["results"]
    assert body["all_requests_accepted"] is False and body["partial_failure"] is True
    assert send.call_count == 2


def test_fleet_profiles_are_reductions_and_registry_access_is_explicit():
    observer = server.allowed_tools("observer", "fleet")
    operator = server.allowed_tools("operator", "fleet")
    responder = server.allowed_tools("responder", "fleet")
    administrator = server.allowed_tools("administrator", "fleet")
    assert "opencdr_fleet_agents_list" in observer
    assert (
        "opencdr_fleet_agent_refresh" not in observer and "opencdr_fleet_agent_refresh" in operator
    )
    for name in (
        "opencdr_fleet_agent_register",
        "opencdr_fleet_agent_update",
        "opencdr_fleet_invoke",
        "opencdr_fleet_request",
    ):
        assert name not in responder and name in administrator
        assert getattr(server, name)._mcp_annotations.destructiveHint is True
    assert not set(server._FLEET_TOOL_CAPS) & server.allowed_tools("administrator", "core")


@pytest.mark.parametrize("profile", ["observer", "administrator"])
def test_registered_mcp_tools_match_fleet_policy_and_expose_agent_selector(profile, tmp_path):
    env = {
        **os.environ,
        "OPENCDR_CONNECTION_MODE": "fleet",
        "OPENCDR_MCP_PROFILE": profile,
        "OPENCDR_CONFIG_FILE": str(tmp_path / "empty.json"),
    }
    script = """import asyncio,json
from opencdr_mcp import server
async def main():
    tools=await server.mcp.list_tools()
    schema=next(t.inputSchema for t in tools if t.name=="opencdr_status")
    print(json.dumps({"names":[tool.name for tool in tools], "status_schema":schema}))
asyncio.run(main())"""
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=env, check=True
    )
    body = json.loads(result.stdout)
    assert set(body["names"]) == server.allowed_tools(profile, "fleet")
    assert "agent_id" in body["status_schema"]["properties"]


def test_direct_mode_remains_available_and_rejects_fleet_selectors(fleet_config, monkeypatch):
    monkeypatch.setenv("OPENCDR_CONNECTION_MODE", "core")
    monkeypatch.setattr(fleet.boto3, "Session", Mock(side_effect=AssertionError("AWS called")))
    with pytest.raises(server.OpenCDRConfigError, match="requires fleet mode"):
        server.opencdr_status(agent_id="member-prod")
    with pytest.raises(server.OpenCDRConfigError, match="requires fleet connection"):
        server.opencdr_fleet_status()
