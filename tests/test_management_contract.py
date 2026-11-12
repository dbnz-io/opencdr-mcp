"""Core remains authoritative for validation, activation, conflicts and execution."""

from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest

from opencdr_mcp import client, server


@pytest.fixture(autouse=True)
def api_env(monkeypatch):
    monkeypatch.setenv("OPENCDR_API_URL", "https://core.example/stage")
    monkeypatch.setenv("OPENCDR_API_KEY", "scoped-test-key")


def test_candidate_validation_preserves_core_errors_without_writes():
    result = {"valid": False, "errors": [{"field": "responses.0.targets"}], "warnings": []}
    with patch.object(client, "_request", return_value=(200, result)) as request:
        assert server.opencdr_rules_validate({"rule_id": "candidate"}, []) == result
    request.assert_called_once_with(
        "POST",
        "/rules/validate",
        "https://core.example/stage",
        "scoped-test-key",
        json={"rule": {"rule_id": "candidate"}, "available_lists": []},
    )


def test_evaluation_preserves_typed_list_snapshots():
    lists = {"networks": {"matcher": "cidr", "value_type": "ip", "values": ["10.0.0.0/8"]}}
    with patch.object(client, "_request", return_value=(200, {"matched": False})) as request:
        server.opencdr_rules_evaluate({"rule_id": "candidate"}, [{"src_ip": "1.2.3.4"}], lists)
    assert request.call_args.args[:2] == ("POST", "/rules/evaluate")
    assert request.call_args.kwargs["json"]["lists"] == lists
    assert request.call_count == 1  # no rule save, response or notification request


@pytest.mark.parametrize(
    "operation,path",
    [
        (server.opencdr_rules_schema, "/rules/schema"),
        (server.opencdr_rules_runtime_status, "/rules/runtime-status"),
    ],
)
def test_agent_read_is_authoritative(operation, path):
    result = {"status": "propagating", "future_core_field": True}
    with patch.object(client, "_request", return_value=(200, result)) as request:
        assert operation() == result
    assert request.call_args.args[:2] == ("GET", path)


def test_metrics_preserves_partial_results_and_encodes_selectors():
    result = {"partial": True, "items": []}
    with patch.object(client, "_request", return_value=(200, result)) as request:
        assert server.opencdr_rules_metrics(rule_id="a/b?c", release_id="release+1") == result
    query = parse_qs(urlsplit(request.call_args.args[1]).query)
    assert query == {"rule_id": ["a/b?c"], "release_id": ["release+1"]}


def test_release_plan_does_not_implicitly_apply():
    manifest = {"release_id": "release-a", "rules": []}
    with patch.object(client, "_request", return_value=(200, {"operations": []})) as request:
        server.opencdr_rule_releases_plan(manifest)
    assert request.call_count == 1
    assert request.call_args.args[:2] == ("POST", "/rule-releases/plan")
    assert request.call_args.kwargs["json"] == manifest


def test_apply_does_not_claim_runtime_activation_or_retry_partial_conflict():
    partial = {"message": "conflict", "completed": [{"rule_id": "changed-first"}]}
    with patch.object(client, "_request", return_value=(409, partial)) as request:
        with pytest.raises(RuntimeError, match="changed-first"):
            server.opencdr_rule_releases_apply({"rules": []})
    assert request.call_count == 1
    with patch.object(client, "_request", return_value=(200, {"status": "propagating"})):
        assert server.opencdr_rule_releases_apply({})["status"] == "propagating"


def test_replay_keeps_acceptance_distinct_from_completion_and_encodes_ids():
    result = {"run_id": "new-run", "mode": "analysis", "object_id": "new-object"}
    with patch.object(client, "_request", return_value=(202, result)) as request:
        assert server.opencdr_integrations_replay("a/b", "job?1") == result
    assert request.call_args.args[:2] == (
        "POST",
        "/integrations/a%2Fb/jobs/job%3F1/replay",
    )
    assert request.call_count == 1


@pytest.mark.parametrize(
    "operation,kwargs",
    [
        (server.opencdr_lists_list, {}),
        (server.opencdr_integrations_get, {"integration_id": "runtime", "jobs": True}),
    ],
)
def test_pagination_cursors_survive_round_trip(operation, kwargs):
    token = "opaque+/= value"
    with patch.object(client, "_request", return_value=(200, {"items": []})) as request:
        operation(**kwargs, next_token=token)
    assert parse_qs(urlsplit(request.call_args.args[1]).query)["next_token"] == [token]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"jobs": True},
        {"job_id": "job"},
        {"integration_id": "source", "job_id": "job"},
        {"integration_id": "source", "next_token": "token"},
    ],
)
def test_invalid_job_queries_never_silently_read_another_resource(kwargs):
    with patch.object(client, "_request") as request:
        with pytest.raises(ValueError):
            server.opencdr_integrations_get(**kwargs)
    request.assert_not_called()


@pytest.mark.parametrize("read_result,expected_rev", [(200, 7), (404, 0)])
def test_ir_role_implicit_revision_is_guarded_once(read_result, expected_rev):
    with patch.object(
        client,
        "_request",
        side_effect=[
            (200, {"capabilities": {"ir_role_revision_guards": True}}),
            (read_result, {"rev": 7}),
            (409, {"message": "changed concurrently"}),
        ],
    ) as request:
        with pytest.raises(RuntimeError, match="changed concurrently"):
            server.opencdr_ir_roles_upsert("123456789012", "arn:aws:iam::123456789012:role/IR")
    assert request.call_args.kwargs["json"]["expected_rev"] == expected_rev
    assert request.call_count == 3  # capability check, read, write; no conflict retry


def test_explicit_ir_role_revision_is_not_replaced_with_fresh_state():
    with patch.object(
        client,
        "_request",
        side_effect=[
            (200, {"capabilities": {"ir_role_revision_guards": True}}),
            (409, {"message": "stale"}),
        ],
    ) as request:
        with pytest.raises(RuntimeError, match="stale"):
            server.opencdr_ir_roles_upsert(
                "123456789012", "arn:aws:iam::123456789012:role/IR", expected_rev=2
            )
    assert request.call_count == 2
    assert request.call_args.kwargs["json"]["expected_rev"] == 2


def test_ir_role_write_refuses_core_without_revision_capability():
    with patch.object(client, "_request", return_value=(200, {"capabilities": {}})) as request:
        with pytest.raises(RuntimeError, match="ir_role_revision_guards"):
            server.opencdr_ir_roles_upsert(
                "123456789012", "arn:aws:iam::123456789012:role/IR", expected_rev=2
            )
    assert request.call_count == 1
    assert request.call_args.args[0] == "GET"


@pytest.mark.parametrize("read_result", [(403, {}), (503, {}), (200, "invalid body")])
def test_settings_read_failure_never_becomes_an_empty_document_write(read_result):
    with patch.object(client, "_request", return_value=read_result) as request:
        with pytest.raises(RuntimeError, match="no settings write attempted"):
            server.opencdr_settings_set(notifications_enabled=False)
    assert request.call_count == 1
    assert request.call_args.args[0] == "GET"


def test_settings_partial_channel_update_preserves_secret_and_routes():
    existing = {
        "rev": 3,
        "channels": {"slack": {"enabled": True, "webhook_url": "stored"}},
        "routing": {"HIGH": ["slack"]},
    }
    with patch.object(client, "_request", side_effect=[(200, existing), (200, {})]) as request:
        server.opencdr_settings_set(channels={"slack": {"enabled": False}})
    payload = request.call_args.kwargs["json"]
    assert payload["channels"]["slack"] == {"enabled": False, "webhook_url": "stored"}
    assert payload["routing"] == existing["routing"]
    assert payload["expected_rev"] == 3


def test_routing_can_be_explicitly_cleared_without_touching_other_settings():
    with patch.object(
        client,
        "_request",
        side_effect=[
            (200, {"rev": 2, "routing": {"HIGH": ["slack"]}}),
            (200, {}),
        ],
    ) as request:
        server.opencdr_settings_set(routing={})
    assert request.call_args.kwargs["json"]["routing"] == {}


def test_http_transport_never_follows_redirects_with_agent_credentials():
    with patch.object(client.requests, "request") as request:
        request.return_value.status_code = 302
        request.return_value.json.return_value = {"message": "redirect"}
        assert client._request("GET", "/status", "https://core.example", "key")[0] == 302
    assert request.call_args.kwargs["allow_redirects"] is False
    with pytest.raises(RuntimeError, match="302"):
        server._raise_on_error(302, {"message": "redirect"}, "status")
