from unittest.mock import Mock

import pytest

from opencdr_mcp.core import CoreTarget
from opencdr_mcp.fleet import FleetError


def target(monkeypatch, report):
    transport = Mock()
    transport.request.side_effect = [(200, report), (409, {"completed": ["first"]})]
    monkeypatch.setattr("opencdr_mcp.core.FleetClient", Mock(return_value=transport))
    client = CoreTarget(
        {
            "url": "https://example.execute-api.us-east-1.amazonaws.com/dev",
            "deployment": {
                "account_id": "123456789012",
                "home_region": "us-east-1",
                "stage": "dev",
            },
            "access": "operator",
        }
    )
    return client, transport


def report():
    return {
        "product": "OpenCDR Core",
        "deployment": {"account_id": "123456789012", "home_region": "us-east-1", "stage": "dev"},
        "management_contract_version": "2.0.0",
        "capabilities": {"iam_management": True},
    }


def test_core_iam_checks_identity_then_preserves_partial_conflict(monkeypatch):
    client, transport = target(monkeypatch, report())
    result = client.request("POST", "/rule-releases/apply", json={"expected_plan_digest": "review"})
    assert result == (409, {"completed": ["first"]})
    assert transport.request.call_count == 2
    assert transport.request.call_args_list[0].args == ("GET", "/status")
    assert transport.base_url.endswith("/dev/management/operator")


@pytest.mark.parametrize(
    "override",
    [
        {"deployment": {"account_id": "999999999999"}},
        {"management_contract_version": "1.0.0"},
        {"capabilities": {}},
    ],
)
def test_core_iam_refuses_unknown_identity_or_contract_before_writing(monkeypatch, override):
    client, transport = target(monkeypatch, {**report(), **override})
    with pytest.raises(FleetError, match="identity or IAM contract"):
        client.request("PUT", "/rules/test", json={})
    transport.request.assert_called_once_with("GET", "/status")
