import json
from unittest.mock import Mock

import pytest
import requests
from botocore.credentials import Credentials

from opencdr_mcp.fleet import FleetClient, FleetConnection, FleetError

IDENTITY = {"issuer": "opencdr-saas", "tenant": "org-a", "subject": "user-a"}
OWNER = {"account_id": "123456789012", "home_region": "us-east-1", "stage": "dev"}


def client():
    result = FleetClient(
        FleetConnection(
            "https://abc.execute-api.us-east-1.amazonaws.com/dev",
            "reader",
            "123456789012",
            "us-east-1",
            "dev",
            "triage",
            IDENTITY,
        )
    )
    result._session = Mock()
    result._session.get_credentials.return_value = Credentials("id", "secret", "session")
    return result


@pytest.mark.parametrize("prefix", ["/v1", ""])
def test_mcp_signs_human_scope_and_never_retries_or_downgrades(monkeypatch, prefix):
    api = client()
    api.path_prefix = prefix + "/"
    response = Mock(status_code=403)
    response.iter_content.return_value = [b'{"code":"identity_denied"}']
    manager = Mock()
    manager.__enter__ = Mock(return_value=response)
    manager.__exit__ = Mock(return_value=False)
    send = Mock(return_value=manager)
    monkeypatch.setattr(requests, "request", send)
    monkeypatch.setattr("opencdr_mcp.delegation.time.time", lambda: 1000)
    assert api.request("GET", prefix + "/detections", params={"agent_ids": "a,b"}) == (
        403,
        {"code": "identity_denied"},
    )
    args, kwargs = send.call_args
    assert args == ("POST", api.base_url + prefix + "/delegated")
    assert kwargs["headers"]["Authorization"].startswith("AWS4-HMAC-SHA256")
    assert "x-api-key" not in kwargs["headers"]
    assert json.loads(kwargs["data"]) == {
        "identity": {**IDENTITY, "audience": OWNER, "issued_at": 1000, "expires_at": 1060},
        "operation": {
            "method": "GET",
            "path": prefix + "/detections",
            "query": {"agent_ids": "a,b"},
            "body": {},
        },
    }
    send.assert_called_once()
    send.reset_mock(side_effect=True)
    send.side_effect = requests.Timeout("lost")
    with pytest.raises(FleetError, match="unknown"):
        api.request("POST", prefix + "/cases", json_body={"request_id": "a" * 32})
    send.assert_called_once()


def test_mcp_envelope_size_and_ambiguous_queries_fail_before_network(monkeypatch):
    send = Mock(side_effect=AssertionError("network"))
    monkeypatch.setattr(requests, "request", send)
    api = client()
    with pytest.raises(FleetError, match="2 MB"):
        api.request("POST", "/v1/cases", json_body={"data": "a" * 1_999_980})
    with pytest.raises(FleetError, match="Duplicate"):
        api.request("GET", "/v1/cases?status=open", params={"status": "closed"})
    send.assert_not_called()
