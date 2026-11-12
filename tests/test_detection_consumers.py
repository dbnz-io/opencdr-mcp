from unittest.mock import Mock

import pytest

from opencdr_mcp import server


@pytest.fixture
def delivery(monkeypatch):
    monkeypatch.setattr(
        server.opencdr,
        "_load_config",
        lambda: {"auth_mode": "iam", "access": "delivery", "mode": "core"},
    )
    monkeypatch.setattr(server, "_resolve_api", lambda: ("url", "target"))
    send = Mock(return_value=(200, {"rev": 2}))
    monkeypatch.setattr(server.opencdr, "_request", send)
    return send


def test_consumer_tools_preserve_revision_receipt_and_do_not_ack_on_status(delivery):
    assert server.opencdr_detection_consumer_status("test") == {"rev": 2}
    delivery.assert_called_once_with("GET", "/detections/consumers/test", "url", "target")
    delivery.reset_mock()
    server.opencdr_detection_consumer_update(
        "test", "read", expected_rev=3, receipt_id="a" * 32, limit=5
    )
    delivery.assert_called_once_with(
        "POST",
        "/detections/consumers/test/read",
        "url",
        "target",
        json={"expected_rev": 3, "receipt_id": "a" * 32, "limit": 5},
    )


@pytest.mark.parametrize(
    "args",
    [
        {"action": "reset"},
        {"action": "read", "expected_rev": True},
        {"action": "ack", "expected_rev": 1},
        {"action": "register", "initial_cursor": "cursor"},
        {"action": "read", "expected_rev": 1, "receipt_id": "bad"},
    ],
)
def test_invalid_consumer_commands_never_send(delivery, args):
    with pytest.raises(ValueError):
        server.opencdr_detection_consumer_update("test", **args)
    delivery.assert_not_called()


@pytest.mark.parametrize(
    "config",
    [
        {"mode": "fleet"},
        {"auth_mode": "iam", "access": "operator"},
        {"auth_mode": "legacy-api-key"},
    ],
)
def test_no_fleet_or_key_fallback_for_receipts(delivery, monkeypatch, config):
    monkeypatch.setattr(server.opencdr, "_load_config", lambda: config)
    with pytest.raises(ValueError):
        server.opencdr_detection_consumer_update("test", "register")
    delivery.assert_not_called()
