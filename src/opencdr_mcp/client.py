"""Small HTTP/configuration layer used by the OpenCDR MCP adapter."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import requests


def _config_file() -> Path:
    configured = os.getenv("OPENCDR_CONFIG_FILE")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".config" / "opencdr" / "mcp.json"


def _load_config() -> dict[str, Any]:
    path = _config_file()
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read OpenCDR configuration {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"OpenCDR configuration {path} must contain a JSON object")
    return value


def _request(method: str, path: str, url: str, key: str, **kwargs: Any) -> tuple[int, Any]:
    headers = {"x-api-key": key, "Content-Type": "application/json"}
    response = requests.request(method, f"{url}{path}", headers=headers, timeout=15, **kwargs)
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, response.text


def _merge_channels(existing: dict, new_channels: dict) -> dict:
    """Merge channel configuration without clobbering untouched channels."""
    merged = dict(existing)
    for channel, new_config in new_channels.items():
        if channel == "webhook" and "webhook" in existing:
            existing_targets = existing["webhook"].get("targets") or []
            new_targets = new_config.get("targets") or []
            new_names = {target.get("name") for target in new_targets}
            kept = [target for target in existing_targets if target.get("name") not in new_names]
            merged["webhook"] = {
                **existing["webhook"],
                **new_config,
                "targets": kept + new_targets,
            }
        else:
            merged[channel] = new_config
    return merged


def _merge_guardduty_notify(existing: dict, new: dict) -> dict:
    """Merge GuardDuty notification routing fields key by key."""
    merged = dict(existing)
    if "default" in new:
        merged["default"] = new["default"]
    for sub_key in ("by_severity", "by_service", "by_severity_and_service"):
        if sub_key in new:
            merged[sub_key] = {**(existing.get(sub_key) or {}), **new[sub_key]}
    return merged


def _fetch_existing_settings(url: str, key: str, setting_id: str) -> tuple[dict, dict]:
    """Return the current base settings payload and configured channels."""
    status, body = _request("GET", f"/settings/{setting_id}", url, key)
    if status == 404 or not isinstance(body, dict):
        return {"notifications_enabled": True}, {}
    existing_channels = body.get("channels") or {}
    base_payload = {name: value for name, value in body.items() if name != "channels"}
    base_payload.setdefault("notifications_enabled", True)
    return base_payload, existing_channels
