"""Request-scoped IAM/SigV4 routing for the optional Fleet Manager connection."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

import boto3
import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import BotoCoreError


class FleetError(RuntimeError):
    """Fleet routing/configuration failed; never fall back to direct Core."""


def agent_identifier(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", value):
        raise FleetError("agent_id must be 1–63 lowercase letters, digits or hyphens")
    return value


def relative_path(path: str, prefix: str = "/v1/") -> str:
    parsed = urlsplit(path)
    decoded = unquote(unquote(parsed.path))
    if (
        not path.startswith(prefix)
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or "\\" in decoded
        or any(part in {".", ".."} for part in decoded.split("/"))
        or any(ord(char) < 32 for char in path)
    ):
        raise FleetError(f"Use a relative {prefix} path without traversal or a fragment")
    return path


@dataclass(frozen=True)
class FleetConnection:
    url: str
    aws_profile: str
    security_account_id: str
    region: str
    stage: str

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        values = config.get("fleet", {})
        if not isinstance(values, dict):
            raise FleetError("fleet must be a JSON object")
        name = os.getenv("OPENCDR_FLEET_NAME") or values.get("name")
        if name:
            path = Path(
                os.getenv("OPENCDR_DEPLOY_REGISTRY")
                or values.get("registry")
                or "~/.config/opencdr/deployments.json"
            ).expanduser()
            try:
                stored = json.loads(path.read_text())
                entry = stored["fleet_managers"][name]
                if stored.get("version") != 1 or not isinstance(entry, dict):
                    raise ValueError("Unsupported fleet registry")
            except (OSError, ValueError, KeyError, TypeError) as error:
                raise FleetError(
                    "Cannot read the named fleet connection; run opencdr-deploy fleet connect"
                ) from error
            values = {**entry, **values}

        def value(env, *fields):
            return os.getenv(env) or next((values[key] for key in fields if values.get(key)), "")

        connection = cls(
            url=value("OPENCDR_FLEET_URL", "url", "api_url"),
            aws_profile=value("OPENCDR_FLEET_AWS_PROFILE", "aws_profile"),
            security_account_id=value("OPENCDR_FLEET_ACCOUNT_ID", "security_account_id"),
            region=value("OPENCDR_FLEET_REGION", "region"),
            stage=value("OPENCDR_FLEET_STAGE", "stage"),
        )
        connection.validate()
        return connection

    def validate(self):
        if not all(isinstance(value, str) for value in vars(self).values()):
            raise FleetError("Fleet URL, profile, account, region and stage must be strings")
        if not re.fullmatch(r"\d{12}", self.security_account_id):
            raise FleetError("Set the expected fleet security_account_id (12 digits)")
        if not self.aws_profile or not isinstance(self.aws_profile, str):
            raise FleetError("Set a named fleet aws_profile; no AWS keys are stored by MCP")
        if not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", self.region):
            raise FleetError("Set the fleet AWS region")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", self.stage):
            raise FleetError("Set the fleet stage")
        try:
            url = urlsplit(self.url)
            valid = (
                url.scheme == "https"
                and not url.username
                and not url.password
                and not url.port
                and not url.query
                and not url.fragment
                and url.path.rstrip("/") == f"/{self.stage}"
                and re.fullmatch(
                    rf"[a-z0-9]+\.execute-api\.{re.escape(self.region)}\.amazonaws\.com",
                    url.hostname or "",
                )
            )
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise FleetError("Use the regional HTTPS FleetManagerApiUrl, including its stage")


class FleetClient:
    def __init__(self, connection: FleetConnection):
        connection.validate()
        self.connection = connection
        self._session = None
        self._verified = False

    def request(self, method: str, path: str, *, json_body=None, params=None):
        relative_path(path)
        if method not in {"GET", "POST", "PUT", "DELETE"}:
            raise FleetError("Unsupported fleet HTTP method")
        if method == "GET" and json_body is not None:
            raise FleetError("GET requests cannot contain a body")
        payload = (
            json.dumps(json_body, separators=(",", ":")).encode() if json_body is not None else None
        )
        if payload is not None and len(payload) > 2_000_000:
            raise FleetError("Fleet request exceeds 2 MB")
        try:
            if self._session is None:
                self._session = boto3.Session(
                    profile_name=self.connection.aws_profile, region_name=self.connection.region
                )
            credentials = self._session.get_credentials()
            if credentials is None:
                raise FleetError("AWS credentials unavailable; sign in to the saved AWS profile")
            prepared = requests.Request(
                method, self.connection.url.rstrip("/") + path, params=params
            ).prepare()
            signed = AWSRequest(
                method=method,
                url=prepared.url,
                data=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
            )
            SigV4Auth(
                credentials.get_frozen_credentials(), "execute-api", self.connection.region
            ).add_auth(signed)
            with requests.request(
                method,
                prepared.url,
                headers=dict(signed.headers),
                data=payload,
                timeout=(5, 30),
                allow_redirects=False,
                stream=True,
            ) as response:
                content, size = [], 0
                for chunk in response.iter_content(64 * 1024):
                    size += len(chunk)
                    if size > 2_000_000:
                        raise FleetError("Fleet response exceeds 2 MB; use narrower pagination")
                    content.append(chunk)
                raw = b"".join(content)
                try:
                    body = json.loads(raw) if raw else None
                except (ValueError, UnicodeError) as error:
                    raise FleetError("Fleet Manager returned invalid JSON") from error
                return response.status_code, body
        except BotoCoreError as error:
            raise FleetError(
                "AWS authentication failed; check the fleet AWS profile and SSO login"
            ) from error
        except requests.RequestException as error:
            message = "Fleet Manager is unavailable"
            if method != "GET":
                message += "; write outcome is unknown. Inspect agent state before retrying"
            raise FleetError(message) from error

    def verify(self):
        status, body = self.request("GET", "/v1/status")
        identity = body.get("deployment") if isinstance(body, dict) else None
        if (
            status != 200
            or not isinstance(identity, dict)
            or body.get("product") != "OpenCDR Fleet Manager"
            or not re.fullmatch(r"1\.\d+\.\d+", str(body.get("fleet_contract_version", "")))
            or identity.get("account_id") != self.connection.security_account_id
            or identity.get("home_region") != self.connection.region
            or identity.get("stage") != self.connection.stage
        ):
            raise FleetError(
                "Fleet identity, contract or access does not match the configured connection"
            )
        self._verified = True
        return body

    def verified_request(self, method: str, path: str, *, json_body=None, params=None):
        if not self._verified:
            self.verify()
        return self.request(method, path, json_body=json_body, params=params)


class FleetTarget:
    """A single tool call's route. Never stored as a global selected agent."""

    def __init__(self, connection: FleetConnection, agent_id: str):
        self.agent_id = agent_identifier(agent_id)
        self.client = FleetClient(connection)

    def request(self, method: str, path: str, **kwargs):
        relative_path(path, "/")
        if set(kwargs) - {"json", "params"}:
            raise FleetError("Unsupported fleet request options")
        status, result = self.client.verified_request(
            method,
            f"/v1/agents/{self.agent_id}/api{path}",
            json_body=kwargs.get("json"),
            params=kwargs.get("params"),
        )
        if (
            not isinstance(result, dict)
            or result.get("agent_id") != self.agent_id
            or result.get("status_code") != status
            or not isinstance(result.get("attempted"), bool)
        ):
            raise FleetError("Fleet Manager returned an invalid agent response")
        if not result["attempted"] or result.get("outcome") or result.get("error_code"):
            raise FleetError("Fleet forwarding failed: " + json.dumps(result, default=str))
        return status, result.get("body")
