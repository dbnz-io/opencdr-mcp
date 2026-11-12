"""
OpenCDR MCP server -- an optional client for Core agent management:
rules, lists, signals, logs, settings, and IR-role assignments.

Run: opencdr-mcp  (stdio transport)
Register with Claude Code:
  claude mcp add opencdr -- opencdr-mcp

Configure direct Core access with OPENCDR_API_URL / OPENCDR_API_KEY, or set
OPENCDR_CONNECTION_MODE=fleet and OPENCDR_FLEET_NAME for an IAM-authenticated
Fleet Manager connection saved by opencdr-deploy. Fleet calls never fall back
to direct Core credentials. Every Core tool then requires an explicit agent_id.

Capability profiles (OPENCDR_MCP_PROFILE)
-----------------------------------------
This server exposes a reduced tool set depending on the profile it runs
under. The profile controls *which tools an MCP client can discover/call*:

  observer  (default) -- read-only: status, rules/lists read, signals &
                         logs search, integrations/settings read, IR roles &
                         actions read.
  operator            -- observer + rules/lists, integrations, and settings
                         writes.
  responder           -- operator + IR-role management and IR-action rollback.
  administrator       -- responder + fleet registry and broad forwarding tools.

IMPORTANT: the profile is a client-side capability *reduction*, not the
security boundary. Authorization is enforced by the OpenCDR API against the
scopes encoded in the API key (read / rules / settings / ir_roles /
ir_actions -- see src/handlers/api.py `_required_scope_for`). Run each
profile with an API key whose scopes match the profile, so the MCP tool set
and the backend enforcement agree. A responder profile pointed at a
read-only key will simply get 403s from the API; an observer profile pointed
at an all-scopes key still cannot mutate anything because the destructive
tools are never registered. Fleet mode additionally enforces AWS IAM at the
manager and registration/write-key permissions at Core. MCP profiles do not
grant AWS permissions. Observer remains the default.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from typing import Any, Literal
from urllib.parse import quote, urlencode

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from . import client as opencdr
from .fleet import (
    FleetClient,
    FleetConnection,
    FleetError,
    FleetTarget,
    agent_identifier,
    relative_path,
)

mcp = FastMCP("opencdr")


class OpenCDRConfigError(Exception):
    pass


# ---------------------------------------------------------------------------
# Typed domain values -- so an MCP client sees the valid inputs from the tool
# schema instead of a bare `str` (and an out-of-domain value is rejected
# before it ever reaches the API). Kept in sync with OpenCDR Core's allowed
# rule kinds and severities.
# ---------------------------------------------------------------------------

RuleKind = Literal["signal", "correlation"]
ListMatcher = Literal["exact", "cidr"]
ListValueType = Literal["string", "ip", "cidr", "iam_user", "arn", "aws_account_id", "resource_id"]
Order = Literal["asc", "desc"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL", "UNKNOWN"]
FleetConfigKind = Literal["rule", "list", "setting", "ir_role", "integration", "catalog"]

_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
# arn:aws:iam::<12-digit-account>:role/<path/name>
_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):role/.+$")

# Compare-and-set retries for the read-modify-write tools (lists add/remove,
# settings set). The API owns the concurrency guarantee via `expected_rev`;
# this is just a bounded client retry on a 409, NOT a lock.
_CAS_MAX_ATTEMPTS = 4


# ---------------------------------------------------------------------------
# Capability profiles.
#
# Each tool declares the capability it needs. A tool is only *registered*
# (and therefore only discoverable/callable) when the active profile grants
# that capability. `allowed_tools()` is a pure policy function so the mapping
# can be asserted in tests without re-importing the module per profile.
# ---------------------------------------------------------------------------

# Capability -> backend API-key scope it corresponds to (documentation/parity
# only; the backend, not this map, does the enforcing).
CAP_READ = "read"
CAP_RULES = "rules"
CAP_SETTINGS = "settings"
CAP_IR_ROLES = "ir_roles"
CAP_IR_ACTIONS_WRITE = "ir_actions"
CAP_FLEET_REFRESH = "fleet_refresh"
CAP_FLEET_ADMIN = "fleet_admin"
CAP_MAINTENANCE = "maintenance"
CAP_TRIAGE = "triage"

_OBSERVER_CAPS = frozenset({CAP_READ})
_OPERATOR_CAPS = _OBSERVER_CAPS | {CAP_TRIAGE, CAP_RULES, CAP_SETTINGS, CAP_FLEET_REFRESH}
_RESPONDER_CAPS = _OPERATOR_CAPS | {CAP_IR_ROLES, CAP_IR_ACTIONS_WRITE}

_PROFILE_CAPS: dict[str, frozenset[str]] = {
    "observer": _OBSERVER_CAPS,
    "triage": _OBSERVER_CAPS | {CAP_TRIAGE},
    "operator": _OPERATOR_CAPS,
    "responder": _RESPONDER_CAPS,
    "administrator": _RESPONDER_CAPS | {CAP_FLEET_ADMIN, CAP_MAINTENANCE},
}


def _resolve_profile() -> str:
    raw = (os.getenv("OPENCDR_MCP_PROFILE") or "observer").strip().lower()
    return raw if raw in _PROFILE_CAPS else "observer"


PROFILE = _resolve_profile()
_ACTIVE_CAPS = _PROFILE_CAPS[PROFILE]

# tool name -> required capability, populated by @_tool at import time.
_TOOL_CAPS: dict[str, str] = {}
_FLEET_TOOL_CAPS: dict[str, str] = {}
_CORE_ONLY_TOOLS: set[str] = set()


def allowed_tools(profile: str, mode: str = "core") -> set[str]:
    """Names of the tools a given profile may discover/call. Pure policy."""
    caps = _PROFILE_CAPS.get(profile, _OBSERVER_CAPS)
    catalog = {**_TOOL_CAPS, **(_FLEET_TOOL_CAPS if mode == "fleet" else {})}
    return {
        name
        for name, cap in catalog.items()
        if cap in caps and (mode != "fleet" or name not in _CORE_ONLY_TOOLS)
    }


def _tool(
    cap: str,
    *,
    annotations: ToolAnnotations,
    fleet_only: bool = False,
    central: bool = False,
    core_only: bool = False,
) -> Callable[[Callable], Callable]:
    """Register a FastMCP tool only if the active profile grants `cap`.

    The decorated function is always returned unchanged (so it stays
    importable/unit-testable regardless of profile); it is only *registered*
    with FastMCP -- i.e. exposed to MCP clients -- when the profile allows it.
    """

    def deco(fn: Callable) -> Callable:
        (_FLEET_TOOL_CAPS if fleet_only else _TOOL_CAPS)[fn.__name__] = cap
        if core_only:
            _CORE_ONLY_TOOLS.add(fn.__name__)
        if not fleet_only:
            fn.__doc__ = (fn.__doc__ or "") + (
                "\n\nStandalone Core only; Fleet uses reviewed distribution jobs."
                if core_only
                else "\n\nIn fleet mode this tool uses the Fleet authority directly; "
                "Core mode uses standalone Core."
                if central or core_only
                else "\n\nIn fleet mode, supply agent_id explicitly. "
                "Core mode leaves agent_id unset."
            )
        # Stash for introspection/testing so the classification can be
        # asserted regardless of which profile happens to be active.
        fn._mcp_capability = cap  # type: ignore[attr-defined]
        fn._mcp_annotations = annotations  # type: ignore[attr-defined]
        if (
            cap in _ACTIVE_CAPS
            and (not fleet_only or opencdr.connection_mode() == "fleet")
            and (not core_only or opencdr.connection_mode() != "fleet")
        ):
            mcp.tool(annotations=annotations)(fn)
        return fn

    return deco


# Annotation presets. Every tool talks to the external OpenCDR API, so
# openWorldHint is True everywhere.
_READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
# Idempotent, non-destructive write (PUT upsert / no-op-safe add/remove).
_MUTATING = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True
)
# Destructive or security-sensitive write.
_DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
)
# Rollback: security-sensitive AND not idempotent (409 if one is in flight).
_ROLLBACK = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
# Release application uses revisions; retrying is not an unconditional repeat.
_RELEASE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
# Each replay request enqueues a new analysis run.
_REPLAY = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)


# ---------------------------------------------------------------------------
# HTTP / config helpers
# ---------------------------------------------------------------------------


def _resolve_api(agent_id: str | None = None) -> tuple[str, str | FleetTarget]:
    """
    Environment variables take precedence over the optional config file.
    Raise instead of exiting: an MCP tool call should return a tool error,
    not kill the server process.
    """
    cfg = opencdr._load_config()
    if opencdr.connection_mode(cfg) == "fleet":
        if agent_id is None:
            raise OpenCDRConfigError(
                "Fleet mode requires agent_id for Core tools. "
                "Use opencdr_fleet_agents_list to select an agent."
            )
        connection = FleetConnection.from_config(cfg)
        return connection.url, FleetTarget(connection, agent_id)
    if agent_id is not None:
        raise OpenCDRConfigError(
            "agent_id requires fleet mode; this server is configured for direct Core access"
        )
    if cfg.get("auth_mode") == "iam":
        return cfg["url"], opencdr.CoreTarget(cfg)
    url = os.getenv("OPENCDR_API_URL") or cfg.get("url", "")
    key = os.getenv("OPENCDR_API_KEY") or cfg.get("key", "")
    missing = [
        name for name, value in (("OPENCDR_API_URL", url), ("OPENCDR_API_KEY", key)) if not value
    ]
    if missing:
        raise OpenCDRConfigError(
            f"Missing config: {', '.join(missing)}. Set OPENCDR_API_URL/OPENCDR_API_KEY "
            "or provide an OPENCDR_CONFIG_FILE JSON document."
        )
    url = opencdr.normalize_url(url)
    if "deployment" in cfg:
        opencdr.verify_identity(url, key, cfg["deployment"])
    return url, key


def _raise_on_error(status: int, body: Any, context: str) -> None:
    if status >= 300:
        msg = body.get("message", body) if isinstance(body, dict) else body
        raise RuntimeError(f"{context}: HTTP {status} — {msg}")


def _require_capability(url, key, capability):
    code, report = opencdr._request("GET", "/status", url, key)
    _raise_on_error(code, report, "Core capability check")
    if not isinstance(report, dict) or report.get("capabilities", {}).get(capability) is not True:
        raise RuntimeError(f"Core does not advertise {capability}; upgrade before this write")


def _qs(**params: Any) -> str:
    """URL-encoded query string from keyword params, dropping None values.

    Uses urllib so opaque values (base64 next_token cursors with `=`/`+`,
    principals/ARNs with `:` and `/`, etc.) are percent-encoded correctly
    instead of being spliced in raw.
    """
    clean = {k: v for k, v in params.items() if v is not None}
    return urlencode(clean)


def _seg(value: str, name: str) -> str:
    """Encode a single path segment, rejecting empty/whitespace ids.

    `safe=""` means a value containing `/`, `?`, `#` or whitespace cannot
    break out of its segment and forge a different path.
    """
    if value is None or str(value).strip() == "":
        raise ValueError(f"{name} is required")
    return quote(str(value), safe="")


def _require_account_id(aws_account_id: str) -> str:
    if not isinstance(aws_account_id, str) or not _ACCOUNT_ID_RE.match(aws_account_id):
        raise ValueError("aws_account_id must be a 12-digit AWS account ID")
    return aws_account_id


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_status(agent_id: str | None = None) -> dict:
    """Check OpenCDR API health. Read-only."""
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request("GET", "/status", url, key)
    _raise_on_error(status, body, "status")
    return body


# ---------------------------------------------------------------------------
# Rules (detection + correlation). Reusable lists have their own /lists
# resource and tool group below.
# ---------------------------------------------------------------------------


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_rules_list(
    kind: RuleKind | None = None,
    page_size: int = 50,
    next_token: str | None = None,
    agent_id: str | None = None,
) -> dict:
    """List detection/correlation rules. Read-only.

    kind: "signal" or "correlation" (omit for both; detection lists use
    opencdr_lists_list). Paginated: pass the returned next_token to continue.
    """
    url, key = _resolve_api(agent_id)
    query = _qs(page_size=page_size, rule_kind=kind, next_token=next_token)
    status, body = opencdr._request("GET", f"/rules?{query}", url, key)
    _raise_on_error(status, body, "rules list")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_rules_get(rule_id: str, kind: RuleKind, agent_id: str | None = None) -> dict:
    """Get a rule by id. Read-only. kind must be "signal" or "correlation"."""
    url, key = _resolve_api(agent_id)
    query = _qs(rule_kind=kind)
    status, body = opencdr._request("GET", f"/rules/{_seg(rule_id, 'rule_id')}?{query}", url, key)
    if status == 404:
        return {"found": False, "rule_id": rule_id}
    _raise_on_error(status, body, "rules get")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_rules_schema(agent_id: str | None = None) -> dict:
    """Read this agent's rule contract, operators, bounds and response target keys."""
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request("GET", "/rules/schema", url, key)
    _raise_on_error(status, body, "rules schema")
    return body


@_tool(CAP_RULES, annotations=_READ_ONLY)
def opencdr_rules_validate(
    rule: dict, available_lists: list[str] | None = None, agent_id: str | None = None
) -> dict:
    """Validate a candidate without saving it. Core requires the rules scope.

    Omit available_lists to use Core's validation behavior; supply an array to
    declare candidate list IDs explicitly. Inspect valid/errors before applying.
    """
    url, key = _resolve_api(agent_id)
    payload = {"rule": rule}
    if available_lists is not None:
        payload["available_lists"] = available_lists
    status, body = opencdr._request("POST", "/rules/validate", url, key, json=payload)
    _raise_on_error(status, body, "rules validate")
    return body


@_tool(CAP_RULES, annotations=_READ_ONLY)
def opencdr_rules_evaluate(
    rule: dict,
    events: list[dict],
    lists: dict[str, list[str] | dict] | None = None,
    agent_id: str | None = None,
) -> dict:
    """Evaluate a candidate against up to 500 supplied fixture events.

    No rule is saved, notification sent, or response executed. Lists map list IDs
    to values or complete list snapshots (including matcher/value_type). Core
    remains responsible for validation and evaluation; the rules scope is required.
    """
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request(
        "POST",
        "/rules/evaluate",
        url,
        key,
        json={"rule": rule, "events": events, "lists": lists if lists is not None else {}},
    )
    _raise_on_error(status, body, "rules evaluate")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_rules_runtime_status(agent_id: str | None = None) -> dict:
    """Read stored and evaluator-observed generations. Only verified means active.

    An accepted write can still be propagating; do not infer activation from a
    successful upsert or release application.
    """
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request("GET", "/rules/runtime-status", url, key)
    _raise_on_error(status, body, "rules runtime status")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_rules_metrics(
    rule_id: str | None = None,
    rule_version: str | None = None,
    release_id: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    agent_id: str | None = None,
) -> dict:
    """Read Core's rule/release aggregates. Preserve and inspect partial results."""
    url, key = _resolve_api(agent_id)
    query = _qs(
        rule_id=rule_id,
        rule_version=rule_version,
        release_id=release_id,
        date_from=date_from,
        date_to=date_to,
    )
    path = "/rules/metrics" + (f"?{query}" if query else "")
    status, body = opencdr._request("GET", path, url, key)
    _raise_on_error(status, body, "rules metrics")
    return body


@_tool(CAP_RULES, annotations=_READ_ONLY)
def opencdr_rule_releases_plan(manifest: dict, agent_id: str | None = None) -> dict:
    """Ask Core to plan a rule release without writes; requires rules scope.

    Review creates, updates, disables and deletes. Lists are managed separately.
    A plan is a preview, not an approval token or a lock on future agent state.
    """
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request("POST", "/rule-releases/plan", url, key, json=manifest)
    _raise_on_error(status, body, "rule release plan")
    return body


@_tool(CAP_RULES, annotations=_RELEASE)
def opencdr_rule_releases_apply(manifest: dict, agent_id: str | None = None) -> dict:
    """Apply a reviewed complete manifest. May disable/delete managed rules.

    Core validates the manifest and guards writes by revision. There is no
    cross-record transaction: inspect partial failure before retrying. Core
    rejects stale reviewed plans when manifest.expected_plan_digest is supplied.
    IAM mode requires that digest from opencdr_rule_releases_plan.
    Poll opencdr_rules_runtime_status after acceptance until verified.
    """
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request("POST", "/rule-releases/apply", url, key, json=manifest)
    if status >= 300:
        # A conflict can follow completed writes. Keep Core's per-rule outcome
        # visible in the MCP error rather than reducing it to only "message".
        raise RuntimeError(f"rule release apply: HTTP {status} — {json.dumps(body)}")
    return body


@_tool(CAP_RULES, annotations=_MUTATING)
def opencdr_rules_upsert(
    rule_id: str,
    kind: RuleKind,
    rule: dict,
    expected_rev: int | None = None,
    agent_id: str | None = None,
) -> dict:
    """Create or update a rule (PUT -- idempotent upsert, safe to call again).

    `rule` is the full rule body (conditions, severity, notify,
    response_module, etc.) -- see docs/detection-rules.md for the schema.

    The explicit rule_id/kind arguments are AUTHORITATIVE: any rule_id or
    rule_kind inside the `rule` object is overwritten with them before the
    request is sent, so a contradictory id/kind embedded in the body can
    never reach the API. kind must be "signal" or "correlation".

    Optional optimistic concurrency: pass `expected_rev` (the `rev` you read
    from opencdr_rules_get) to make the write conditional -- if the rule was
    changed since you read it, the API returns 409 rather than silently
    clobbering that change. Omit it for a plain upsert.
    """
    url, key = _resolve_api(agent_id)
    payload = {**rule, "rule_id": rule_id, "rule_kind": kind}
    if expected_rev is not None:
        payload["expected_rev"] = expected_rev
    query = _qs(rule_kind=kind)
    status, body = opencdr._request(
        "PUT", f"/rules/{_seg(rule_id, 'rule_id')}?{query}", url, key, json=payload
    )
    _raise_on_error(status, body, "rules upsert")
    return body


@_tool(CAP_RULES, annotations=_DESTRUCTIVE)
def opencdr_rules_delete(
    rule_id: str, kind: RuleKind, agent_id: str | None = None, expected_rev: int | None = None
) -> dict:
    """Delete a rule by id. DESTRUCTIVE and irreversible.

    kind must be "signal" or "correlation".
    """
    url, key = _resolve_api(agent_id)
    query = _qs(rule_kind=kind, expected_rev=expected_rev)
    status, body = opencdr._request(
        "DELETE", f"/rules/{_seg(rule_id, 'rule_id')}?{query}", url, key
    )
    if status == 404:
        return {"found": False, "rule_id": rule_id}
    _raise_on_error(status, body, "rules delete")
    return {"deleted": True, "rule_id": rule_id}


# ---------------------------------------------------------------------------
# Reusable, independently versioned lists referenced by rule conditions.
# ---------------------------------------------------------------------------


def _get_list_or_raise(url: str, key: str, list_id: str) -> dict:
    status, body = opencdr._request("GET", f"/lists/{_seg(list_id, 'list_id')}", url, key)
    if status == 404:
        raise RuntimeError(f"List not found: {list_id}")
    _raise_on_error(status, body, "lists get")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_lists_list(
    page_size: int = 100, next_token: str | None = None, agent_id: str | None = None
) -> dict:
    """Read one page of list metadata. Pass next_token to continue."""
    url, key = _resolve_api(agent_id)
    query = _qs(page_size=page_size, next_token=next_token)
    status, body = opencdr._request("GET", f"/lists?{query}", url, key)
    _raise_on_error(status, body, "lists list")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_lists_show(list_id: str, agent_id: str | None = None) -> dict:
    """Show a list's values. Read-only."""
    url, key = _resolve_api(agent_id)
    return _get_list_or_raise(url, key, list_id)


@_tool(CAP_RULES, annotations=_DESTRUCTIVE)
def opencdr_lists_replace(
    list_id: str,
    description: str = "",
    values: list[str] | None = None,
    matcher: ListMatcher = "exact",
    value_type: ListValueType = "string",
    agent_id: str | None = None,
) -> dict:
    """Create a list, or COMPLETELY REPLACE an existing one. DESTRUCTIVE.

    This is a whole-object PUT: `values` becomes the list's entire contents
    and any values not present in `values` are permanently dropped
    (`description` is likewise overwritten). To change membership
    incrementally without clobbering existing values, use opencdr_lists_add /
    opencdr_lists_remove instead. Creates the list if it does not exist.
    """
    url, key = _resolve_api(agent_id)
    payload: dict[str, Any] = {
        "list_id": list_id,
        "matcher": matcher,
        "value_type": value_type,
        "description": description,
        "values": values or [],
    }
    get_status, current = opencdr._request("GET", f"/lists/{_seg(list_id, 'list_id')}", url, key)
    if get_status == 200:
        payload["expected_rev"] = int(current.get("rev") or 0)
    elif get_status != 404:
        _raise_on_error(get_status, current, "lists replace read")
    status, body = opencdr._request(
        "PUT", f"/lists/{_seg(list_id, 'list_id')}", url, key, json=payload
    )
    _raise_on_error(status, body, "lists replace")
    return body


def _list_compare_and_set(
    list_id: str, value: str, *, add: bool, context: str, agent_id: str | None = None
) -> dict:
    """Read-modify-write a single list value under optimistic concurrency.

    Reads the list, applies the add/remove, and PUTs it back guarded by the
    `rev` it read (`expected_rev`). If a concurrent writer changed the list in
    between, the API returns 409 and we re-read and retry (bounded compare-and-
    set -- the API owns the guarantee; this is not a lock). No-ops (value
    already present / already absent) short-circuit without a write.
    """
    url, key = _resolve_api(agent_id)
    for _ in range(1 if isinstance(key, FleetTarget) else _CAS_MAX_ATTEMPTS):
        item = _get_list_or_raise(url, key, list_id)
        values = list(item.get("values") or [])
        present = value in values
        if add and present:
            return {"changed": False, "list_id": list_id, "values": values}
        if not add and not present:
            return {"changed": False, "list_id": list_id, "values": values}
        if add:
            values.append(value)
        else:
            values.remove(value)
            if not values:
                raise RuntimeError("A list must retain at least one value; delete it instead")
        item["values"] = values
        item["expected_rev"] = int(item.get("rev") or 0)
        status, body = opencdr._request(
            "PUT", f"/lists/{_seg(list_id, 'list_id')}", url, key, json=item
        )
        if status == 409 and isinstance(key, FleetTarget):
            _raise_on_error(
                status, body, "fleet revision conflict; inspect Core state before retrying"
            )
        if status == 409:
            continue  # concurrent write -- re-read the current rev and retry
        _raise_on_error(status, body, context)
        return body
    raise RuntimeError(
        f"{context}: list {list_id} is being modified concurrently -- retried "
        f"{_CAS_MAX_ATTEMPTS} times, give up and retry the operation"
    )


@_tool(CAP_RULES, annotations=_MUTATING)
def opencdr_lists_add(list_id: str, value: str, agent_id: str | None = None) -> dict:
    """Add a single value to an existing list (no-op if already present).

    Concurrency-safe: the write is guarded by the list's `rev` (optimistic
    concurrency, enforced by the API), so a simultaneous edit by another
    writer cannot be silently lost. The list must already exist.
    """
    return _list_compare_and_set(list_id, value, add=True, context="lists add", agent_id=agent_id)


@_tool(CAP_RULES, annotations=_MUTATING)
def opencdr_lists_remove(list_id: str, value: str, agent_id: str | None = None) -> dict:
    """Remove a single value from a list (no-op if not present).

    Concurrency-safe: the write is guarded by the list's `rev` (optimistic
    concurrency, enforced by the API).
    """
    return _list_compare_and_set(
        list_id, value, add=False, context="lists remove", agent_id=agent_id
    )


@_tool(CAP_RULES, annotations=_DESTRUCTIVE)
def opencdr_lists_delete(
    list_id: str, agent_id: str | None = None, expected_rev: int | None = None
) -> dict:
    """Delete a list entirely. DESTRUCTIVE and irreversible."""
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request(
        "DELETE",
        f"/lists/{_seg(list_id, 'list_id')}"
        + ("?" + _qs(expected_rev=expected_rev) if expected_rev is not None else ""),
        url,
        key,
    )
    if status == 404:
        return {"found": False, "list_id": list_id}
    _raise_on_error(status, body, "lists delete")
    return {"deleted": True, "list_id": list_id}


# ---------------------------------------------------------------------------
# Signals / logs (read-only investigation queries)
#
# NOTE ON FILTERS: the backend serves these from single-partition GSI
# queries, so exactly ONE indexed selector is supported per call
# (severity|event_id|category for signals; service|event_id|event_name for
# logs). It cannot AND-combine selectors, nor filter by source_ip / principal
# / resource / account_id / region -- those require new backend indexes. The
# richer multi-filter search described in the MCP hardening brief is a
# documented backend gap, deliberately NOT faked here by client-side scanning.
# date_from/date_to apply only to the day-bucketed selector (severity /
# service).
# ---------------------------------------------------------------------------


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_detections_feed(
    cursor: str | None = None,
    limit: int = 100,
    start: str = "earliest",
    agent_id: str | None = None,
) -> dict:
    """Read a bounded page of signals and correlated alerts in durable commit order.

    Requires an IAM Core connection advertising detection_feed 1.x. In Fleet
    mode select one agent_id; this forwards a read, not a fleet-wide central
    search. Reading does not acknowledge delivery. Retention gaps are returned
    as errors; never silently reset a cursor. start=latest deliberately skips
    retained records and cannot be combined with a cursor.
    """
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("limit must be an integer from 1 to 100")
    if start not in {"earliest", "latest"}:
        raise ValueError("start must be earliest or latest")
    if cursor is not None and (not isinstance(cursor, str) or not 1 <= len(cursor) <= 512):
        raise ValueError("cursor must be a nonempty feed cursor of at most 512 characters")
    if cursor and start != "earliest":
        raise ValueError("Specify either cursor or start=latest")
    url, key = _resolve_api(agent_id)
    query = _qs(cursor=cursor, limit=limit, start=start if not cursor else None)
    status, body = opencdr._request("GET", f"/detections/feed?{query}", url, key)
    _raise_on_error(status, body, "detections feed")
    return body


def _consumer_target(consumer_id, agent_id):
    if not isinstance(consumer_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", consumer_id):
        raise ValueError("Invalid consumer_id")
    config = opencdr._load_config()
    if opencdr.connection_mode(config) == "fleet" or agent_id is not None:
        raise ValueError("Fleet mode owns its worker receipts; use Fleet detection status")
    if config.get("auth_mode") != "iam" or config.get("access") != "delivery":
        raise ValueError("Consumer operations require a direct Core IAM delivery connection")
    return _resolve_api()


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_detection_consumer_status(
    consumer_id: str,
    agent_id: str | None = None,
    audit: bool = False,
    after: str | None = None,
    limit: int = 50,
) -> dict:
    """Read this IAM principal's consumer receipt and lag without acknowledging.

    Requires direct Core IAM delivery access. Fleet mode owns its worker receipts;
    inspect Fleet agent detection status instead. Names never select another owner.
    """
    url, key = _consumer_target(consumer_id, agent_id)
    if type(limit) is not int or not 1 <= limit <= 100 or (after is not None and not audit):
        raise ValueError("Audit pagination requires audit=true and limit 1–100")
    path = f"/detections/consumers/{consumer_id}"
    if audit:
        path += "/reconciliations?" + _qs(after=after, limit=limit)
    code, body = opencdr._request("GET", path, url, key)
    _raise_on_error(code, body, "detection consumer status")
    return body


@_tool(CAP_SETTINGS, annotations=_REPLAY)
def opencdr_detection_consumer_update(
    consumer_id: str,
    action: str,
    expected_rev: int | None = None,
    receipt_id: str | None = None,
    limit: int = 20,
    initial_cursor: str | None = None,
    checkpoint_sha256: str | None = None,
    agent_id: str | None = None,
) -> dict:
    """Register, read, or acknowledge this principal's durable delivery consumer.

    A read creates/replays an outstanding receipt; ACK only after durable storage.
    Read may acknowledge the previous receipt and offer the next page in one call.
    Registration optionally declares an existing durable checkpoint and its digest;
    it cannot reset an existing consumer. After uncertain outcomes inspect status.
    Requires direct Core IAM delivery access. Fleet mode manages its own receipts.
    """
    if action not in {"register", "read", "ack"}:
        raise ValueError("action must be register, read or ack")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("limit must be 1–100")
    body = {}
    if action == "register":
        if expected_rev is not None or receipt_id is not None:
            raise ValueError("Registration cannot acknowledge or reset a consumer")
        if (initial_cursor is None) != (checkpoint_sha256 is None):
            raise ValueError("Import requires initial_cursor and checkpoint_sha256")
        if initial_cursor is not None:
            if (
                not isinstance(initial_cursor, str)
                or not 1 <= len(initial_cursor) <= 512
                or not isinstance(checkpoint_sha256, str)
                or not re.fullmatch(r"[a-f0-9]{64}", checkpoint_sha256)
            ):
                raise ValueError("Invalid declared checkpoint")
            body = {"initial_cursor": initial_cursor, "checkpoint_sha256": checkpoint_sha256}
    else:
        if (
            type(expected_rev) is not int
            or expected_rev < 1
            or initial_cursor is not None
            or checkpoint_sha256 is not None
        ):
            raise ValueError("Read/ack requires a positive expected_rev and no initial checkpoint")
        body["expected_rev"] = expected_rev
        if receipt_id is not None:
            if not isinstance(receipt_id, str) or not re.fullmatch(r"[a-f0-9]{32}", receipt_id):
                raise ValueError("Invalid receipt_id")
            body["receipt_id"] = receipt_id
        if action == "ack" and receipt_id is None:
            raise ValueError("ACK requires the durably persisted page's receipt_id")
        if action == "read":
            body["limit"] = limit
    url, key = _consumer_target(consumer_id, agent_id)
    path = f"/detections/consumers/{consumer_id}" + ("" if action == "register" else "/" + action)
    code, result = opencdr._request("POST", path, url, key, json=body)
    _raise_on_error(code, result, "detection consumer " + action)
    return result


def _backfill_id(job_id):
    if not isinstance(job_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", job_id):
        raise ValueError("Invalid backfill job_id")
    return job_id


def _handoff_principal(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"aws(?:-us-gov|-cn)?:[0-9]{12}:(?:AROA|AIDA)[A-Z0-9]{12,64}", value
    ):
        raise ValueError("Use the immutable IAM principal identity, not a role ARN or session name")
    return value


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_detection_recovery_status(
    recovery_id: str | None = None, agent_id: str | None = None
) -> dict:
    """Inspect physical feed identity/digest, or a saved rotation plan/receipt."""
    path = (
        "/detections/storage"
        if recovery_id is None
        else "/detections/recoveries/" + _backfill_id(recovery_id)
    )
    url, key = _resolve_api(agent_id)
    code, result = opencdr._request("GET", path, url, key)
    _raise_on_error(code, result, "feed recovery status")
    return result


@_tool(CAP_MAINTENANCE, annotations=_DESTRUCTIVE)
def opencdr_detection_recovery_update(
    recovery_id: str,
    action: Literal["plan", "apply"],
    digest: str,
    reason: str | None = None,
    accept_unrecoverable: bool = False,
    agent_id: str | None = None,
) -> dict:
    """Administrator: plan or apply reviewed feed rotation, preserving stored rows.

    Plan uses the exact storage digest, reason and accepted uncertainty. Apply
    uses the separately reviewed plan digest. Pause old writers before upgrade
    and maintenance. This does not restore AWS resources or reconnect consumers.
    """
    _backfill_id(recovery_id)
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("Exact reviewed digest required")
    if action == "plan":
        if (
            not isinstance(reason, str)
            or not 1 <= len(reason) <= 512
            or accept_unrecoverable is not True
        ):
            raise ValueError(
                "Review reason and explicit acceptance of unavailable history required"
            )
        body = {"storage_digest": digest, "reason": reason, "accept_unrecoverable": True}
        suffix = ""
    elif action == "apply":
        body, suffix = {"plan_digest": digest}, "/apply"
    else:
        raise ValueError("Use plan or apply")
    url, key = _resolve_api(agent_id)
    code, result = opencdr._request(
        "POST", "/detections/recoveries/" + recovery_id + suffix, url, key, json=body
    )
    _raise_on_error(code, result, "feed recovery " + action)
    return result


def _recovery_checkpoint(value):
    if not isinstance(value, dict) or set(value) != {
        "cursor",
        "sequence",
        "receipt_id",
        "principal",
    }:
        raise ValueError("Exact prior durable checkpoint required")
    if type(value["sequence"]) is not int or not 0 <= value["sequence"] <= 10**18:
        raise ValueError("Invalid prior sequence")
    if value["cursor"] is None:
        if value["sequence"] or value["receipt_id"] is not None:
            raise ValueError("Only an empty checkpoint can omit its cursor")
    elif not isinstance(value["cursor"], str) or not 1 <= len(value["cursor"]) <= 512:
        raise ValueError("Invalid prior cursor")
    if value["principal"] is not None:
        _handoff_principal(value["principal"])
    if value["receipt_id"] is not None and (
        not isinstance(value["receipt_id"], str)
        or not re.fullmatch(r"[a-f0-9]{32}", value["receipt_id"])
    ):
        raise ValueError("Invalid prior receipt")
    return value


@_tool(CAP_MAINTENANCE, annotations=_DESTRUCTIVE)
def opencdr_detection_consumer_recover(
    job_id: str,
    plan_digest: str,
    target_epoch: str,
    target_owner: str,
    previous_checkpoint: dict,
    reason: str,
    request_id: str,
    accept_unrecoverable: bool = False,
    agent_id: str | None = None,
) -> dict:
    """Direct IAM delivery: initialize a fresh recovery consumer after reviewed backfill.

    Accepts unavailable history explicitly. The old consumer is never rewound.
    Fleet must queue its recovery instead, so the worker accepts as itself.
    """
    body = _reconciliation_body(job_id, plan_digest, reason, request_id, accept_unrecoverable)
    if not isinstance(target_epoch, str) or not re.fullmatch(r"[a-f0-9]{32}", target_epoch):
        raise ValueError("Reviewed target epoch required")
    body.update(
        target_epoch=target_epoch,
        target_owner=_handoff_principal(target_owner),
        previous_checkpoint=_recovery_checkpoint(previous_checkpoint),
    )
    name = "recovery-" + request_id
    url, key = _consumer_target(name, agent_id)
    code, result = opencdr._request(
        "POST", f"/detections/consumers/{name}/recover", url, key, json=body
    )
    _raise_on_error(code, result, "consumer recovery")
    return result


@_tool(CAP_FLEET_ADMIN, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_detection_recovery_context(agent_id: str) -> dict:
    """Administrator: read the exact local checkpoint and guards before recovery."""
    return _fleet_call("GET", f"/v1/agents/{agent_identifier(agent_id)}/detections/recover")


@_tool(CAP_FLEET_ADMIN, annotations=_DESTRUCTIVE, fleet_only=True)
def opencdr_fleet_detection_recover(
    agent_id: str,
    expected_generation: int,
    expected_registration_rev: int,
    job_id: str,
    plan_digest: str,
    target_epoch: str,
    target_owner: str,
    reason: str,
    request_id: str,
    accept_unrecoverable: bool = False,
    supersedes_request_id: str | None = None,
) -> dict:
    """Queue reviewed backfill replay into a fresh worker-owned delivery consumer.

    Requires paused detection polling. Capture the exact local guards, review
    backfill findings and the replacement worker principal. Completion preserves
    existing Fleet records and leaves polling paused for separate verification.
    """
    for value in (expected_generation, expected_registration_rev):
        if type(value) is not int or value < 1:
            raise ValueError("Positive checkpoint and registration guards required")
    body = _reconciliation_body(job_id, plan_digest, reason, request_id, accept_unrecoverable)
    if not isinstance(target_epoch, str) or not re.fullmatch(r"[a-f0-9]{32}", target_epoch):
        raise ValueError("Reviewed target epoch required")
    body.update(
        expected_generation=expected_generation,
        expected_registration_rev=expected_registration_rev,
        target_epoch=target_epoch,
        target_owner=_handoff_principal(target_owner),
    )
    if supersedes_request_id is not None:
        if not isinstance(supersedes_request_id, str) or not re.fullmatch(
            r"[a-f0-9]{32}", supersedes_request_id
        ):
            raise ValueError("Invalid superseded request ID")
        body["supersedes_request_id"] = supersedes_request_id
    return _fleet_call("POST", f"/v1/agents/{agent_identifier(agent_id)}/detections/recover", body)


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_detection_handoff_status(handoff_id: str, agent_id: str | None = None) -> dict:
    """Read a reviewed consumer handoff plan or permanent acceptance receipt."""
    url, key = _resolve_api(agent_id)
    code, result = opencdr._request(
        "GET", "/detections/handoffs/" + _backfill_id(handoff_id), url, key
    )
    _raise_on_error(code, result, "consumer handoff status")
    return result


@_tool(CAP_MAINTENANCE, annotations=_MUTATING)
def opencdr_detection_handoff_plan(
    handoff_id: str,
    consumer_id: str,
    previous_owner: str,
    target_owner: str,
    cursor: str,
    sequence: int,
    reason: str,
    receipt_id: str | None = None,
    agent_id: str | None = None,
) -> dict:
    """Administrator: freeze a handoff plan for review without changing ownership.

    Obtain Fleet's durable checkpoint from its handoff context tool. Use exact
    old/new IAM principal IDs. Acceptance is separate and cannot reset progress.
    A changed feed incarnation requires different recovery, not this operation.
    """
    for value in (handoff_id, consumer_id):
        _backfill_id(value)
    for value in (previous_owner, target_owner):
        _handoff_principal(value)
    if previous_owner == target_owner or type(sequence) is not int or sequence < 0:
        raise ValueError("Different principals and a nonnegative durable sequence are required")
    if (
        not isinstance(cursor, str)
        or not 1 <= len(cursor) <= 512
        or not isinstance(reason, str)
        or not 1 <= len(reason) <= 512
    ):
        raise ValueError("A durable cursor and review reason are required")
    if receipt_id is not None and not re.fullmatch(r"[a-f0-9]{32}", receipt_id):
        raise ValueError("Invalid receipt ID")
    body = {
        "consumer_id": consumer_id,
        "previous_owner": previous_owner,
        "target_owner": target_owner,
        "reason": reason,
        "checkpoint": {"cursor": cursor, "sequence": sequence, "receipt_id": receipt_id},
    }
    url, key = _resolve_api(agent_id)
    code, result = opencdr._request(
        "POST", "/detections/handoffs/" + handoff_id, url, key, json=body
    )
    _raise_on_error(code, result, "consumer handoff plan")
    return result


@_tool(CAP_MAINTENANCE, annotations=_DESTRUCTIVE)
def opencdr_detection_handoff_accept(
    consumer_id: str, handoff_id: str, plan_digest: str, agent_id: str | None = None
) -> dict:
    """Direct IAM delivery: accept a reviewed handoff as its exact new principal.

    Retires the original consumer, preserving its cursor and pending receipt.
    Fleet users must queue its handoff instead so the worker owns acceptance.
    """
    _backfill_id(handoff_id)
    if not re.fullmatch(r"[a-f0-9]{64}", plan_digest):
        raise ValueError("The exact reviewed plan digest is required")
    url, key = _consumer_target(consumer_id, agent_id)
    code, result = opencdr._request(
        "POST",
        f"/detections/consumers/{consumer_id}/handoff",
        url,
        key,
        json={"handoff_id": handoff_id, "plan_digest": plan_digest},
    )
    _raise_on_error(code, result, "consumer handoff acceptance")
    return result


def _reconciliation_body(job_id, plan_digest, reason, request_id, accept_unrecoverable):
    _backfill_id(job_id)
    if (
        not isinstance(plan_digest, str)
        or not re.fullmatch(r"[a-f0-9]{64}", plan_digest)
        or not isinstance(request_id, str)
        or not re.fullmatch(r"[a-f0-9]{32}", request_id)
        or not isinstance(reason, str)
        or not 1 <= len(reason) <= 512
        or accept_unrecoverable is not True
    ):
        raise ValueError(
            "Reviewed digest, request ID, reason and explicit acceptance "
            "of unavailable history are required"
        )
    return {
        "backfill_job_id": job_id,
        "plan_digest": plan_digest,
        "reason": reason,
        "request_id": request_id,
        "accept_unrecoverable": True,
    }


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_detection_backfill_status(
    job_id: str,
    results: bool = False,
    after: str | None = None,
    limit: int = 50,
    agent_id: str | None = None,
) -> dict:
    """Inspect a backfill plan/progress or bounded outcomes and skipped-source findings.

    A completed retained-source scan does not prove complete history. Use results
    and next_after to review invalid, expired or conflicting source records.
    """
    path = "/detections/backfills/" + _backfill_id(job_id)
    if type(limit) is not int or not 1 <= limit <= 100 or (after is not None and not results):
        raise ValueError("Results pagination requires results=true and limit 1–100")
    if results:
        path += "/results?" + _qs(after=after, limit=limit)
    url, key = _resolve_api(agent_id)
    code, result = opencdr._request("GET", path, url, key)
    _raise_on_error(code, result, "backfill status")
    return result


@_tool(CAP_MAINTENANCE, annotations=_REPLAY)
def opencdr_detection_backfill_update(
    job_id: str,
    action: Literal["plan", "step"],
    reason: str | None = None,
    expected_rev: int | None = None,
    plan_digest: str | None = None,
    limit: int = 10,
    agent_id: str | None = None,
) -> dict:
    """Plan a retained-source import, or execute one reviewed bounded step.

    Requires Core administrator access (also the selected agent's write access
    in Fleet mode). Historical imports preserve IDs and do not evaluate rules or
    replay notifications/responses. Inspect status after an uncertain request;
    a lease can require waiting 60 seconds before a safe retry. Never invent IDs
    or treat completion as proof of complete history.
    """
    path = "/detections/backfills/" + _backfill_id(job_id)
    if action == "plan":
        if (
            not isinstance(reason, str)
            or not 1 <= len(reason) <= 512
            or expected_rev is not None
            or plan_digest is not None
        ):
            raise ValueError("Plan requires only an explicit reason")
        body = {"reason": reason}
    elif action == "step":
        if (
            type(expected_rev) is not int
            or expected_rev < 1
            or reason is not None
            or not isinstance(plan_digest, str)
            or not re.fullmatch(r"[a-f0-9]{64}", plan_digest)
            or type(limit) is not int
            or not 1 <= limit <= 25
        ):
            raise ValueError("Step requires exact expected_rev, plan_digest and limit 1–25")
        body = {"expected_rev": expected_rev, "plan_digest": plan_digest, "limit": limit}
        path += "/step"
    else:
        raise ValueError("action must be plan or step")
    url, key = _resolve_api(agent_id)
    code, result = opencdr._request("POST", path, url, key, json=body)
    _raise_on_error(code, result, "backfill " + action)
    return result


@_tool(CAP_SETTINGS, annotations=_DESTRUCTIVE)
def opencdr_detection_consumer_reconcile(
    consumer_id: str,
    expected_rev: int,
    job_id: str,
    plan_digest: str,
    reason: str,
    request_id: str,
    accept_unrecoverable: bool = False,
    agent_id: str | None = None,
) -> dict:
    """Explicitly accept unavailable history and resume this consumer at a completed import.

    Direct Core delivery only. Review the job and findings first. This discards
    the pending receipt and records accepted loss; it is not proof of full recovery.
    Retry the same request_id and content after an uncertain response. Fleet uses
    opencdr_fleet_detection_reconcile so its original worker retains ownership.
    """
    if type(expected_rev) is not int or expected_rev < 1:
        raise ValueError("expected_rev must be positive")
    body = _reconciliation_body(job_id, plan_digest, reason, request_id, accept_unrecoverable)
    url, key = _consumer_target(consumer_id, agent_id)
    code, result = opencdr._request(
        "POST",
        f"/detections/consumers/{consumer_id}/reconcile",
        url,
        key,
        json={**body, "expected_rev": expected_rev},
    )
    _raise_on_error(code, result, "consumer reconciliation")
    return result


def _indexed_detection_read(path: str) -> dict:
    if opencdr.connection_mode(opencdr._load_config()) == "fleet":
        return _fleet_call("GET", "/v1" + path)
    url, key = _resolve_api()
    status, body = opencdr._request("GET", path, url, key)
    _raise_on_error(status, body, "indexed detections")
    return body


def _library_call(method, path, payload=None):
    cfg = opencdr._load_config()
    if opencdr.connection_mode(cfg) == "fleet":
        return _fleet_call(method, "/v1" + path, payload)
    if cfg.get("auth_mode") != "iam":
        raise OpenCDRConfigError("Content library requires IAM")
    url, key = _resolve_api()
    code, report = opencdr._request("GET", "/status", url, key)
    _raise_on_error(code, report, "library capability")
    if report.get("capabilities", {}).get("content_library") != "1.0.0":
        raise RuntimeError("Core content library capability unavailable")
    code, result = opencdr._request(
        method, path, url, key, **({"json": payload} if payload is not None else {})
    )
    _raise_on_error(code, result, "content library")
    return result


def _library_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise ValueError("A 32-character lowercase hex library ID is required")
    return value


@_tool(CAP_READ, annotations=_READ_ONLY, central=True)
def opencdr_library_read(
    view: str = "items",
    content_id: str | None = None,
    version: int | None = None,
    release_id: str | None = None,
    after: str | None = None,
    limit: int = 20,
) -> dict:
    """Read owner-wide drafts, immutable versions/history, or frozen release snapshots.

    Views: items, item, versions, version, artifact, history, releases, release,
    manifest. Saved/frozen content is not validated, approved or active runtime content.
    Pagination uses next_after; versions/history are in ascending numeric order.
    """
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("Library limit must be 1..50")
    lists = {"items", "versions", "history", "releases"}
    if view in {"items", "releases"}:
        if content_id is not None or release_id is not None or version is not None:
            raise ValueError("List views do not take item selectors")
        path = "/library/" + view
    elif view in {"release", "manifest"}:
        if content_id is not None or version is not None:
            raise ValueError("Release views require only release_id")
        path = "/library/releases/" + _library_id(release_id)
        if view == "manifest":
            path += "/artifact"
    elif view in {"item", "versions", "version", "artifact", "history"}:
        if release_id is not None:
            raise ValueError("Item views do not take release_id")
        path = "/library/items/" + _library_id(content_id)
        if view in {"version", "artifact"}:
            if type(version) is not int or not 1 <= version <= 9007199254740991:
                raise ValueError("A positive version is required")
            path += f"/versions/{version}" + ("/artifact" if view == "artifact" else "")
        elif version is not None:
            raise ValueError("This view does not take a version")
        elif view != "item":
            path += "/" + view
    else:
        raise ValueError("Unknown library view")
    if view in lists:
        params = {"limit": limit}
        if after is not None:
            if view in {"versions", "history"}:
                if (
                    not isinstance(after, str)
                    or not re.fullmatch(r"[0-9]{1,16}", after)
                    or int(after) > 9007199254740991
                ):
                    raise ValueError("Invalid numeric library cursor")
            else:
                _library_id(after)
            params["after"] = after
        path += "?" + urlencode(params)
    elif after is not None:
        raise ValueError("Only list views take a cursor")
    return _library_call("GET", path)


@_tool(CAP_RULES, annotations=_MUTATING, central=True)
def opencdr_library_write(operation: str, payload: dict, content_id: str | None = None) -> dict:
    """Save library metadata, a new immutable draft version, or a frozen snapshot.

    Every payload requires stable request_id (32 hex) and reason. create: kind
    (signal/correlation/list), runtime_id, title, description. update: expected_rev,
    title, description, archived. version: expected_rev, document, dependencies
    [{content_id,version,artifact_sha256}], provenance ({kind: authored} or declared
    pinned import metadata). release: title, description, items (pinned references).
    Retry unknown outcomes with identical payload and request_id. This never validates,
    approves, deploys, fetches Git or changes runtime rules. Library is owner-wide.
    """
    fields = {
        "create": {"kind", "runtime_id", "title", "description"},
        "update": {"expected_rev", "title", "description", "archived"},
        "version": {"expected_rev", "document", "dependencies", "provenance"},
        "release": {"title", "description", "items"},
    }
    if (
        operation not in fields
        or not isinstance(payload, dict)
        or set(payload) != fields[operation] | {"request_id", "reason"}
    ):
        raise ValueError("Provide only the documented library fields")
    _library_id(payload["request_id"])
    if (
        not isinstance(payload["reason"], str)
        or not payload["reason"].strip()
        or len(payload["reason"]) > 1000
    ):
        raise ValueError("A library change reason is required")
    if operation in {"create", "release"}:
        if content_id is not None:
            raise ValueError("The library assigns its own ID")
        path = "/library/" + ("items" if operation == "create" else "releases")
    else:
        if (
            type(payload["expected_rev"]) is not int
            or not 1 <= payload["expected_rev"] <= 9007199254740991
        ):
            raise ValueError("Read the current library revision first")
        path = (
            "/library/items/"
            + _library_id(content_id)
            + ("/versions" if operation == "version" else "")
        )
    return _library_call("PUT" if operation == "update" else "POST", path, payload)


@_tool(CAP_RULES, annotations=_MUTATING, central=True)
def opencdr_library_quality(operation: str, owner_id: str, payload: dict) -> dict:
    """Persist a native test, verify a pinned Git import, compile, or map legacy content.

    Owner ID is content_id for test/import; release_id for compile/mapping.
    All commands require request_id and reason. test: reference, events (max 100),
    expected_matches (sorted event indexes). import: expected_rev, dependencies,
    provenance (GitHub repository, exact commit/path/upstream_sha256). compile:
    artifact_sha256 of the frozen release. runtime_import: expected_rev, dependencies,
    source_deployment, source_revision and source_sha256 from a verified observation.
    mapping: compilation_id, legacy_manifest,
    manifest_digest. These operations never promote content or change runtime state.
    Retry an uncertain result with the unchanged request ID and payload.
    """
    fields = {
        "test": {"reference", "events", "expected_matches"},
        "import": {"expected_rev", "dependencies", "provenance"},
        "runtime_import": {
            "expected_rev",
            "dependencies",
            "source_deployment",
            "source_revision",
            "source_sha256",
        },
        "compile": {"artifact_sha256"},
        "mapping": {"compilation_id", "legacy_manifest", "manifest_digest"},
    }
    if (
        operation not in fields
        or not isinstance(payload, dict)
        or set(payload) != fields[operation] | {"request_id", "reason"}
    ):
        raise ValueError("Provide only the documented quality fields")
    _library_id(payload["request_id"])
    if (
        not isinstance(payload["reason"], str)
        or not payload["reason"].strip()
        or len(payload["reason"]) > 1000
    ):
        raise ValueError("A change reason is required")
    if len(json.dumps(payload, allow_nan=False).encode()) > 131072:
        raise ValueError("Library request exceeds byte limit")
    resource, sub = {
        "test": ("items", "tests"),
        "import": ("items", "imports"),
        "runtime_import": ("items", "runtime-imports"),
        "compile": ("releases", "compilations"),
        "mapping": ("releases", "mappings"),
    }[operation]
    return _library_call("POST", f"/library/{resource}/{_library_id(owner_id)}/{sub}", payload)


@_tool(CAP_READ, annotations=_READ_ONLY, central=True)
def opencdr_library_evidence(
    view: str,
    owner_id: str,
    record_id: str | None = None,
    after: str | None = None,
    limit: int = 20,
) -> dict:
    """Read retained tests, compilations or legacy mappings and their freshness.

    Use views tests (content_id), compilations or mappings (release_id). Omit
    record_id for a bounded page; select a record to read its exact artifact.
    Historical passes never imply the latest content, current evaluator or runtime acceptance.
    """
    if view not in {"tests", "compilations", "mappings"}:
        raise ValueError("Unknown evidence view")
    resource = "items" if view == "tests" else "releases"
    path = f"/library/{resource}/{_library_id(owner_id)}/{view}"
    if record_id is not None:
        if after is not None:
            raise ValueError("Record reads do not take a cursor")
        path += "/" + _library_id(record_id)
    else:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Library limit must be 1..50")
        params = {"limit": limit}
        if after is not None:
            params["after"] = _library_id(after)
        path += "?" + urlencode(params)
    return _library_call("GET", path)


@_tool(CAP_READ, annotations=_READ_ONLY, central=True)
def opencdr_library_runtime_source(
    content_id: str, source_deployment: str, source_revision: str
) -> dict:
    """Preview a verified Core-local or fresh scoped Fleet snapshot for runtime import.

    Returns the exact source document, canonical hash and observation time. This is
    read-only; pass the returned hash/revision in a separate runtime_import command.
    """
    if (
        not isinstance(source_deployment, str)
        or not 1 <= len(source_deployment) <= 256
        or not isinstance(source_revision, str)
        or not 1 <= len(source_revision) <= 128
    ):
        raise ValueError("Source deployment and revision are required")
    return _library_call(
        "GET",
        "/library/items/"
        + _library_id(content_id)
        + "/runtime-source?"
        + urlencode({"source_deployment": source_deployment, "source_revision": source_revision}),
    )


def _review_call(method, path, payload=None):
    cfg = opencdr._load_config()
    if opencdr.connection_mode(cfg) == "fleet":
        return _fleet_call(method, "/v1" + path, payload)
    if cfg.get("auth_mode") != "iam":
        raise OpenCDRConfigError("Owner reviews require IAM")
    url, key = _resolve_api()
    code, result = opencdr._request(
        method, path, url, key, **({"json": payload} if payload is not None else {})
    )
    _raise_on_error(code, result, "owner review registry")
    return result


@_tool(CAP_READ, annotations=_READ_ONLY, central=True)
def opencdr_reviews_read(
    approval_id: str | None = None, limit: int = 20, after: str | None = None
) -> dict:
    """Read the owner-scoped approval inbox or one exact review and its binding.

    Current owner grants filter results. Follow next_after even for an empty page.
    A registry decision does not execute a mutation or authorize a queued job.
    """
    if type(limit) is not int or not 1 <= limit <= 50:
        raise ValueError("Review page limit must be 1 to 50")
    if approval_id is not None:
        if after is not None:
            raise ValueError("A detail read does not accept a cursor")
        return _review_call("GET", "/reviews/" + _case_id(approval_id))
    if after is not None and (not isinstance(after, str) or not 1 <= len(after) <= 1024):
        raise ValueError("Invalid review cursor")
    return _review_call("GET", "/reviews?" + _qs(limit=limit, after=after))


@_tool(CAP_RULES, annotations=_MUTATING, central=True)
def opencdr_review_decide(approval_id: str, payload: dict, withdraw: bool = False) -> dict:
    """Record a review decision or withdrawal; never execute the reviewed operation.

    Preserve expected_rev, request_id and reason on retries. Decisions additionally
    require approve (boolean) and mode: peer, self_exception or emergency. The
    owner enforces live review and response grants; the client grants no authority.
    """
    identity = _case_id(approval_id)
    fields = {"expected_rev", "request_id", "reason"} | (set() if withdraw else {"approve", "mode"})
    if type(withdraw) is not bool or not isinstance(payload, dict) or set(payload) != fields:
        raise ValueError("Invalid review decision fields")
    if type(payload["expected_rev"]) is not int or payload["expected_rev"] < 1:
        raise ValueError("An exact review revision is required")
    _case_id(payload["request_id"])
    if not isinstance(payload["reason"], str) or not 1 <= len(payload["reason"].strip()) <= 1000:
        raise ValueError("A review reason is required")
    if not withdraw and (
        type(payload["approve"]) is not bool
        or payload["mode"] not in ("peer", "self_exception", "emergency")
    ):
        raise ValueError("An explicit decision and configured review mode are required")
    return _review_call(
        "POST", "/reviews/" + identity + ("/withdrawals" if withdraw else "/decisions"), payload
    )


@_tool(CAP_RULES, annotations=_MUTATING, central=True)
def opencdr_review_propose(payload: dict) -> dict:
    """Retain an owner-compiled proposal. This neither approves nor executes it.

    Supply operation, expires_at, request_id and reason. The owner resolves exact
    dependencies and targets; never supply a client-made authorization plan.
    """
    if not isinstance(payload, dict) or set(payload) != {
        "operation",
        "expires_at",
        "request_id",
        "reason",
    }:
        raise ValueError("Invalid review proposal")
    _case_id(payload["request_id"])
    if type(payload["expires_at"]) is not int or payload["expires_at"] <= 0:
        raise ValueError("An explicit approval expiry is required")
    return _review_call("POST", "/reviews", payload)


def _execution_payload(payload: dict, extra=()) -> dict:
    if not isinstance(payload, dict) or set(payload) != {
        "expected_rev",
        "request_id",
        "reason",
        *extra,
    }:
        raise ValueError("Invalid reviewed execution fields")
    if type(payload["expected_rev"]) is not int or payload["expected_rev"] < 1:
        raise ValueError("An exact approval revision is required")
    _case_id(payload["request_id"])
    if not isinstance(payload["reason"], str) or not 1 <= len(payload["reason"].strip()) <= 1000:
        raise ValueError("An execution reason is required")
    return payload


def _core_execution_call(method, path, payload=None):
    cfg = opencdr._load_config()
    if opencdr.connection_mode(cfg) == "fleet":
        raise OpenCDRConfigError("Use a reviewed Fleet distribution job for member mutations")
    return _review_call(method, path, payload)


@_tool(CAP_RULES, annotations=_RELEASE, core_only=True)
def opencdr_review_execute(approval_id: str, payload: dict) -> dict:
    """Execute an exact Core approval once; retain the request ID for reconciliation.

    Requires live owner authority. A committed receipt proves stored configuration;
    evaluator activation requires a separate verification read. No automatic retry.
    """
    return _core_execution_call(
        "POST", "/reviews/" + _case_id(approval_id) + "/execute", _execution_payload(payload)
    )


@_tool(CAP_READ, annotations=_READ_ONLY, core_only=True)
def opencdr_review_execution(approval_id: str, verify: bool = False) -> dict:
    """Read the durable Core receipt or freshly compare stored/effective state."""
    if type(verify) is not bool:
        raise ValueError("verify must be boolean")
    return _core_execution_call(
        "GET", "/reviews/" + _case_id(approval_id) + ("/verification" if verify else "/execution")
    )


@_tool(CAP_RULES, annotations=_MUTATING, core_only=True)
def opencdr_review_cancel(approval_id: str, payload: dict) -> dict:
    """Cancel an unstarted Core reviewed job; cannot reset a started or uncertain effect."""
    return _core_execution_call(
        "POST", "/reviews/" + _case_id(approval_id) + "/cancel", _execution_payload(payload)
    )


@_tool(CAP_RULES, annotations=_RELEASE, central=True)
def opencdr_routing_activate(approval_id: str, payload: dict) -> dict:
    """Activate an approved owner routing configuration pinned to a Library version.

    This writes finite-lived configuration, not a feed subscription. Check the
    returned worker_connected flag; never claim automatic routing when false.
    """
    return _review_call(
        "POST", "/reviews/" + _case_id(approval_id) + "/activate", _execution_payload(payload)
    )


@_tool(CAP_READ, annotations=_READ_ONLY, central=True)
def opencdr_routing_activation(approval_id: str) -> dict:
    """Read retained owner routing activation, expiry and feed connection status."""
    return _review_call("GET", "/reviews/" + _case_id(approval_id) + "/activation")


def _case_call(method, path, payload=None):
    cfg = opencdr._load_config()
    if opencdr.connection_mode(cfg) == "fleet":
        # Cases belong to Fleet; never address or fall back to a member Core.
        return _fleet_call(method, "/v1" + path, payload)
    if cfg.get("auth_mode") != "iam":
        raise OpenCDRConfigError("Operational cases require IAM")
    url, key = _resolve_api()
    code, report = opencdr._request("GET", "/status", url, key)
    _raise_on_error(code, report, "case capability")
    if report.get("capabilities", {}).get("operational_cases") != "1.0.0":
        raise RuntimeError("Core operational case capability unavailable")
    code, result = opencdr._request(
        method, path, url, key, **({"json": payload} if payload is not None else {})
    )
    _raise_on_error(code, result, "operational cases")
    return result


def _case_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise ValueError("A 32-character lowercase hex case ID is required")
    return value


@_tool(CAP_READ, annotations=_READ_ONLY, central=True)
def opencdr_cases_list(
    agent_ids: list[str] | None = None,
    status: str | None = None,
    limit: int = 20,
    cursor: str | None = None,
) -> dict:
    """List operational cases from the configured authority. Scope must include every case account.

    Counts apply to this page. Continue even an empty page when next_cursor is set.
    Fleet requires explicit server-side principal grants; a filter never grants access.
    """
    if (
        type(limit) is not int
        or not 1 <= limit <= 50
        or (status is not None and status not in {"open", "investigating", "contained", "closed"})
    ):
        raise ValueError("Invalid case filter or page size")
    if agent_ids is not None and (
        not isinstance(agent_ids, list)
        or not 1 <= len(agent_ids) <= 100
        or any(
            not isinstance(a, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", a)
            for a in agent_ids
        )
        or len(set(agent_ids)) != len(agent_ids)
    ):
        raise ValueError("Select 1 to 100 unique account identifiers")
    return _case_call(
        "GET",
        "/cases?"
        + _qs(
            agent_ids=",".join(agent_ids) if agent_ids else None,
            status=status,
            limit=limit,
            cursor=cursor,
        ),
    )


@_tool(CAP_READ, annotations=_READ_ONLY, central=True)
def opencdr_case_read(
    view: str = "case",
    case_id: str | None = None,
    attachment_id: str | None = None,
    after: int = 0,
    limit: int = 20,
) -> dict:
    """Read a case, immutable history, retained evidence, or the signer's account access.

    view is case, history, evidence, or access. Status labels track work in a SIEM;
    they do not execute an investigation or change detection handling.
    """
    if view == "access":
        return _case_call("GET", "/case-access")
    path = "/cases/" + _case_id(case_id)
    if view == "history":
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Invalid case history pagination")
        path += "/history?" + _qs(after=after, limit=limit)
    elif view == "evidence":
        if not isinstance(attachment_id, str) or not re.fullmatch(r"[a-f0-9]{64}", attachment_id):
            raise ValueError("A retained attachment ID is required")
        path += "/evidence?" + _qs(attachment_id=attachment_id)
    elif view != "case":
        raise ValueError("Unknown case view")
    return _case_call("GET", path)


@_tool(CAP_READ, annotations=_READ_ONLY, central=True)
def opencdr_case_active(agent_id: str, detection_id: str, agent_ids: list[str]) -> dict:
    """Find the accessible active case for one detection in a complete account scope.

    Fleet reads its own index without contacting a member Core. A 404 does not
    prove global absence: the case can include accounts outside your grants/scope.
    """
    if (
        not isinstance(agent_ids, list)
        or not 1 <= len(agent_ids) <= 100
        or any(
            not isinstance(a, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", a)
            for a in agent_ids
        )
        or len(set(agent_ids)) != len(agent_ids)
        or agent_id not in agent_ids
        or not isinstance(detection_id, str)
        or not detection_id.strip()
        or len(detection_id) > 512
    ):
        raise ValueError("Provide the detection identity and 1 to 100 unique account identifiers")
    return _case_call(
        "GET",
        "/cases/active?"
        + _qs(agent_id=agent_id, detection_id=detection_id, agent_ids=",".join(sorted(agent_ids))),
    )


@_tool(CAP_FLEET_ADMIN, annotations=_DESTRUCTIVE, central=True)
def opencdr_case_integration(integration_id: str, payload: dict | None = None) -> dict:
    """Read or bind a dedicated connector principal to scoped SIEM status reporting.

    Administrator only. Supply principal, agent_ids, enabled, incident_origin
    (HTTPS origin), max_age_seconds (60..604800), expected_rev, request_id and reason.
    This configures trust; it does not fetch SIEM data or submit incident status.
    Use Deploy with dedicated integration IAM access for machine connector reports.
    """
    if not isinstance(integration_id, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{1,64}", integration_id
    ):
        raise ValueError("Invalid integration ID")
    if payload is not None:
        fields = {
            "principal",
            "agent_ids",
            "enabled",
            "incident_origin",
            "max_age_seconds",
            "expected_rev",
            "request_id",
            "reason",
        }
        if not isinstance(payload, dict) or set(payload) != fields:
            raise ValueError("Provide only the documented connector binding fields")
        _case_id(payload["request_id"])
        if (
            type(payload["expected_rev"]) is not int
            or payload["expected_rev"] < 0
            or not isinstance(payload["reason"], str)
            or not payload["reason"].strip()
        ):
            raise ValueError("Read the current binding revision and provide a reason")
    return _case_call(
        "GET" if payload is None else "PUT", "/case-integrations/" + integration_id, payload
    )


@_tool(CAP_TRIAGE, annotations=_READ_ONLY, central=True)
def opencdr_case_routing_preview(
    policy: dict, agent_id: str, detection_id: str, case_id: str | None = None
) -> dict:
    """Preview a draft routing policy against owner-verified evidence, without writes.

    The owner validates exact rule versions, grouping, event-time windows and case
    scope. This never activates policy, creates/joins/reopens a case, sends a page
    or invokes a provider. effective_policy_revision remains null for this draft.
    Historical evidence without a rule fingerprint returns an explicit manual result.
    """
    if (
        not isinstance(policy, dict)
        or not isinstance(agent_id, str)
        or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", agent_id)
        or not isinstance(detection_id, str)
        or not 1 <= len(detection_id) <= 512
    ):
        raise ValueError("A routing policy, scoped agent and detection identity are required")
    body = {"policy": policy, "agent_id": agent_id, "detection_id": detection_id}
    if case_id is not None:
        body["case_id"] = _case_id(case_id)
    return _case_call("POST", "/cases/routing/preview", body)


@_tool(CAP_TRIAGE, annotations=_MUTATING, central=True)
def opencdr_case_mutate(operation: str, payload: dict, case_id: str | None = None) -> dict:
    """Create, update, note, attach or detach an operational case with audited concurrency checks.

    Every payload needs request_id (stable 32-hex) and reason. Create also needs title,
    description, severity, agent_ids. Other operations require expected_rev and:
    update: changes; note: text; attach: agent_id+detection_id; detach: attachment_id.
    Retry an unknown outcome with the identical payload and request_id. Closing releases
    active detection links. Reopening can conflict with another active case.
    """
    fields = {
        "create": {"title", "description", "severity", "agent_ids"},
        "update": {"changes"},
        "note": {"text"},
        "attach": {"agent_id", "detection_id"},
        "detach": {"attachment_id"},
    }
    if operation not in fields or not isinstance(payload, dict):
        raise ValueError("Unknown case operation")
    expected = (
        fields[operation]
        | {"request_id", "reason"}
        | (set() if operation == "create" else {"expected_rev"})
    )
    if set(payload) != expected:
        raise ValueError("Provide only the documented case fields")
    _case_id(payload["request_id"])
    if not isinstance(payload["reason"], str) or not 1 <= len(payload["reason"].strip()) <= 1000:
        raise ValueError("A case change reason is required")
    if operation == "create":
        if case_id is not None:
            raise ValueError("Create assigns its own case ID")
        return _case_call("POST", "/cases", payload)
    if type(payload["expected_rev"]) is not int or payload["expected_rev"] < 1:
        raise ValueError("Read the current case revision first")
    path = (
        "/cases/"
        + _case_id(case_id)
        + {"update": "", "note": "/notes", "attach": "/detections", "detach": "/detections/detach"}[
            operation
        ]
    )
    return _case_call("PUT" if operation == "update" else "POST", path, payload)


@_tool(CAP_FLEET_ADMIN, annotations=_DESTRUCTIVE, fleet_only=True)
def opencdr_fleet_case_access(
    principal: str, agent_ids: list[str], expected_rev: int, request_id: str, reason: str
) -> dict:
    """Grant/revoke case account access for an immutable AWS signer. Empty agent_ids revokes.

    Use the canonical principal from opencdr_case_read(view='access'). No implicit
    administrator data access. End-user delegation is separate from this service grant.
    """
    _case_id(request_id)
    if (
        type(expected_rev) is not int
        or expected_rev < 0
        or not isinstance(principal, str)
        or not re.fullmatch(
            r"aws(?:-us-gov|-cn)?:[0-9]{12}:(?:AROA|AIDA)[A-Z0-9]{12,64}", principal
        )
    ):
        raise ValueError("Invalid principal or grant revision")
    return _fleet_call(
        "PUT",
        "/v1/case-access",
        {
            "principal": principal,
            "agent_ids": agent_ids,
            "expected_rev": expected_rev,
            "request_id": request_id,
            "reason": reason,
        },
    )


def _handling_call(
    method, detection_id, agent_id=None, body=None, history=False, after=None, limit=50
):
    if not isinstance(detection_id, str) or not 1 <= len(detection_id) <= 512:
        raise ValueError("A detection ID is required")
    path = "/detections/handling" + ("/history" if history else "")
    path += "?" + _qs(
        detection_id=detection_id,
        after=after if history else None,
        limit=limit if history else None,
    )
    cfg = opencdr._load_config()
    if opencdr.connection_mode(cfg) == "fleet":
        return _fleet_call(method, f"/v1/agents/{agent_identifier(agent_id)}" + path, body)
    if cfg.get("auth_mode") != "iam":
        raise OpenCDRConfigError("Detection handling requires an IAM Core connection")
    url, key = _resolve_api(agent_id)
    code, report = opencdr._request("GET", "/status", url, key)
    _raise_on_error(code, report, "handling capability")
    if report.get("capabilities", {}).get("detection_handling") != "1.0.0":
        raise RuntimeError("Core handling capability unavailable; no edit sent")
    code, result = opencdr._request(
        method, path, url, key, **({"json": body} if body is not None else {})
    )
    _raise_on_error(code, result, "detection handling")
    return result


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_response_outcomes(
    detection_id: str,
    agent_id: str | None = None,
    attempt_id: str | None = None,
    after: str | None = None,
    limit: int = 20,
) -> dict:
    """Read retained response/rollback observations or one attempt's immutable history.

    Fleet forwards only this selected Core read. No historical backfill. Failed
    can include partial effects; unknown requires reconciliation before replay.
    after is the previous next_after; limit is 1..50. No mutation or replay occurs.
    """
    if (
        not isinstance(detection_id, str)
        or not detection_id.strip()
        or len(detection_id) > 512
        or type(limit) is not int
        or not 1 <= limit <= 50
    ):
        raise ValueError("Invalid detection or page size")
    if attempt_id is not None:
        _case_id(attempt_id)
    if after is not None:
        if not isinstance(after, str) or (attempt_id and not re.fullmatch(r"[0-9]{1,12}", after)):
            raise ValueError("Invalid outcome cursor")
        if not attempt_id:
            _case_id(after)
    path = (
        "/detections/outcomes"
        + ("/history" if attempt_id else "")
        + "?"
        + _qs(detection_id=detection_id, attempt_id=attempt_id, after=after, limit=limit)
    )
    cfg = opencdr._load_config()
    if opencdr.connection_mode(cfg) == "fleet":
        return _fleet_call("GET", f"/v1/agents/{agent_identifier(agent_id)}" + path)
    if cfg.get("auth_mode") != "iam":
        raise OpenCDRConfigError("Response outcomes require IAM")
    url, key = _resolve_api(agent_id)
    code, status = opencdr._request("GET", "/status", url, key)
    _raise_on_error(code, status, "outcome capability")
    if status.get("capabilities", {}).get("response_outcomes") != "1.0.0":
        raise RuntimeError("Core outcome capability unavailable")
    code, result = opencdr._request("GET", path, url, key)
    _raise_on_error(code, result, "response outcomes")
    return result


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_detection_handling(
    detection_id: str,
    agent_id: str | None = None,
    history: bool = False,
    after: int = 0,
    limit: int = 50,
) -> dict:
    """Read Core-owned handling or immutable audit history via the configured owner.

    Unlike indexed browsing, Fleet forwards this selected-record request to its Core.
    SIEM references are manual and unverified; investigation remains in the SIEM.
    """
    if (
        type(after) is not int
        or after < 0
        or type(limit) is not int
        or not 1 <= limit <= 100
        or type(history) is not bool
    ):
        raise ValueError("Invalid audit pagination")
    return _handling_call("GET", detection_id, agent_id, history=history, after=after, limit=limit)


@_tool(CAP_TRIAGE, annotations=_MUTATING)
def opencdr_detection_handling_update(
    detection_id: str,
    expected_rev: int,
    request_id: str,
    reason: str,
    changes: dict,
    agent_id: str | None = None,
) -> dict:
    """Edit status/disposition/assignment/note/manual SIEM references with audit and CAS.

    Read the current handling revision first. Supply a stable 32-character lowercase
    hex request ID; after a lost reply retry EXACTLY the same body and ID. A new edit
    needs a new ID and current revision. No response execution or evidence change.
    Fleet requires allow_triage and returns projection_state=pending after Core confirms.
    """
    if (
        type(expected_rev) is not int
        or expected_rev < 0
        or not isinstance(request_id, str)
        or not re.fullmatch(r"[a-f0-9]{32}", request_id)
    ):
        raise ValueError("Expected revision and stable request ID are required")
    if (
        not isinstance(reason, str)
        or not 1 <= len(reason.strip()) <= 1000
        or not isinstance(changes, dict)
        or not changes
        or set(changes) - {"status", "disposition", "assigned_to", "note", "external_refs"}
    ):
        raise ValueError("A reason and supported handling changes are required")
    return _handling_call(
        "PUT",
        detection_id,
        agent_id,
        {
            "expected_rev": expected_rev,
            "request_id": request_id,
            "reason": reason,
            "changes": changes,
        },
    )


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_detections_query(
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 50,
    next_token: str | None = None,
    agent_ids: list[str] | None = None,
    account_ids: list[str] | None = None,
    severities: list[Severity] | None = None,
    kind: Literal["signal", "correlation"] | None = None,
    rule_id: str | None = None,
    source: str | None = None,
    integration_id: str | None = None,
    summary: bool = False,
    status: Literal["open", "acknowledged", "resolved", "dismissed"] | None = None,
    disposition: str | None = None,
    has_incident: bool | None = None,
) -> dict:
    """Query indexed signals/correlations, or bounded counts, in the configured owner.

    Fleet mode reads Fleet's central index without live member fanout. Core mode
    reads the selected Core. Inclusive dates filter Core commit time, max 90 days.
    Cursors bind the filters and expire after one hour. Empty pages may have more
    results; inspect next_token, coverage and (for summaries) complete. A summary
    with complete=false is a lower bound, never a proven fleet total. No ACK/write.
    """
    if type(limit) is not int or not 1 <= limit <= 100 or type(summary) is not bool:
        raise ValueError("limit must be 1–100 and summary must be boolean")
    for values, pattern in ((agent_ids, r"[A-Za-z0-9_.:-]{1,128}"), (account_ids, r"[0-9]{12}")):
        if values is not None and (
            not isinstance(values, list)
            or not 1 <= len(values) <= 100
            or any(not isinstance(v, str) or not re.fullmatch(pattern, v) for v in values)
        ):
            raise ValueError("Select 1–100 valid agent or account IDs")
    if next_token is not None and (
        not isinstance(next_token, str) or not 1 <= len(next_token) <= 4096
    ):
        raise ValueError("Invalid detection cursor")
    for value in (rule_id, source, integration_id):
        if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 128):
            raise ValueError("Invalid detection filter")
    query = _qs(
        status=status,
        disposition=disposition,
        has_incident=str(has_incident).lower() if has_incident is not None else None,
        date_from=date_from,
        date_to=date_to,
        limit=limit,
        next_token=next_token,
        agent_ids=",".join(sorted(set(agent_ids))) if agent_ids else None,
        account_ids=",".join(sorted(set(account_ids))) if account_ids else None,
        severity=",".join(sorted(set(severities))) if severities else None,
        kind=kind,
        rule_id=rule_id,
        source=source,
        integration_id=integration_id,
    )
    return _indexed_detection_read(("/detections/summary?" if summary else "/detections?") + query)


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_detection_detail(detection_id: str, agent_id: str | None = None) -> dict:
    """Fetch exact retained detection evidence. Fleet requires an explicit agent ID.

    No live member request is used in Fleet mode. Missing/expired evidence and
    integrity failures remain errors; they are never treated as an empty finding.
    """
    if not isinstance(detection_id, str) or not 1 <= len(detection_id) <= 512:
        raise ValueError("A detection ID is required")
    if opencdr.connection_mode(opencdr._load_config()) == "fleet":
        agent_identifier(agent_id)
    return _indexed_detection_read(
        "/detections/detail?" + _qs(detection_id=detection_id, agent_id=agent_id)
    )


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_signals_search(
    severity: Severity | None = None,
    event_id: str | None = None,
    category: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 25,
    order: Order = "desc",
    next_token: str | None = None,
    integration_id: str | None = None,
    agent_id: str | None = None,
) -> dict:
    """Search detection signals. Read-only.

    Provide exactly ONE selector: severity, event_id, category, or integration_id (the
    backend serves each from a dedicated index and cannot AND-combine them).
    date_from/date_to (YYYY-MM-DD, UTC, inclusive, max 31-day range) apply
    ONLY to the severity selector and default to the last 7 days; they are
    ignored for event_id/category. Paginated via next_token.

    Correlating by source_ip / principal / resource / account / region is not
    yet supported by the backend -- use event_id to pivot on a specific event.
    """
    provided = [x for x in (severity, event_id, category, integration_id) if x]
    if len(provided) != 1:
        raise ValueError("Provide exactly one of severity, event_id, category, or integration_id")
    url, key = _resolve_api(agent_id)
    query = _qs(
        limit=limit,
        order=order,
        severity=severity.upper() if severity else None,
        event_id=event_id,
        category=category,
        integration_id=integration_id,
        date_from=date_from if severity else None,
        date_to=date_to if severity else None,
        next_token=next_token,
    )
    status, body = opencdr._request("GET", f"/signals?{query}", url, key)
    _raise_on_error(status, body, "signals search")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_signals_stats(
    date_from: str | None = None, date_to: str | None = None, agent_id: str | None = None
) -> dict:
    """Signal counts by severity for a date range. Read-only.

    A dashboard/summary view, not a substitute for opencdr_signals_search's
    paginated item listing. Defaults to the last 7 days if neither date is
    given (YYYY-MM-DD, UTC, inclusive; max range 31 days -- the same
    date-range bound the severity selector of opencdr_signals_search uses).
    Returns {date_from, date_to, counts: {<severity>: <count>, ...}, total}.
    """
    url, key = _resolve_api(agent_id)
    query = _qs(date_from=date_from, date_to=date_to)
    path = "/signals/stats" + (f"?{query}" if query else "")
    status, body = opencdr._request("GET", path, url, key)
    _raise_on_error(status, body, "signals stats")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_logs_search(
    service: str | None = None,
    event_id: str | None = None,
    event_name: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 25,
    order: Order = "desc",
    next_token: str | None = None,
    agent_id: str | None = None,
) -> dict:
    """Search audit/CloudTrail logs. Read-only.

    Provide exactly ONE selector: service, event_id, or event_name (the
    backend serves each from a dedicated index and cannot AND-combine them).
    date_from/date_to (YYYY-MM-DD, UTC, inclusive, max 31-day range) apply
    ONLY to the service selector and default to the last 7 days; they are
    ignored for event_id/event_name. Paginated via next_token.

    Correlating by source_ip / principal / access_key_id / user_agent /
    resource / account is not yet supported by the backend -- use event_id to
    pivot on a specific event.
    """
    provided = [x for x in (service, event_id, event_name) if x]
    if len(provided) != 1:
        raise ValueError("Provide exactly one of service, event_id, or event_name")
    url, key = _resolve_api(agent_id)
    query = _qs(
        limit=limit,
        order=order,
        service=service,
        event_id=event_id,
        event_name=event_name,
        date_from=date_from if service else None,
        date_to=date_to if service else None,
        next_token=next_token,
    )
    status, body = opencdr._request("GET", f"/logs?{query}", url, key)
    _raise_on_error(status, body, "logs search")
    return body


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_integrations_get(
    integration_id: str = "",
    jobs: bool = False,
    job_id: str = "",
    next_token: str | None = None,
    agent_id: str | None = None,
) -> dict:
    """Read a parser catalog, binding or ingestion jobs, with job-list pagination.

    The catalog does not enumerate saved bindings. Pass an integration_id to read
    a known binding, jobs=True for its job list, and job_id for diagnostics.
    """
    if (jobs or job_id or next_token is not None) and not integration_id:
        raise ValueError("integration_id is required for job queries")
    if job_id and not jobs:
        raise ValueError("jobs=True is required with job_id")
    if next_token is not None and (not jobs or job_id):
        raise ValueError("next_token is only supported when listing jobs")
    url, key = _resolve_api(agent_id)
    path = "/integrations"
    if integration_id:
        path += "/" + _seg(integration_id, "integration_id")
        if jobs:
            path += "/jobs"
            if job_id:
                path += "/" + _seg(job_id, "job_id")
            elif next_token is not None:
                path += "?" + _qs(next_token=next_token)
    status, body = opencdr._request("GET", path, url, key)
    _raise_on_error(status, body, "integrations get")
    return body


@_tool(CAP_SETTINGS, annotations=_REPLAY)
def opencdr_integrations_replay(
    integration_id: str, job_id: str, agent_id: str | None = None
) -> dict:
    """Enqueue a new analysis-only replay using current binding and rules.

    Each invocation creates a new run; do not blindly retry an ambiguous result.
    Acceptance is not completion. Inspect ingestion jobs for the result. This
    does not execute response actions or send notifications.
    """
    url, key = _resolve_api(agent_id)
    path = (
        f"/integrations/{_seg(integration_id, 'integration_id')}"
        f"/jobs/{_seg(job_id, 'job_id')}/replay"
    )
    status, body = opencdr._request("POST", path, url, key, json={})
    _raise_on_error(status, body, "integration replay")
    return body


@_tool(CAP_SETTINGS, annotations=_MUTATING)
def opencdr_integrations_put(
    integration_id: str, configuration: dict, agent_id: str | None = None
) -> dict:
    """Create/update a binding; configuration must include expected_rev (0 for create)."""
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request(
        "PUT",
        "/integrations/" + _seg(integration_id, "integration_id"),
        url,
        key,
        json=configuration,
    )
    _raise_on_error(status, body, "integration put")
    return body


@_tool(CAP_SETTINGS, annotations=_MUTATING)
def opencdr_integrations_preview(
    integration_id: str,
    configuration: dict,
    record: dict | str,
    agent_id: str | None = None,
) -> dict:
    """Execute the selected parser on one sample; does not activate or emit detections."""
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request(
        "POST",
        "/integrations/" + _seg(integration_id, "integration_id") + "/preview",
        url,
        key,
        json={"config": configuration, "record": record},
    )
    _raise_on_error(status, body, "integration preview")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_settings_get(setting_id: str = "global", agent_id: str | None = None) -> dict:
    """Get an OpenCDR settings document by id (default: global). Read-only."""
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request("GET", f"/settings/{_seg(setting_id, 'setting_id')}", url, key)
    if status == 404:
        return {"found": False, "setting_id": setting_id}
    _raise_on_error(status, body, "settings get")
    return body


@_tool(CAP_SETTINGS, annotations=_MUTATING)
def opencdr_settings_set(
    setting_id: str = "global",
    channels: dict | None = None,
    guardduty_notify: dict | None = None,
    notifications_enabled: bool | None = None,
    routing: dict[str, list[str]] | None = None,
    agent_id: str | None = None,
) -> dict:
    """Update an OpenCDR settings document (idempotent merge upsert).

    Only the fields provided are changed: an omitted channel (slack/
    discord/email/securityhub/jira/webhook) is left untouched, and
    guardduty_notify is merged key-by-key (default/by_severity/by_service/
    by_severity_and_service) rather than replaced wholesale -- same
    read-modify-write semantics as `opencdr.py settings set`, see
    docs/notifications.md. Concurrency-safe: the merge+write is guarded by the
    document's `rev` (optimistic concurrency enforced by the API), so a
    simultaneous edit cannot be silently lost; on a conflict the fetch+merge is
    re-run against the latest state (bounded compare-and-set, not a lock).

    `channels` shape (all keys optional):
      {"slack": {"webhook_url": str},
       "discord": {"webhook_url": str},
       "email": {"topic_arn": str},
       "securityhub": {"enabled": bool},
       "jira": {"url": str, "project": str, "email": str, "token": str},
       "webhook": {"targets": [{"name": str, "url": str, "headers": {..}}]}}
    `guardduty_notify` shape:
      {"default": bool, "by_severity": {"HIGH": bool, ...},
       "by_service": {"<svc>": bool, ...},
       "by_severity_and_service": {"HIGH:<svc>": bool, ...}}
    `routing` replaces the severity-to-channel map when supplied; an omitted
    map is preserved. An empty map restores Core's default channel routing.
    """
    url, key = _resolve_api(agent_id)
    for _ in range(1 if isinstance(key, FleetTarget) else _CAS_MAX_ATTEMPTS):
        base_payload, existing_channels = opencdr._fetch_existing_settings(url, key, setting_id)

        payload = dict(base_payload)
        if notifications_enabled is not None:
            payload["notifications_enabled"] = notifications_enabled
        if routing is not None:
            payload["routing"] = routing
        payload["channels"] = (
            opencdr._merge_channels(existing_channels, channels) if channels else existing_channels
        )
        if guardduty_notify:
            payload["guardduty_notify"] = opencdr._merge_guardduty_notify(
                base_payload.get("guardduty_notify") or {}, guardduty_notify
            )
        payload["expected_rev"] = int(base_payload.get("rev") or 0)

        status, body = opencdr._request(
            "PUT", f"/settings/{_seg(setting_id, 'setting_id')}", url, key, json=payload
        )
        if status == 409 and isinstance(key, FleetTarget):
            _raise_on_error(
                status, body, "fleet revision conflict; inspect Core state before retrying"
            )
        if status == 409:
            continue  # concurrent write -- re-fetch, re-merge against latest, retry
        _raise_on_error(status, body, "settings set")
        return body
    raise RuntimeError(
        f"settings set: {setting_id} is being modified concurrently -- retried "
        f"{_CAS_MAX_ATTEMPTS} times, give up and retry the operation"
    )


@_tool(CAP_SETTINGS, annotations=_DESTRUCTIVE)
def opencdr_settings_delete(
    setting_id: str = "global", agent_id: str | None = None, expected_rev: int | None = None
) -> dict:
    """Delete an OpenCDR settings document by id. DESTRUCTIVE and irreversible."""
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request(
        "DELETE",
        f"/settings/{_seg(setting_id, 'setting_id')}"
        + ("?" + _qs(expected_rev=expected_rev) if expected_rev is not None else ""),
        url,
        key,
    )
    if status == 404:
        return {"found": False, "setting_id": setting_id}
    _raise_on_error(status, body, "settings delete")
    return {"deleted": True, "setting_id": setting_id}


# ---------------------------------------------------------------------------
# IR roles -- which IAM role responder assumes to take automated response
# actions, per AWS account. Privileged security configuration: a write here
# directly controls which role the responder may assume.
# ---------------------------------------------------------------------------


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_ir_roles_list(
    page_size: int = 20, next_token: str | None = None, agent_id: str | None = None
) -> dict:
    """List IR role mappings (which IAM role responder assumes per AWS account). Read-only."""
    url, key = _resolve_api(agent_id)
    query = _qs(page_size=page_size, next_token=next_token)
    status, body = opencdr._request("GET", f"/ir-roles?{query}", url, key)
    _raise_on_error(status, body, "ir-roles list")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_ir_roles_get(aws_account_id: str, agent_id: str | None = None) -> dict:
    """Get the IR role mapping for a 12-digit AWS account id. Read-only."""
    _require_account_id(aws_account_id)
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request(
        "GET", f"/ir-roles/{_seg(aws_account_id, 'aws_account_id')}", url, key
    )
    if status == 404:
        return {"found": False, "aws_account_id": aws_account_id}
    _raise_on_error(status, body, "ir-roles get")
    return body


@_tool(CAP_IR_ROLES, annotations=_DESTRUCTIVE)
def opencdr_ir_roles_upsert(
    aws_account_id: str,
    role_arn: str,
    enabled: bool = True,
    expected_rev: int | None = None,
    agent_id: str | None = None,
) -> dict:
    """Create/update the IR role mapping for an AWS account (PUT upsert).

    PRIVILEGED, security-sensitive: this controls which IAM role the
    responder assumes to take automated response actions in that account.

    role_arn must be an IAM role ARN (arn:aws:iam::<account>:role/<name>) and
    the account embedded in the ARN MUST equal aws_account_id -- a mapping
    whose ARN points at a different account is refused here (and by the API)
    to prevent introducing arbitrary cross-account role assumption. Set
    enabled=False to disable a mapping without deleting it.

    Pass the revision read from opencdr_ir_roles_get to reject stale changes, or
    0 for conditional creation. When omitted, read the current revision once and
    guard the PUT; a conflict is returned without rebasing or automatic retry.
    """
    aws_account_id = _require_account_id(aws_account_id)
    m = _ROLE_ARN_RE.match(role_arn or "")
    if not m:
        raise ValueError("role_arn must be an IAM role ARN: arn:aws:iam::<account>:role/<name>")
    if m.group(1) != aws_account_id:
        raise ValueError(
            "role_arn account does not match aws_account_id -- cross-account role mapping refused"
        )
    url, key = _resolve_api(agent_id)
    _require_capability(url, key, "ir_role_revision_guards")
    if expected_rev is None:
        read_status, current = opencdr._request(
            "GET", f"/ir-roles/{_seg(aws_account_id, 'aws_account_id')}", url, key
        )
        if read_status == 404:
            expected_rev = 0
        else:
            _raise_on_error(read_status, current, "ir-roles upsert read")
            expected_rev = int(current.get("rev") or 0)
    if isinstance(expected_rev, bool) or not isinstance(expected_rev, int) or expected_rev < 0:
        raise ValueError("expected_rev must be a non-negative integer")
    payload = {"aws_account_id": aws_account_id, "role_arn": role_arn, "enabled": enabled}
    payload["expected_rev"] = expected_rev
    status, body = opencdr._request(
        "PUT", f"/ir-roles/{_seg(aws_account_id, 'aws_account_id')}", url, key, json=payload
    )
    _raise_on_error(status, body, "ir-roles upsert")
    return body


@_tool(CAP_IR_ROLES, annotations=_DESTRUCTIVE)
def opencdr_ir_roles_delete(
    aws_account_id: str, agent_id: str | None = None, expected_rev: int | None = None
) -> dict:
    """Delete the IR role mapping for an AWS account. DESTRUCTIVE.

    Removing a mapping means the responder falls back to its default role for
    that account (or can no longer act in it).
    """
    aws_account_id = _require_account_id(aws_account_id)
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request(
        "DELETE",
        f"/ir-roles/{_seg(aws_account_id, 'aws_account_id')}"
        + ("?" + _qs(expected_rev=expected_rev) if expected_rev is not None else ""),
        url,
        key,
    )
    if status == 404:
        return {"found": False, "aws_account_id": aws_account_id}
    _raise_on_error(status, body, "ir-roles delete")
    return {"deleted": True, "aws_account_id": aws_account_id}


# ---------------------------------------------------------------------------
# IR actions -- executed, rollback-eligible IR actions and their undo.
# ---------------------------------------------------------------------------


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_ir_actions_list(
    page_size: int = 20, next_token: str | None = None, agent_id: str | None = None
) -> dict:
    """List executed, rollback-eligible IR actions. Read-only."""
    url, key = _resolve_api(agent_id)
    query = _qs(page_size=page_size, next_token=next_token)
    status, body = opencdr._request("GET", f"/ir-actions?{query}", url, key)
    _raise_on_error(status, body, "ir-actions list")
    return body


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_ir_actions_get(detection_id: str, agent_id: str | None = None) -> dict:
    """Get a specific executed IR action. Read-only.

    Includes rollback_supported and, once a rollback has been attempted,
    rollback_status ("pending"/"succeeded"/"failed"), rollback_error (set
    only on failure), and rollback_updated_at. rolled_back mirrors
    rollback_status == "succeeded" for back-compat; absent rollback_status
    means no rollback has been attempted yet.
    """
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request(
        "GET", f"/ir-actions/{_seg(detection_id, 'detection_id')}", url, key
    )
    if status == 404:
        return {"found": False, "detection_id": detection_id}
    _raise_on_error(status, body, "ir-actions get")
    return body


@_tool(CAP_IR_ACTIONS_WRITE, annotations=_ROLLBACK)
def opencdr_ir_actions_rollback(
    detection_id: str, reason: str | None = None, agent_id: str | None = None
) -> dict:
    """Enqueue the rollback of a specific IR action for async execution.

    SECURITY-SENSITIVE: this reverses an automated containment action.
    Not idempotent -- a 409 is raised if a rollback is already in flight
    (rollback_status == "pending"); a previously failed rollback can be
    retried, a currently-pending one cannot. Raises on a 400 if rollback
    isn't supported for this action.

    Returns as soon as the rollback is enqueued, not once it has run --
    rollbackHandler executes it separately. Prefer opencdr_response_outcomes
    where available: legacy pending/failed metadata is not proof of an effect.
    New workers block replay after any execution claim and preserve dry runs.

    `reason` is an optional human-readable justification (e.g. "containment
    determined to be a false positive"); when given it is recorded on the
    action's audit trail alongside the server-authenticated caller identity.
    The actor identity itself is never taken from this call -- it comes from
    the authenticated API key on the server side.
    """
    url, key = _resolve_api(agent_id)
    payload: dict[str, Any] = {"interface": "mcp"}
    if reason:
        payload["reason"] = reason
    status, body = opencdr._request(
        "POST", f"/ir-actions/{_seg(detection_id, 'detection_id')}/rollback", url, key, json=payload
    )
    if status == 404:
        return {"found": False, "detection_id": detection_id}
    _raise_on_error(status, body, "ir-actions rollback")
    return body


# Fleet tools operate on the concentrator; Core tools above forward to an explicit agent_id.
_REGISTRATION_FIELDS = {
    "agent_id",
    "name",
    "account_id",
    "region",
    "stage",
    "api_url",
    "enabled",
    "allow_writes",
    "allow_triage",
    "settings_ids",
    "integration_ids",
    "auth_mode",
    "write_access",
}


def _fleet_client() -> FleetClient:
    cfg = opencdr._load_config()
    if opencdr.connection_mode(cfg) != "fleet":
        raise OpenCDRConfigError(
            "This tool requires fleet connection mode; restart MCP after configuring it"
        )
    return FleetClient(FleetConnection.from_config(cfg))


def _fleet_call(
    method: str,
    path: str,
    payload: dict | None = None,
    *,
    fleet_client: FleetClient | None = None,
) -> dict:
    active = fleet_client or _fleet_client()
    status, body = active.verified_request(method, path, json_body=payload)
    if status >= 300:
        raise FleetError(f"Fleet HTTP {status}: {json.dumps(body, default=str)}")
    if not isinstance(body, dict):
        raise FleetError("Fleet Manager returned an unexpected response")
    if status == 207:
        results = body.get("results")
        if not isinstance(results, list):
            raise FleetError("Fleet Manager returned an invalid multi-agent result")
        accepted = all(
            isinstance(row, dict)
            and isinstance(row.get("status_code"), int)
            and 200 <= row["status_code"] < 300
            and row.get("attempted") is True
            and not (row.get("outcome") or row.get("error_code") or row.get("body_omitted"))
            for row in results
        )
        body = {**body, "all_requests_accepted": accepted, "partial_failure": not accepted}
    return body


def _fleet_registration(registration: dict, agent_id: str | None = None) -> dict:
    required = {"agent_id", "name", "account_id", "region", "stage", "api_url"}
    if set(registration) - _REGISTRATION_FIELDS or not required <= set(registration):
        raise ValueError("Use a complete registration document without credentials or metadata")
    agent_identifier(registration["agent_id"])
    if agent_id is not None and registration["agent_id"] != agent_identifier(agent_id):
        raise ValueError("Registration agent_id does not match the requested agent")
    return dict(registration)


def _fleet_revision(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("expected_rev must be a positive registration revision")
    return value


@_tool(CAP_READ, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_status() -> dict:
    """Verify Fleet Manager identity and read its version and deployment status. No Core calls."""
    return _fleet_client().verify()


@_tool(CAP_READ, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_agents_list(limit: int = 20, next_token: str | None = None) -> dict:
    """Read a page of agent identities and observed status. Follow next_token for all accounts.

    Status/configuration timestamps and stale flags describe cached observations,
    not current Core configuration or a guarantee that an evaluator is active.
    Select the exact agent_id when calling any existing Core management tool.
    """
    if not 1 <= limit <= 50:
        raise ValueError("limit must be 1–50")
    return _fleet_call("GET", "/v1/agents?" + _qs(limit=limit, next_token=next_token))


@_tool(CAP_READ, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_agent_get(agent_id: str) -> dict:
    """Read a registered agent's identity, forwarding permissions and cached polling health."""
    return _fleet_call("GET", f"/v1/agents/{agent_identifier(agent_id)}")


@_tool(CAP_READ, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_configuration_get(
    agent_id: str,
    kind: FleetConfigKind | None = None,
    limit: int = 20,
    next_token: str | None = None,
) -> dict:
    """Read a page of a cached configuration snapshot, preserving generation and coverage metadata.

    Contains redacted rule/list/notification/integration documents. Follow the
    pinned next_token; stale or partial registered-ID coverage is not live state.
    Use normal Core tools with agent_id for authoritative live configuration.
    """
    if not 1 <= limit <= 50:
        raise ValueError("limit must be 1–50")
    return _fleet_call(
        "GET",
        f"/v1/agents/{agent_identifier(agent_id)}/configuration?"
        + _qs(kind=kind, limit=limit, next_token=next_token),
    )


@_tool(CAP_FLEET_REFRESH, annotations=_REPLAY, fleet_only=True)
def opencdr_fleet_agent_refresh(agent_id: str) -> dict:
    """Queue a read-only poll. Inspect observation times to confirm completion."""
    return _fleet_call("POST", f"/v1/agents/{agent_identifier(agent_id)}/refresh")


@_tool(CAP_FLEET_ADMIN, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_detection_handoff_context(agent_id: str) -> dict:
    """Read exact durable cursor, receipt and guards for a Core handoff plan.

    Administrator only. A null previous_owner requires corroborating the old
    immutable principal from retained records; never substitute the new owner.
    """
    return _fleet_call("GET", f"/v1/agents/{agent_identifier(agent_id)}/detections/handoff")


@_tool(CAP_FLEET_ADMIN, annotations=_DESTRUCTIVE, fleet_only=True)
def opencdr_fleet_detection_handoff(
    agent_id: str,
    expected_generation: int,
    expected_registration_rev: int,
    handoff_id: str,
    plan_digest: str,
    target_owner: str,
    reason: str,
    request_id: str,
    supersedes_request_id: str | None = None,
) -> dict:
    """Queue a reviewed handoff for acceptance by Fleet's detection worker.

    Accepted intent is not completion. Inspect detection status; a retry requeues
    pending intent even with schedules paused. Cursor, records and gaps survive.
    """
    for value in (expected_generation, expected_registration_rev):
        if type(value) is not int or value < 1:
            raise ValueError("Positive checkpoint generation and registration revision required")
    _backfill_id(handoff_id)
    _handoff_principal(target_owner)
    if not re.fullmatch(r"[a-f0-9]{64}", plan_digest) or not re.fullmatch(
        r"[a-f0-9]{32}", request_id
    ):
        raise ValueError("Reviewed digest and unique request ID required")
    if not isinstance(reason, str) or not 1 <= len(reason) <= 512:
        raise ValueError("A review reason is required")
    body = {
        "expected_generation": expected_generation,
        "expected_registration_rev": expected_registration_rev,
        "handoff_id": handoff_id,
        "plan_digest": plan_digest,
        "target_owner": target_owner,
        "reason": reason,
        "request_id": request_id,
    }
    if supersedes_request_id is not None:
        if not re.fullmatch(r"[a-f0-9]{32}", supersedes_request_id):
            raise ValueError("Invalid superseded request ID")
        body["supersedes_request_id"] = supersedes_request_id
    return _fleet_call("POST", f"/v1/agents/{agent_identifier(agent_id)}/detections/handoff", body)


@_tool(CAP_FLEET_ADMIN, annotations=_DESTRUCTIVE, fleet_only=True)
def opencdr_fleet_detection_reconcile(
    agent_id: str,
    expected_generation: int,
    expected_registration_rev: int,
    job_id: str,
    plan_digest: str,
    reason: str,
    request_id: str,
    accept_unrecoverable: bool = False,
    supersedes_request_id: str | None = None,
) -> dict:
    """Queue reviewed gap recovery through Fleet's original detection worker.

    Administrator only. Obtain checkpoint_generation and registration revision
    from agent status, review the completed Core backfill and its findings, then
    explicitly accept unavailable history. Acceptance does not mean completion;
    inspect agent detection status. Correct a pending request only by explicitly
    naming supersedes_request_id. The worker's consumer identity stays unchanged.
    """
    for value in (expected_generation, expected_registration_rev):
        if type(value) is not int or value < 1:
            raise ValueError("Positive checkpoint generation and registration revision required")
    body = _reconciliation_body(job_id, plan_digest, reason, request_id, accept_unrecoverable)
    body.update(
        expected_generation=expected_generation, expected_registration_rev=expected_registration_rev
    )
    if supersedes_request_id is not None:
        if not re.fullmatch(r"[a-f0-9]{32}", supersedes_request_id):
            raise ValueError("Invalid supersedes_request_id")
        body["supersedes_request_id"] = supersedes_request_id
    return _fleet_call(
        "POST", f"/v1/agents/{agent_identifier(agent_id)}/detections/reconcile", body
    )


@_tool(CAP_FLEET_ADMIN, annotations=_RELEASE, fleet_only=True)
def opencdr_fleet_agent_register(registration: dict) -> dict:
    """Register a reviewed Core agent. Requires administrator profile and fleet IAM registry access.

    IAM registrations require Core to trust the selected Fleet execution roles.
    Legacy keys must already exist in Fleet SSM. This tool accepts no credentials.
    Start with allow_writes=false. Core remains the execution authority.
    """
    return _fleet_call("POST", "/v1/agents", _fleet_registration(registration))


@_tool(CAP_FLEET_ADMIN, annotations=_DESTRUCTIVE, fleet_only=True)
def opencdr_fleet_agent_update(agent_id: str, registration: dict, expected_rev: int) -> dict:
    """Replace agent registration with an explicit revision guard. No conflict retries.

    Changing endpoint, enablement or allow_writes affects forwarding access.
    Review all fields. Account/region/stage immutability is enforced by Fleet Manager.
    """
    payload = _fleet_registration(registration, agent_id)
    payload["expected_rev"] = _fleet_revision(expected_rev)
    return _fleet_call("PUT", f"/v1/agents/{agent_identifier(agent_id)}", payload)


def _fleet_agent_enabled(agent_id: str, expected_rev: int, enabled: bool) -> dict:
    expected_rev = _fleet_revision(expected_rev)
    active = _fleet_client()
    path = f"/v1/agents/{agent_identifier(agent_id)}"
    result = _fleet_call("GET", path, fleet_client=active)
    current = result.get("agent")
    if not isinstance(current, dict) or current.get("rev") != expected_rev:
        raise FleetError("Registration revision changed; inspect the agent and review again")
    payload = {key: value for key, value in current.items() if key in _REGISTRATION_FIELDS}
    payload["enabled"] = enabled
    payload = _fleet_registration(payload, agent_id)
    payload["expected_rev"] = expected_rev
    return _fleet_call("PUT", path, payload, fleet_client=active)


@_tool(CAP_FLEET_ADMIN, annotations=_DESTRUCTIVE, fleet_only=True)
def opencdr_fleet_agent_disable(agent_id: str, expected_rev: int) -> dict:
    """Disable polling/forwarding, retaining registry and observations. Keys remain issued."""
    return _fleet_agent_enabled(agent_id, expected_rev, False)


@_tool(CAP_FLEET_ADMIN, annotations=_DESTRUCTIVE, fleet_only=True)
def opencdr_fleet_agent_enable(agent_id: str, expected_rev: int) -> dict:
    """Enable polling/forwarding using a reviewed registration revision. Security-sensitive."""
    return _fleet_agent_enabled(agent_id, expected_rev, True)


@_tool(CAP_READ, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_read(agent_ids: list[str], path: str, query: dict | None = None) -> dict:
    """GET fan-out to 1–8 agents. Preserve target statuses, omissions and errors.

    HTTP 207 is not overall success. Requests are not atomic. Omitted bodies need
    individual reads. Core remains authoritative; this is not a fleet state mutation.
    """
    if not 1 <= len(agent_ids) <= 8 or len(set(agent_ids)) != len(agent_ids):
        raise ValueError("Choose 1–8 unique agent IDs")
    payload = {
        "agent_ids": [agent_identifier(value) for value in agent_ids],
        "method": "GET",
        "path": relative_path(path, "/"),
        "query": query or {},
    }
    return _fleet_call("POST", "/v1/fleet/read", payload)


@_tool(CAP_FLEET_ADMIN, annotations=_RELEASE, fleet_only=True)
def opencdr_fleet_invoke(
    agent_ids: list[str],
    method: Literal["POST", "PUT", "DELETE"],
    path: str,
    body: dict | None = None,
    query: dict | None = None,
) -> dict:
    """Non-atomic multi-agent write with administrator, IAM and agent write access.

    No automatic retries or rollback. Preserve per-agent partial/unknown outcomes.
    Different revisions usually require individual Core tools with agent_id instead.
    Never interpret API acceptance as evaluator activation.
    """
    if not 1 <= len(agent_ids) <= 8 or len(set(agent_ids)) != len(agent_ids):
        raise ValueError("Choose 1–8 unique agent IDs")
    payload = {
        "agent_ids": [agent_identifier(value) for value in agent_ids],
        "method": method,
        "path": relative_path(path, "/"),
        "query": query or {},
        "body": body,
    }
    return _fleet_call("POST", "/v1/fleet/invoke", payload)


@_tool(CAP_FLEET_ADMIN, annotations=_RELEASE, fleet_only=True)
def opencdr_fleet_request(
    method: Literal["GET", "POST", "PUT", "DELETE"],
    path: str,
    body: dict | None = None,
) -> dict:
    """Administrator-only access to the complete Fleet Manager API, including future routes.

    This broad tool can mutate registry or forward Core writes. Prefer typed tools.
    No retries; inspect every partial/uncertain result. Paths must start with /v1/.
    """
    return _fleet_call(method, relative_path(path), body)


def _rollout_id(value: str) -> str:
    if not re.fullmatch(r"(operator|responder|administrator)-[a-f0-9]{32}", value):
        raise ValueError("Invalid rollout ID")
    return value


@_tool(CAP_RULES, annotations=_MUTATING, fleet_only=True)
def opencdr_fleet_rollout_plan(agent_ids: list[str], manifest: dict) -> dict:
    """Persist a plan for 1–8 explicit targets. Review every operation and retain review_digest.

    This writes Fleet planning metadata but never changes Core configuration.
    """
    return _fleet_call("POST", "/v1/rollouts/plan", {"agent_ids": agent_ids, "manifest": manifest})


@_tool(CAP_RULES, annotations=_RELEASE, fleet_only=True)
def opencdr_fleet_rollout_apply(rollout_id: str, review_digest: str) -> dict:
    """Queue only the original reviewed per-target plans. May disable or delete rules.

    Delivery is idempotent. Partial or unknown outcomes require inspection and
    a new reviewed plan, never blind replay. API acceptance is not runtime activation.
    """
    return _fleet_call(
        "POST", f"/v1/rollouts/{_rollout_id(rollout_id)}/apply", {"review_digest": review_digest}
    )


@_tool(CAP_READ, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_rollout_status(rollout_id: str) -> dict:
    """Read durable per-agent outcomes, including partial and unknown results."""
    return _fleet_call("GET", f"/v1/rollouts/{_rollout_id(rollout_id)}")


@_tool(CAP_RULES, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_rollout_drift(rollout_id: str, after: str | None = None) -> dict:
    """Compare live rules to a rollout manifest. Report differences without applying them."""
    return _fleet_call(
        "POST", f"/v1/rollouts/{_rollout_id(rollout_id)}/drift", {"after": after} if after else {}
    )


@_tool(CAP_RULES, annotations=_MUTATING, fleet_only=True)
def opencdr_fleet_distribution_plan(
    targets: list[dict], request_id: str, reason: str, allocation: dict | None = None
) -> dict:
    """Freeze 1–100 explicit targets and their exact Core approval IDs/revisions.

    Membership changes cannot expand this plan. Preparation resolves at most eight
    members per request. An independently approved Fleet proposal is still required.
    """
    if not isinstance(targets, list) or not 1 <= len(targets) <= 100:
        raise ValueError("Select 1 to 100 exact targets")
    _case_id(request_id)
    for target in targets:
        if not isinstance(target, dict) or set(target) != {
            "agent_id",
            "approval_id",
            "expected_rev",
        }:
            raise ValueError("Invalid distribution target")
        _case_id(target["approval_id"])
        if type(target["expected_rev"]) is not int or target["expected_rev"] < 1:
            raise ValueError("Invalid Core approval revision")
    if allocation is not None:
        if not isinstance(allocation, dict) or set(allocation) != {"group_id", "expected_rev"}:
            raise ValueError("Exact allocation group and revision required")
        _group_id(allocation["group_id"])
        if type(allocation["expected_rev"]) is not int or allocation["expected_rev"] < 1:
            raise ValueError("Exact allocation revision required")
    return _fleet_call(
        "POST",
        "/v1/rollouts/plan",
        {
            "targets": targets,
            "request_id": request_id,
            "reason": reason,
            **({"allocation": allocation} if allocation is not None else {}),
        },
    )


@_tool(CAP_RULES, annotations=_MUTATING, fleet_only=True)
def opencdr_fleet_distribution_prepare(rollout_id: str) -> dict:
    """Resolve one bounded preparation batch; repeat until the frozen job is ready."""
    return _fleet_call("POST", f"/v1/rollouts/{_rollout_id(rollout_id)}/prepare", {})


@_tool(CAP_RULES, annotations=_RELEASE, fleet_only=True)
def opencdr_fleet_distribution_apply(rollout_id: str, payload: dict) -> dict:
    """Queue an approved job with live authority. Never replay uncertain targets."""
    _execution_payload(payload, {"approval_id"})
    _case_id(payload["approval_id"])
    return _fleet_call("POST", f"/v1/rollouts/{_rollout_id(rollout_id)}/apply", payload)


@_tool(CAP_RULES, annotations=_MUTATING, fleet_only=True)
def opencdr_fleet_distribution_reconcile(rollout_id: str, agent_id: str) -> dict:
    """Read a member's receipt and verification; retain the result without resending."""
    if not isinstance(agent_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", agent_id
    ):
        raise ValueError("Invalid agent ID")
    return _fleet_call("POST", f"/v1/rollouts/{_rollout_id(rollout_id)}/reconcile/{agent_id}", {})


@_tool(CAP_RULES, annotations=_MUTATING, fleet_only=True)
def opencdr_fleet_distribution_cancel(rollout_id: str, payload: dict) -> dict:
    """Stop remaining targets. Retain sending, unknown and completed outcomes."""
    if not isinstance(payload, dict) or set(payload) != {"review_digest", "request_id", "reason"}:
        raise ValueError("Invalid cancellation fields")
    _case_id(payload["request_id"])
    if not isinstance(payload["review_digest"], str) or not re.fullmatch(
        r"[a-f0-9]{64}", payload["review_digest"]
    ):
        raise ValueError("An exact review digest is required")
    return _fleet_call("POST", f"/v1/rollouts/{_rollout_id(rollout_id)}/cancel", payload)


@_tool(CAP_READ, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_groups(
    group_id: str | None = None, limit: int = 20, after: str | None = None
) -> dict:
    """Read Fleet-owned groups/rings; listing is scoped and cursor bounded."""
    if group_id is not None:
        if after is not None:
            raise ValueError("A group detail does not accept a cursor")
        return _fleet_call("GET", "/v1/groups/" + _group_id(group_id))
    if (
        type(limit) is not int
        or not 1 <= limit <= 50
        or (after is not None and (not isinstance(after, str) or not 1 <= len(after) <= 4096))
    ):
        raise ValueError("Invalid group page")
    return _fleet_call("GET", "/v1/groups?" + _qs(limit=limit, after=after))


def _group_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", value):
        raise ValueError("Invalid group ID")
    return value


@_tool(CAP_READ, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_group_resolve(group_id: str, expected_rev: int) -> dict:
    """Resolve at most 100 exact members of a known group revision; never dispatch."""
    identity = _group_id(group_id)
    if type(expected_rev) is not int or expected_rev < 1:
        raise ValueError("An exact group revision is required")
    return _fleet_call(
        "POST", "/v1/groups/" + identity + "/resolve", {"expected_rev": expected_rev}
    )


@_tool(CAP_RULES, annotations=_RELEASE, fleet_only=True)
def opencdr_fleet_review_execute(approval_id: str, payload: dict) -> dict:
    """Execute a reviewed Fleet group/ring configuration; never proxy a Core mutation.

    Propose group.configure through opencdr_review_propose, record a separate
    review decision, then execute the exact approved revision with a retained ID.
    """
    return _fleet_call(
        "POST", "/v1/reviews/" + _case_id(approval_id) + "/execute", _execution_payload(payload)
    )


@_tool(CAP_READ, annotations=_READ_ONLY, fleet_only=True)
def opencdr_fleet_review_execution(approval_id: str, verify: bool = False) -> dict:
    """Read a Fleet configuration receipt or compare the retained group version."""
    if type(verify) is not bool:
        raise ValueError("verify must be boolean")
    return _fleet_call(
        "GET",
        "/v1/reviews/" + _case_id(approval_id) + ("/verification" if verify else "/execution"),
    )


@_tool(CAP_READ, annotations=_READ_ONLY, central=True)
def opencdr_configuration_flags() -> dict:
    """Read owner runtime flag types/permissions and the separate Deploy application mechanism."""
    return _review_call("GET", "/configuration/flags")


@_tool(CAP_READ, annotations=_READ_ONLY)
def opencdr_configuration_ownership(agent_id: str | None = None) -> dict:
    """Read Core local/central bindings; reviewed owner-admin changes transfer control."""
    url, key = _resolve_api(agent_id)
    status, body = opencdr._request("GET", "/configuration/ownership", url, key)
    _raise_on_error(status, body, "configuration ownership")
    return body


@_tool(CAP_RULES, annotations=_MUTATING, central=True)
def opencdr_routing_drain(approval_id: str, payload: dict) -> dict:
    """Process at most 20 retained entries at the case owner under its active approval.

    Includes agent_id plus expected_rev/request_id/reason. Preserve request_id on
    unknown outcome; a new request drains the next page. No caller cursor or event
    payload is accepted. Imported history cannot create cases or call providers.
    """
    _execution_payload(payload, extra=("agent_id",))
    if not isinstance(payload["agent_id"], str) or not 1 <= len(payload["agent_id"]) <= 128:
        raise ValueError("An exact source agent is required")
    return _review_call("POST", "/reviews/" + _case_id(approval_id) + "/drain", payload)


@_tool(CAP_RULES, annotations=_MUTATING, central=True)
def opencdr_case_tuning_draft(case_id: str, payload: dict) -> dict:
    """Save a disabled Library version from exact retained case/rule evidence.

    Requires current triage and Library authority. Supply case_rev, attachment_id,
    pinned source reference, proposed document, expected_rev of the Library head,
    request_id and reason. This never promotes a rule or invokes a provider.
    """
    _execution_payload(payload, extra=("case_rev", "attachment_id", "source", "document"))
    return _case_call("POST", "/cases/" + _case_id(case_id) + "/tuning-draft", payload)



@_tool(CAP_READ, annotations=_READ_ONLY, central=True)
def opencdr_case_extensions(case_id: str, kind: str, after: str | None = None) -> dict:
    """Read 20 case-owned indicators or historical provider-results.

    Uses Fleet authority directly in fleet mode; never executes a lookup.
    """
    if kind not in {"indicators", "provider-results"}:
        raise ValueError("Choose indicators or provider-results")
    if after is not None and (not isinstance(after, str) or not 1 <= len(after) <= 2048):
        raise ValueError("Use the exact bounded owner cursor")
    path = "/cases/" + _case_id(case_id) + "/extensions/" + kind
    return _case_call("GET", path + ("?" + _qs(after=after) if after else ""))


@_tool(CAP_TRIAGE, annotations=_MUTATING, central=True)
def opencdr_case_extension_save(case_id: str, kind: str, payload: dict) -> dict:
    """Curate indicators or retain historical provider evidence at the case owner.

    Uses Fleet authority directly in fleet mode.
    History is immutable and explicitly unverified; importing it cannot enqueue
    lookups, send notifications, or authorize paid work. Preserve request_id on an
    unknown result. Current case revision and all case account grants are required.
    """
    if kind not in {"indicators", "provider-results"}:
        raise ValueError("Choose indicators or provider-results")
    extra = ("indicator", "relationship", "note", "source") if kind == "indicators" else ("provider", "reference", "source_sha256", "observed_at", "result", "indicator")
    _execution_payload(payload, extra=extra)
    return _case_call("POST", "/cases/" + _case_id(case_id) + "/extensions/" + kind, payload)


def main() -> None:
    """Run the OpenCDR MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
