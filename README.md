# OpenCDR MCP

`opencdr-mcp` exposes the OpenCDR management API as tools for MCP-compatible
clients. It is an optional client integration: OpenCDR Core detects and responds
to events without this package.

The server uses stdio transport. It connects directly to one Core agent, or to an
optional [Fleet Manager](https://github.com/dbnz-io/opencdr-fleet-manager) for
multiple accounts. It requires no Core or Fleet Manager source checkout.

## Install

```bash
pip install opencdr-mcp
```

For isolated command-line installation, `pipx` is also supported:

```bash
pipx install opencdr-mcp
```

## Connect through Fleet Manager

Fleet mode is available in OpenCDR MCP **0.2.0+**. It uses IAM/SigV4 with a local
AWS profile. The MCP stores no AWS access keys or Core API keys for this mode.
Core remains authoritative for each agent's configuration and response execution.

### Reuse an OpenCDR Deploy connection

First connect the deployed manager with OpenCDR Deploy 0.6.0+:

```bash
aws sso login --profile security-admin
opencdr-deploy fleet connect security-prod \
  --url https://FLEET_API_ID.execute-api.us-east-1.amazonaws.com/prod \
  --profile security-admin --security-account-id 111111111111 \
  --region us-east-1 --stage prod
```

Replace the URL and account ID with your CloudFormation outputs. Then configure
your MCP server to use that saved manager:

```bash
export OPENCDR_CONNECTION_MODE=fleet
export OPENCDR_FLEET_NAME=security-prod
export OPENCDR_MCP_PROFILE=observer
opencdr-mcp
```

The MCP reads only the chosen fleet entry from
`~/.config/opencdr/deployments.json`. Set `OPENCDR_DEPLOY_REGISTRY` if you used a
custom CLI registry. The CLI package is not needed at MCP runtime. For a restricted
MCP identity, set `OPENCDR_FLEET_AWS_PROFILE` to your dedicated reader/operator AWS
profile instead of inheriting the administrative deployment profile. AWS IAM and
the agent's scoped keys enforce access; MCP profiles reduce tool exposure.

Claude Code example:

```bash
claude mcp add opencdr-fleet \
  --env OPENCDR_CONNECTION_MODE=fleet \
  --env OPENCDR_FLEET_NAME=security-prod \
  --env OPENCDR_MCP_PROFILE=observer \
  -- opencdr-mcp
```

One MCP server process connects to one fleet. Add another MCP entry with a
different fleet name for another security account. Each tool invocation selects
its Core agent explicitly; there is no process-wide mutable selected agent.

### Configure a fleet without the CLI registry

Save this JSON as your `OPENCDR_CONFIG_FILE` (or the default MCP configuration):

```json
{
  "mode": "fleet",
  "fleet": {
    "url": "https://FLEET_API_ID.execute-api.us-east-1.amazonaws.com/prod",
    "aws_profile": "fleet-reader",
    "security_account_id": "111111111111",
    "region": "us-east-1",
    "stage": "prod"
  }
}
```

The URL must be the regional AWS `execute-api` URL, including its stage. Custom
manager domains and other AWS partitions are not currently supported. Environment
overrides are `OPENCDR_FLEET_URL`, `OPENCDR_FLEET_AWS_PROFILE`,
`OPENCDR_FLEET_ACCOUNT_ID`, `OPENCDR_FLEET_REGION`, and `OPENCDR_FLEET_STAGE`.
`OPENCDR_CONNECTION_MODE` overrides the configuration mode. Restart the MCP server
after changing its connection mode or capability profile.

In fleet mode, ambient `OPENCDR_API_URL` / `OPENCDR_API_KEY` values are ignored.
Manager identity and fleet contract are checked before requests. A missing agent,
invalid identity, unavailable manager or rejected IAM request fails the operation;
the MCP never falls back to a direct Core connection.

### Choose an agent in each Core tool call

1. Call `opencdr_fleet_status` to verify the manager connection.
2. Call `opencdr_fleet_agents_list`; follow `next_token` for every account.
3. Use the returned `agent_id` in any existing Core tool. Examples:

```json
{"tool": "opencdr_rules_list", "arguments": {"agent_id": "member-prod", "kind": "signal"}}
```

```json
{"tool": "opencdr_settings_get", "arguments": {"agent_id": "member-prod", "setting_id": "global"}}
```

Every existing Core tool accepts `agent_id`: rules, lists, signals, logs,
notifications, integrations/jobs, responder roles and response actions. It is
required in fleet mode and must be omitted for direct Core mode. Different
concurrent calls keep their own agent identity and credentials.

### Fleet tools and profiles

| Profile | Fleet capabilities, in addition to its Core tools |
|---|---|
| `observer` | Manager status, paginated agent inventory, individual agent state, cached configuration, explicit GET fan-out |
| `operator` | Observer fleet reads plus queueing a fresh poll |
| `responder` | Operator fleet operations and existing Core IR-role/rollback tools |
| `administrator` | Responder plus registration/update, enable/disable, explicit multi-agent writes and full manager API requests |

`administrator` is opt-in and never the default. Registry changes and multi-agent
writes carry destructive/security-sensitive MCP annotations. The backend still
requires the corresponding IAM permissions, `allow_writes` and a scoped Core
operator credential. A client-side profile does not grant AWS permissions.

Fleet-specific tools:

- `opencdr_fleet_status`, `opencdr_fleet_agents_list`, `opencdr_fleet_agent_get`.
- `opencdr_fleet_configuration_get`: paginated cached configuration, retaining
  snapshot generation, coverage and stale flags. It is an observation, not live
  Core state. Registered-ID coverage limits still apply.
- `opencdr_fleet_agent_refresh`: queues a poll; inspect timestamps afterwards.
- `opencdr_fleet_agent_register`, `opencdr_fleet_agent_update`: reviewed registration
  objects. Updates require `expected_rev`; no conflict rebasing/retries.
- `opencdr_fleet_agent_enable`, `opencdr_fleet_agent_disable`: explicit registration
  revision guards. Disabling retains state and does not revoke API keys.
- `opencdr_fleet_read`, `opencdr_fleet_invoke`: explicit fan-out to 1–8 agents.
  Multi-agent results are non-atomic. Inspect each target's status, omitted body,
  error and unknown outcome. `all_requests_accepted` reports HTTP acceptance, not
  evaluator activation; `partial_failure` prevents treating HTTP 207 as success.
- `opencdr_fleet_request`: administrator-only complete Fleet Manager API access.

Agent credentials are prepared outside the MCP with
`opencdr-deploy fleet agents register --core-profile ...`, `fleet agents bootstrap`
or hidden-input `fleet agents credentials`. MCP registration tools accept no API
keys. Infrastructure deployment, reviewed artifacts and retained-table recovery
use OpenCDR Deploy's fleet commands.

No forwarded writes are automatically retried. In fleet mode, list/settings
merge tools also return conflicts directly instead of rebasing a write. Inspect
Core state before retrying an uncertain response action or partial release.
The manager verifies live Core identity before forwarding; cached fleet health is
not used as write authorization.

## Configure direct Core access

Set the deployed API endpoint and a scoped API key:

```bash
export OPENCDR_API_URL="https://example.execute-api.us-east-2.amazonaws.com/dev"
export OPENCDR_API_KEY="..."
export OPENCDR_MCP_PROFILE="observer"
```

Environment variables take precedence over the optional JSON configuration
file at `~/.config/opencdr/mcp.json`:

```json
{
  "url": "https://example.execute-api.us-east-2.amazonaws.com/dev",
  "key": "..."
}
```

Set `OPENCDR_CONFIG_FILE` to use another file. Protect configuration files that
contain API keys with owner-only permissions.

OpenCDR deployments store a dedicated MCP key in SSM at
`/opencdr-<stage>/api-key-mcp` and the endpoint at
`/opencdr-<stage>/api-url`. Consult the OpenCDR Core deployment documentation
for retrieval and key-rotation instructions.

## Register

Claude Code example:

```bash
claude mcp add opencdr \
  --env OPENCDR_API_URL="$OPENCDR_API_URL" \
  --env OPENCDR_API_KEY="$OPENCDR_API_KEY" \
  --env OPENCDR_MCP_PROFILE=observer \
  -- opencdr-mcp
```

The command can also be started directly:

```bash
opencdr-mcp
```

## Capability profiles

| Profile | Exposed operations |
|---|---|
| `observer` | Read status, rules, lists, signals, logs, settings, integrations, IR roles and IR actions |
| `operator` | Observer operations plus rule/list, integration and settings changes |
| `responder` | Operator operations plus IR-role changes and IR-action rollback |
| `administrator` | Responder operations plus fleet registry/admin tools when fleet mode is active |

`observer` is the default. Profiles only reduce which tools an MCP client can
discover; they are not the authorization boundary. The OpenCDR API enforces the
key scopes in direct mode. In fleet mode, Fleet Manager IAM and the scoped Core
keys enforce access. Pair each profile with the least permissions its work needs.

## Tool groups

- Deployment status
- Detection and correlation rules
- Core rule schema, candidate validation and side-effect-free fixture evaluation
- Rule release planning/application, runtime activation status and rule metrics
- Reusable lists
- Signals and operational logs
- Ingestion integrations
- Paginated ingestion jobs and analysis-only job replay
- Notification settings
- Incident-response roles and action rollback

Mutating operations include MCP safety annotations and use OpenCDR's optimistic
concurrency controls where the API supports them.

Core is authoritative for validation, configuration revisions and execution
results. Validation/evaluation and release planning do not change deployed rules,
but require the Core `rules` scope and the `operator`, `responder` or
`administrator` profile.
Release application can disable or delete managed rules; inspect its plan first.
Core recomputes the release diff at apply time, so a prior plan is not a frozen
approval token. A partial conflict can follow completed writes; the tool error
preserves Core's completion details and does not retry automatically. After an
accepted release, use `opencdr_rules_runtime_status` until Core reports `verified`.

List metadata and ingestion-job lists accept `next_token`; continue while Core
returns a cursor. Replay queues a new analysis run on every call: acceptance is
not completion, and an ambiguous response must not be retried blindly. IR-role
updates accept `expected_rev`; when omitted, the tool reads a revision once and
guards its write without retrying a conflict.

This package manages agents through the Core API, directly or through the
optional Fleet Manager connection. Platform-owned incident cases, assignments,
triage and approvals are outside that contract. Direct AWS provisioning and
recovery use OpenCDR Deploy. Capability profiles reduce tools, not backend
authorization or a customer's independent direct access.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
ruff check .
pytest
python -m build
python -m twine check dist/*
```

## Releases

GitHub releases publish to PyPI through trusted publishing. The release tag must
exactly match `v<project.version>`, for example `v0.2.0`. The `pypi` GitHub
environment and the PyPI trusted publisher must be configured before publishing
the first release; no long-lived PyPI token is stored in GitHub.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
