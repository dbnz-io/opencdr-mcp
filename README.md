# OpenCDR MCP

`opencdr-mcp` exposes the OpenCDR management API as tools for MCP-compatible
clients. It is an optional client integration: OpenCDR Core detects and responds
to events without this package.

The server uses stdio transport and connects to an already deployed OpenCDR Core
API. It does not require an OpenCDR source checkout.

## Install

```bash
pip install opencdr-mcp
```

For isolated command-line installation, `pipx` is also supported:

```bash
pipx install opencdr-mcp
```

## Configure

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

`observer` is the default. Profiles only reduce which tools an MCP client can
discover; they are not the authorization boundary. The OpenCDR API enforces the
key scopes. Pair each profile with a key carrying only the corresponding scopes.

## Tool groups

- Deployment status
- Detection and correlation rules
- Reusable lists
- Signals and operational logs
- Ingestion integrations
- Notification settings
- Incident-response roles and action rollback

Mutating operations include MCP safety annotations and use OpenCDR's optimistic
concurrency controls where the API supports them.

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
exactly match `v<project.version>`, for example `v0.1.0`. The `pypi` GitHub
environment and the PyPI trusted publisher must be configured before publishing
the first release; no long-lived PyPI token is stored in GitHub.

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
