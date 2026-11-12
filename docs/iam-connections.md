# IAM connections

Use the same secret-free connection file as `opencdr-deploy`:

```json
{
  "mode": "core",
  "auth_mode": "iam",
  "url": "https://API_ID.execute-api.us-east-1.amazonaws.com/prod",
  "aws_profile": "customer-operator",
  "access": "operator",
  "deployment": {
    "account_id": "123456789012",
    "home_region": "us-east-1",
    "stage": "prod"
  }
}
```

Set `OPENCDR_CONFIG_FILE` to this file before starting `opencdr-mcp`. Sign in to
the named AWS profile using your usual AWS credential provider. Requests use
SigV4 and temporary session credentials, never a stored Core API key. The server
checks the live Core identity and IAM capability before each tool operation.
Redirects and automatic mutation retries are disabled.

`observer` can read, `operator` can change unarmed rules and ordinary settings,
`responder` can change armed rules and request response operations, and
`administrator` can also maintain IR role mappings. Grant the AWS principal only
the required API path. The connection's access selector does not grant IAM rights.
IAM rule, list, setting and role writes/deletes require `expected_rev`; rule
release apply requires the `expected_plan_digest` returned by the reviewed plan.

Fleet connections support the same `access` selector. The typed
`opencdr_fleet_rollout_plan`, `opencdr_fleet_rollout_apply`,
`opencdr_fleet_rollout_status` and `opencdr_fleet_rollout_drift` tools coordinate
explicit targets through Fleet's durable queue. Apply the original review digest
within 15 minutes. Inspect each target result: partial and unknown outcomes are
not safe to replay. Drift is report-only and never reconciles automatically.

Existing legacy connection files remain explicit migration options. IR-role
updates require the Core `ir_role_revision_guards` capability even in legacy
mode; upgrade older Core releases before using that tool. The SaaS connection
and identity model are outside this implementation and remain a separate review.
