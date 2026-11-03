# Security policy

Please do not disclose vulnerabilities in a public issue. Report them through
GitHub's private vulnerability reporting for `dbnz-io/opencdr-mcp`, or contact
the repository maintainers privately if that feature is unavailable.

The MCP capability profile is defense in depth, not authentication. OpenCDR API
authorization remains the security boundary. Use the least-privileged API key
for the selected profile, keep credentials out of MCP configuration committed to
source control, and rotate a key immediately if its configuration is exposed.

In fleet mode, the server signs requests using a named AWS profile, verifies the
manager identity and routes Core tools to an explicit per-call agent ID. It never
falls back to a direct endpoint or stores Core/AWS keys in the MCP config. Each
agent's actual authorization and execution remain enforced by Core, with Fleet
Manager also enforcing IAM and registration forwarding controls.

The administrator profile exposes registry and broad forwarding operations; use
it only with reviewed IAM permissions. Observer is the default. For IAM roles
restricted to individual agents, do not grant `/v1/fleet/*` fan-out routes: IAM
cannot filter the agent IDs inside their JSON body. Prefer per-agent URI grants.

Cached snapshots and tool annotations are not authorization or runtime-activation
proof. Registration updates preserve revision guards; writes and unknown outcomes
are not automatically retried in fleet mode. Configure SSO/role refresh and key
rotation through the customer-owned AWS workflow and OpenCDR Deploy.
