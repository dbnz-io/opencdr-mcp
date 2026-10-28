# Security policy

Please do not disclose vulnerabilities in a public issue. Report them through
GitHub's private vulnerability reporting for `dbnz-io/opencdr-mcp`, or contact
the repository maintainers privately if that feature is unavailable.

The MCP capability profile is defense in depth, not authentication. OpenCDR API
authorization remains the security boundary. Use the least-privileged API key
for the selected profile, keep credentials out of MCP configuration committed to
source control, and rotate a key immediately if its configuration is exposed.
