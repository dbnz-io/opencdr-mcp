# Detection handling

The `triage` profile adds `opencdr_detection_handling_update` to read tools, including `opencdr_detection_handling` for state/history. Operator/responder/administrator include triage. Observer cannot discover mutation tools. Direct handling requires IAM; Fleet uses its dedicated per-agent route, never the generic proxy.

See the canonical [Core operator and acceptance guide](https://github.com/dbnz-io/opencdr/blob/main/docs/detection-handling.md) in the multi-repository workspace. In standalone checkouts use the matching Core source release’s `docs/detection-handling.md`. The public release must package matching API/contract versions.

Every new edit supplies `expected_rev`, a stable 32-hex `request_id`, a reason and changes. Retry an uncertain request unchanged. Manual SIEM status remains unverified and independent of local handling. Fleet acceptance reports pending projection, not completed synchronization. No case cutover, live deployment or release acceptance is claimed.
