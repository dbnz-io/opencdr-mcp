# Read the durable detection feed

Consumer state is a separate capability: `opencdr_detection_consumer_status` reads
this principal's receipt/lag; `opencdr_detection_consumer_update` registers,
offers/reads or acknowledges a page. These require a direct Core IAM connection
with `access: delivery`. Update is classified as a non-idempotent write and is
available to settings-capable MCP profiles; AWS still enforces the dedicated
delivery role. ACK only after durable persistence, using the exact returned
revision/receipt. Read may ACK the previous page and offer the next in one call.
After uncertain outcomes inspect status before retrying. Registration cannot reset
an existing consumer, and these tools never fall back to a key or another mode.
Fleet manages worker receipts internally; use its existing detection-status tools
in Fleet mode. Stateless feed and indexed browsing remain nonconsuming.

Reviewed principal handoff uses `opencdr_detection_handoff_plan` and
`opencdr_detection_handoff_status`. Only a direct Core IAM delivery connection
as the reviewed new owner can use `opencdr_detection_handoff_accept`; the plan and
accept tools require the administrator MCP profile. Fleet administrators instead
use `opencdr_fleet_detection_handoff_context` and
`opencdr_fleet_detection_handoff`, so the detection worker performs acceptance.
The old consumer is retired atomically; progress and pending receipts survive.
Inspect completion separately from HTTP 202. A handoff never clears retention
gaps, resumes scheduled polling or repairs a changed feed incarnation. See the
workspace [operator procedure](https://github.com/dbnz-io/opencdr/blob/main/docs/detection-handoffs.md).

`opencdr_detections_feed` reads both native signals and correlated alerts from
Core's IAM-only `/detections/feed` endpoint. Core must advertise `detection_feed`
version 1.x in its status response (management contract 2.1+). The tool is
available to observer and stronger MCP profiles.

```json
{"tool":"opencdr_detections_feed","arguments":{"limit":100}}
```

Pass the returned `next_cursor` as `cursor` to continue, including after an empty
poll. In Fleet mode also supply the selected `agent_id`; the manager verifies
and forwards to that agent. This is not a central multi-account detection query.
Use the independent cursor for that deployment; do not reuse it for another agent.

Reading never acknowledges delivery or updates another consumer's checkpoint.
Limit is 1–100 records; page bytes are bounded by Core. HTTP 410 means replay is
incomplete: reconcile/backfill explicitly before selecting a new start. The tool
does not reset or retry automatically. `start: "latest"` intentionally skips
retained records and cannot be combined with a cursor. Legacy-key connections
cannot access this endpoint and are not used as an IAM fallback.

The equivalent installed Deploy read uses the existing authenticated API command:

```bash
opencdr-deploy api request GET '/detections/feed?limit=100' --connection ./core.json
```

Feed activation does not backfill earlier history. Consumer registration/receipts,
Fleet collection and central search are separate implementation gates; availability
of this read tool does not establish those capabilities.

## Central query reads

Use `opencdr_detections_query` for indexed signals and correlated alerts, with
received date, agent/account, severity, kind, rule, source and integration filters.
`summary=true` requests bounded counts; `complete=false` is a lower bound. Empty
pages can have continuation. Always display coverage and historical incompleteness.
`opencdr_detection_detail` reads one exact retained detection; Fleet requires an
explicit `agent_id`. Fleet mode uses its central index with no live member fanout.
Core mode requires IAM management access. Both tools are observer/read-only.
These are local changes awaiting compatible public releases and live acceptance.


## Feed storage recovery

`opencdr_detection_recovery_status` inspects physical binding or saved plans.
Administrator `opencdr_detection_recovery_update` separates plan from exact-digest
apply. `opencdr_detection_consumer_recover` uses direct IAM delivery to create a
fresh namespace from a reviewed completed backfill. Fleet uses administrator
`opencdr_fleet_detection_recovery_context` and `opencdr_fleet_detection_recover`
so its worker accepts as itself. Normal polling must be paused; completion does
not resume it. See the [full procedure](https://github.com/dbnz-io/opencdr/blob/main/docs/detection-feed-recovery.md)
for guards, accepted uncertainty, retries, cost measurements and remaining PITR/
activation gates.
