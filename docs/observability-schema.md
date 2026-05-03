# childflow observability schema overview

`childflow` currently exposes three machine-readable observability surfaces:

- `childflow --doctor --doctor-format json`
- `childflow --summary --summary-format json`
- `childflow --report <flow.jsonl> --report-format json`

This document is a small index for those surfaces and summarizes the stable key
families they share.

## Schema documents

- doctor: [doctor-schema.md](doctor-schema.md)
- summary: [summary-schema.md](summary-schema.md)
- report: [report-schema.md](report-schema.md)
- flow-log events: [flow-log-schema.md](flow-log-schema.md)

## Shared conventions

### Ranked entries

`summary` and `report` both use the same ranked entry shape for top-N style
aggregates:

```json
{ "key": "deny_domain", "count": 3 }
```

These arrays are sorted by descending `count`, then ascending `key`.

### Runtime failure reason codes

Stable runtime failure `reason_code` values originate from `runtime_failure`
flow-log events and are surfaced consistently in:

- stderr failure output
- `flow_log.runtime_failures` in summary JSON
- `runtime_failures` in report JSON

Examples include:

- `tap_create_blocked`
- `packet_capture_blocked`
- `mount_propagation_blocked`
- `resolv_conf_bind_blocked`

### Domain-policy correlation views

Both `summary` and `report` expose flattened DNS / domain-policy correlation
rows so external tooling can follow:

- queried DNS name
- observed answer IPs
- correlated target socket
- matched blocked domains

`summary` keeps this lightweight for post-run stderr output, while `report`
includes fuller nested correlation views as well.

### Capability keys

`doctor` uses stable capability `key` values for backend capability checks.

Current examples include:

- `namespace_handles`
- `uidmap_helpers`
- `tun_tap_device`
- `af_packet_capture`
- `root_privileges`

Not every key appears for every backend or environment.

## Recommended usage

- Use `doctor` JSON before a run when you want to decide whether a backend is
  likely to work.
- Use `summary` JSON immediately after a run for lightweight CI parsing.
- Use `report` JSON when you want richer artifact analysis from a saved flow log.

## Compatibility notes

- Additive fields should be considered possible in all current JSON surfaces.
- Existing stable keys and `reason_code` values should remain stable once
  introduced.
- Consumers should ignore unknown fields when possible.
