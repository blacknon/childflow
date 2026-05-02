childflow Flow Log Schema
===

This document describes the current structured JSON Lines schema emitted by `childflow --flow-log`.

## Status

- current `schema_version`: `1`
- current backend support: `rootless-internal`
- current output format: one JSON object per line

## Common Fields

Every event currently includes these fields:

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | integer | Current value is `1` |
| `ts_ms` | integer | Unix epoch milliseconds |
| `event` | string | Event name |

## Event Types

### `dns_query`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `event` | string | Yes | Always `dns_query` |
| `protocol` | string | Yes | Always `udp` |
| `server` | string | Yes | Socket string such as `1.1.1.1:53` |
| `server_ip` | string | Yes | IP-only server field |
| `server_port` | integer | Yes | Current value is `53` |
| `qname` | string or null | Yes | Normalized DNS question name when it can be extracted from the packet |
| `qtype` | string | Yes | Current values are `A`, `AAAA`, `other`, or `unknown` |

Example:

```json
{"schema_version":1,"ts_ms":1760000000000,"event":"dns_query","protocol":"udp","server":"1.1.1.1:53","server_ip":"1.1.1.1","server_port":53,"qname":"example.com","qtype":"A"}
```

### `dns_answer`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `event` | string | Yes | Always `dns_answer` |
| `protocol` | string | Yes | Always `udp` |
| `server` | string | Yes | Socket string such as `1.1.1.1:53` |
| `server_ip` | string | Yes | IP-only server field |
| `server_port` | integer | Yes | Current value is `53` |
| `qname` | string or null | Yes | Mirrors the paired query name when available |
| `qtype` | string | Yes | Mirrors the paired query classification |
| `mode` | string | Yes | Current values are `relayed` or `synthetic_empty` |
| `bytes` | integer | Yes | Response payload length |

Example:

```json
{"schema_version":1,"ts_ms":1760000000001,"event":"dns_answer","protocol":"udp","server":"1.1.1.1:53","server_ip":"1.1.1.1","server_port":53,"qname":"example.com","qtype":"A","mode":"relayed","bytes":128}
```

### `connect_attempt`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `event` | string | Yes | Always `connect_attempt` |
| `protocol` | string | Yes | Always `tcp` |
| `remote_addr` | string | Yes | Socket string such as `93.184.216.34:443` |
| `remote_ip` | string | Yes | IP-only remote field |
| `remote_port` | integer | Yes | Remote port |
| `via_proxy` | boolean | Yes | Whether the connection uses the configured upstream proxy path |

Example:

```json
{"schema_version":1,"ts_ms":1760000000002,"event":"connect_attempt","protocol":"tcp","remote_addr":"93.184.216.34:443","remote_ip":"93.184.216.34","remote_port":443,"via_proxy":false}
```

### `connect_result`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `event` | string | Yes | Always `connect_result` |
| `protocol` | string | Yes | Always `tcp` |
| `remote_addr` | string | Yes | Socket string such as `93.184.216.34:443` |
| `remote_ip` | string | Yes | IP-only remote field |
| `remote_port` | integer | Yes | Remote port |
| `via_proxy` | boolean | Yes | Whether the attempted connection used the proxy path |
| `status` | string | Yes | Current values are `ok` or `error` |
| `error` | string or null | Yes | Error detail when `status` is `error`, otherwise `null` |

Example:

```json
{"schema_version":1,"ts_ms":1760000000003,"event":"connect_result","protocol":"tcp","remote_addr":"93.184.216.34:443","remote_ip":"93.184.216.34","remote_port":443,"via_proxy":false,"status":"ok","error":null}
```

### `policy_violation`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `event` | string | Yes | Always `policy_violation` |
| `protocol` | string | Yes | Current values include `tcp`, `udp`, `dns`, `icmpv4`, `icmpv6` |
| `remote` | string | Yes | Human-readable remote target |
| `remote_ip` | string or null | Yes | Present when the violation has a concrete remote IP |
| `remote_port` | integer or null | Yes | Present when the violation has a concrete port |
| `action` | string | Yes | Current value is `deny` |
| `reason_code` | string | Yes | Current values include `offline`, `metadata`, `private`, `deny_cidr`, `default_deny`, `proxy_only` |
| `control` | string | Yes | Current values include `--offline`, `--block-metadata`, `--block-private`, `--deny-cidr`, `--default-policy`, `--proxy-only` |
| `matched_cidr` | string or null | Yes | Set for CIDR-based deny rules |
| `reason` | string | Yes | Human-readable explanation |

Example:

```json
{"schema_version":1,"ts_ms":1760000000004,"event":"policy_violation","protocol":"tcp","remote":"10.0.0.1:443","remote_ip":"10.0.0.1","remote_port":443,"action":"deny","reason_code":"deny_cidr","control":"--deny-cidr","matched_cidr":"10.0.0.0/8","reason":"blocked by `--deny-cidr 10.0.0.0/8`"}
```

### `flow_end`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `event` | string | Yes | Always `flow_end` |
| `protocol` | string | Yes | Current value is `tcp` |
| `remote_addr` | string | Yes | Socket string such as `93.184.216.34:443` |
| `remote_ip` | string | Yes | IP-only remote field |
| `remote_port` | integer | Yes | Remote port |

Example:

```json
{"schema_version":1,"ts_ms":1760000000005,"event":"flow_end","protocol":"tcp","remote_addr":"93.184.216.34:443","remote_ip":"93.184.216.34","remote_port":443}
```

### `runtime_failure`

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `event` | string | Yes | Always `runtime_failure` |
| `phase` | string | Yes | Failure phase such as `child_bootstrap`, `run`, `cli_validate`, or `preflight` |
| `reason_code` | string | Yes | Stable runtime failure code such as `tap_create_blocked`, `packet_capture_blocked`, or `runtime_shutdown_failed` |
| `detail` | string | Yes | Human-readable error detail captured at the failure site |

Example:

```json
{"schema_version":1,"ts_ms":1760000000006,"event":"runtime_failure","phase":"child_bootstrap","reason_code":"tap_create_blocked","detail":"failed to create tap device `tap0` inside the rootless-internal child namespace using TUNSETIFF"}
```

Current notes:

- `childflow --summary` surfaces compact `runtime_failure` reason and phase aggregates after a run when `--flow-log` is enabled.
- `childflow --report <flow.jsonl>` uses `reason_code` and `phase` to build post-run failure summaries for saved artifacts.

## Compatibility Notes

- Additive fields within the same `schema_version` should be considered possible.
- Changes that would remove fields, rename fields, or change value meanings should increment `schema_version`.
- Consumers should ignore unknown fields when possible.
