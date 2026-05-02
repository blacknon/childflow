# childflow summary schema

`childflow --summary --summary-format json` emits a machine-readable post-run
summary to stderr.

This document describes the current JSON shape of that summary.

## Status

- current output format: one JSON object
- current use case: lightweight post-run aggregation for CI logs and wrapper tooling
- current scope: backend, command, exit code, sandbox controls, capture summary, and flow-log summary

## Top-level fields

| Field | Type | Notes |
| --- | --- | --- |
| `backend` | string | Current values include `rootless-internal` and `rootful` |
| `command` | string | Shell-safe rendered command |
| `exit_code` | integer | Final process exit code |
| `sandbox_controls` | array of strings | Active sandbox control labels |
| `capture` | object | Capture output summary |
| `flow_log` | object | Flow-log-derived summary |

## `capture`

| Field | Type | Notes |
| --- | --- | --- |
| `status` | string | Current values are `disabled` or `enabled` |
| `requested` | string or null | Requested capture view such as `child` or `wire-egress` |
| `effective` | string or null | Effective capture view after expansion such as `child+egress` |
| `output` | string or null | Primary output path for single-file capture modes |
| `child_output` | string or null | Child capture path when `requested = "both"` |
| `egress_output` | string or null | Egress capture path when `requested = "both"` |

Example:

```json
"capture": {
  "status": "enabled",
  "requested": "wire-egress",
  "effective": "wire-egress",
  "output": "/tmp/capture.pcapng",
  "child_output": null,
  "egress_output": null
}
```

## `flow_log`

| Field | Type | Notes |
| --- | --- | --- |
| `status` | string | Current values are `disabled`, `available`, or `unavailable` |
| `path` | string or null | Path passed to `--flow-log` when present |
| `event_counts` | object or null | Aggregate flow-log event counts |
| `top_target` | object or null | Most active connection target |
| `policy_violations` | array | Ranked policy violation counts |
| `connect_errors` | array | Ranked connect error counts |
| `runtime_failures` | array | Ranked runtime failure counts |
| `runtime_failure_phases` | array | Ranked runtime failure phase counts |

When `status` is `disabled` or `unavailable`, aggregate fields may be `null` or
empty arrays.

## `event_counts`

`event_counts` currently includes:

- `total`
- `dns_query`
- `dns_answer`
- `connect_attempt`
- `connect_result`
- `policy_violation`
- `flow_end`
- `runtime_failure`
- `unknown_event`

Example:

```json
"event_counts": {
  "total": 5,
  "dns_query": 0,
  "dns_answer": 0,
  "connect_attempt": 1,
  "connect_result": 1,
  "policy_violation": 1,
  "flow_end": 1,
  "runtime_failure": 1,
  "unknown_event": 0
}
```

## Ranked entries

`policy_violations`, `connect_errors`, `runtime_failures`, and
`runtime_failure_phases` use a common ranked entry shape:

| Field | Type | Notes |
| --- | --- | --- |
| `key` | string | Reason code, error string, or phase |
| `count` | integer | Aggregate count |

These arrays are currently sorted by descending `count`, then ascending `key`.

Example:

```json
"runtime_failures": [
  { "key": "tap_create_blocked", "count": 1 }
]
```

## `top_target`

| Field | Type | Notes |
| --- | --- | --- |
| `target` | string | `host:port`-style remote target |
| `connect_attempts` | integer | Number of `connect_attempt` events |
| `connect_ok` | integer | Number of successful `connect_result` events |
| `connect_error` | integer | Number of error `connect_result` events |
| `flow_end` | integer | Number of `flow_end` events |

Example:

```json
"top_target": {
  "target": "93.184.216.34:443",
  "connect_attempts": 1,
  "connect_ok": 0,
  "connect_error": 1,
  "flow_end": 1
}
```

## Example

```json
{
  "backend": "rootless-internal",
  "command": "curl https://example.com",
  "exit_code": 3,
  "sandbox_controls": [],
  "capture": {
    "status": "enabled",
    "requested": "wire-egress",
    "effective": "wire-egress",
    "output": "/tmp/capture.pcapng",
    "child_output": null,
    "egress_output": null
  },
  "flow_log": {
    "status": "available",
    "path": "./flow.jsonl",
    "event_counts": {
      "total": 5,
      "dns_query": 0,
      "dns_answer": 0,
      "connect_attempt": 1,
      "connect_result": 1,
      "policy_violation": 1,
      "flow_end": 1,
      "runtime_failure": 1,
      "unknown_event": 0
    },
    "top_target": {
      "target": "93.184.216.34:443",
      "connect_attempts": 0,
      "connect_ok": 0,
      "connect_error": 1,
      "flow_end": 1
    },
    "policy_violations": [
      { "key": "deny_cidr", "count": 1 }
    ],
    "connect_errors": [
      { "key": "connection refused", "count": 1 }
    ],
    "runtime_failures": [
      { "key": "tap_create_blocked", "count": 1 }
    ],
    "runtime_failure_phases": [
      { "key": "child_bootstrap", "count": 1 }
    ]
  }
}
```

## Compatibility notes

- Additive fields within the current summary JSON shape should be considered possible.
- Existing field names and value meanings should remain stable unless a future schema version is introduced for the summary format.
- Consumers should ignore unknown fields when possible.
