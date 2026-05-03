# childflow report schema

`childflow --report <flow.jsonl> --report-format json` emits a machine-readable
summary built from a saved flow log.

This document describes the current JSON shape of that report.

## Status

- current output format: one JSON object
- current source artifact: `childflow --flow-log`
- current report focus: event counts, ranked aggregates, top DNS names, and top connection targets

## Top-level fields

| Field | Type | Notes |
| --- | --- | --- |
| `flow_log` | string | Path passed to `--report` |
| `schema_versions` | array of integers | Distinct flow-log schema versions seen in the input |
| `event_counts` | object | Counts per event type |
| `protocols` | object | Map of protocol name to count |
| `sorted_protocols` | array | Ranked protocol counts |
| `top_dns_names` | array | Ranked DNS names with query / answer counts |
| `dns_target_correlations` | array | Ranked DNS-name to target-IP correlations derived from observed `answer_ips` |
| `dns_policy_correlations` | array | Ranked DNS-name correlations that also summarize matched blocked domains per resolved answer IP set |
| `dns_policy_rows` | array | Flattened DNS policy correlation rows for CI tooling and simple consumers |
| `proxy_usage` | object | Counts for proxied vs direct connect attempts |
| `policy_violations` | object | Map of `reason_code` to count |
| `sorted_policy_violations` | array | Ranked policy violation counts |
| `policy_matched_domains` | object | Map of matched blocked domain name to count |
| `sorted_policy_matched_domains` | array | Ranked matched blocked domain counts |
| `connect_errors` | object | Map of connect error string to count |
| `sorted_connect_errors` | array | Ranked connect error counts |
| `runtime_failures` | object | Map of runtime failure `reason_code` to count |
| `sorted_runtime_failures` | array | Ranked runtime failure counts |
| `runtime_failure_phases` | object | Map of runtime failure `phase` to count |
| `sorted_runtime_failure_phases` | array | Ranked runtime failure phase counts |
| `top_connection_targets` | array | Ranked connection targets with per-target stats |

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
  "total": 7,
  "dns_query": 1,
  "dns_answer": 1,
  "connect_attempt": 2,
  "connect_result": 2,
  "policy_violation": 0,
  "flow_end": 1,
  "runtime_failure": 0,
  "unknown_event": 0
}
```

## Ranked count entries

The `sorted_*` arrays use a common entry shape:

| Field | Type | Notes |
| --- | --- | --- |
| `key` | string | Protocol name, `reason_code`, error string, or phase |
| `count` | integer | Aggregate count |

These arrays are sorted by descending `count`, then ascending `key`.

Example:

```json
"sorted_policy_violations": [
  { "key": "deny_cidr", "count": 3 },
  { "key": "proxy_only", "count": 1 }
]
```

The same ranked-entry shape is also used by `sorted_policy_matched_domains`.

## `proxy_usage`

| Field | Type | Notes |
| --- | --- | --- |
| `proxied_connect_attempts` | integer | `connect_attempt` events where `via_proxy` was `true` |
| `direct_connect_attempts` | integer | `connect_attempt` events where `via_proxy` was `false` |

Example:

```json
"proxy_usage": {
  "proxied_connect_attempts": 4,
  "direct_connect_attempts": 1
}
```

## `top_dns_names`

Each element currently includes:

| Field | Type | Notes |
| --- | --- | --- |
| `qname` | string | Normalized DNS question name |
| `queries` | integer | Number of `dns_query` events that carried this name |
| `answers` | integer | Number of `dns_answer` events that carried this name |
| `answer_ips` | array of strings | Distinct A / AAAA answer IPs observed for this name |
| `targets` | string representation in text / markdown only | The JSON shape for target correlation is exposed separately via `dns_target_correlations` |

The array is currently sorted by descending `queries`, then descending `answers`,
then ascending `qname`.

Example:

```json
"top_dns_names": [
  {
    "qname": "example.com",
    "queries": 2,
    "answers": 1,
    "answer_ips": ["93.184.216.34"]
  }
]
```

## `dns_target_correlations`

Each element currently includes:

| Field | Type | Notes |
| --- | --- | --- |
| `qname` | string | Normalized DNS question name |
| `queries` | integer | Number of `dns_query` events that carried this name |
| `answers` | integer | Number of `dns_answer` events that carried this name |
| `answer_ips` | array of strings | Distinct A / AAAA answer IPs observed for this name |
| `targets` | array | Ranked remote targets whose IP matched one of the observed `answer_ips` |

Each `targets` element currently includes:

| Field | Type | Notes |
| --- | --- | --- |
| `target` | string | `host:port`-style remote target |
| `connect_attempts` | integer | Number of `connect_attempt` events |
| `connect_ok` | integer | Number of successful `connect_result` events |
| `connect_error` | integer | Number of error `connect_result` events |
| `flow_end` | integer | Number of `flow_end` events |
| `matched_domains` | array | Ranked blocked domains correlated to this target IP from `policy_violation.matched_domain` |

The outer array follows the same ordering as `top_dns_names`. Each nested
`targets` array is sorted by descending `connect_attempts`, then descending
`connect_error`, then descending `connect_ok`, then ascending `target`.

Example:

```json
"dns_target_correlations": [
  {
    "qname": "example.com",
    "queries": 2,
    "answers": 1,
    "answer_ips": ["93.184.216.34"],
    "targets": [
        {
          "target": "93.184.216.34:443",
          "connect_attempts": 2,
          "connect_ok": 1,
          "connect_error": 1,
          "flow_end": 1,
          "matched_domains": [
            { "key": "blocked.test", "count": 1 }
          ]
        }
      ]
    }
  ]
```

## `dns_policy_correlations`

Each element currently includes:

| Field | Type | Notes |
| --- | --- | --- |
| `qname` | string | Normalized DNS question name |
| `queries` | integer | Number of `dns_query` events that carried this name |
| `answers` | integer | Number of `dns_answer` events that carried this name |
| `answer_ips` | array of strings | Distinct A / AAAA answer IPs observed for this name |
| `matched_domains` | array | Ranked blocked domains correlated to those answer IPs from `policy_violation.matched_domain` |
| `targets` | array | Ranked remote targets whose IP matched one of the observed `answer_ips` |

The outer array follows the same ordering as `top_dns_names`. Each
`matched_domains` array uses the common ranked-entry shape and is sorted by
descending `count`, then ascending `key`.

Example:

```json
"dns_policy_correlations": [
  {
    "qname": "example.com",
    "queries": 2,
    "answers": 1,
    "answer_ips": ["93.184.216.34"],
    "matched_domains": [
      { "key": "blocked.test", "count": 1 }
    ],
    "targets": [
      {
        "target": "93.184.216.34:443",
        "connect_attempts": 2,
        "connect_ok": 1,
        "connect_error": 1,
        "flow_end": 1,
        "matched_domains": [
          { "key": "blocked.test", "count": 1 }
        ]
      }
    ]
  }
]
```

## `dns_policy_rows`

`dns_policy_rows` is a flattened companion to `dns_policy_correlations`. It is
intended for consumers that prefer one row per correlation instead of nested
arrays.

Each element currently includes:

| Field | Type | Notes |
| --- | --- | --- |
| `qname` | string | Normalized DNS question name |
| `queries` | integer | Number of `dns_query` events that carried this name |
| `answers` | integer | Number of `dns_answer` events that carried this name |
| `answer_ips` | array of strings | Distinct A / AAAA answer IPs observed for this name |
| `target` | string or null | Correlated `host:port` remote target when one was observed |
| `target_ip` | string or null | Parsed IP portion of `target` when available |
| `connect_attempts` | integer | Number of `connect_attempt` events for this row's target |
| `connect_ok` | integer | Number of successful `connect_result` events for this row's target |
| `connect_error` | integer | Number of error `connect_result` events for this row's target |
| `flow_end` | integer | Number of `flow_end` events for this row's target |
| `matched_domains` | array | Ranked blocked domains correlated to this row |

Rows are currently sorted by descending `connect_attempts`, then descending
`connect_error`, then descending `connect_ok`, then ascending `qname`, then
ascending `target`.

When a DNS name has matched blocked domains but no correlated remote target,
`target` and `target_ip` are `null` and the connect counters are `0`.

Example:

```json
"dns_policy_rows": [
  {
    "qname": "example.com",
    "queries": 2,
    "answers": 1,
    "answer_ips": ["93.184.216.34"],
    "target": "93.184.216.34:443",
    "target_ip": "93.184.216.34",
    "connect_attempts": 2,
    "connect_ok": 1,
    "connect_error": 1,
    "flow_end": 1,
    "matched_domains": [
      { "key": "blocked.test", "count": 1 }
    ]
  }
]
```

## `top_connection_targets`

Each element currently includes:

| Field | Type | Notes |
| --- | --- | --- |
| `target` | string | `host:port`-style remote target |
| `connect_attempts` | integer | Number of `connect_attempt` events |
| `connect_ok` | integer | Number of successful `connect_result` events |
| `connect_error` | integer | Number of error `connect_result` events |
| `flow_end` | integer | Number of `flow_end` events |
| `dns_names` | array of strings | Correlated DNS names whose observed `answer_ips` included this target IP |
| `matched_domains` | array | Ranked blocked domains correlated to this target IP from `policy_violation.matched_domain` |

The array is currently sorted by descending `connect_attempts`, then descending
`connect_error`, then descending `connect_ok`, then ascending `target`.

Example:

```json
"top_connection_targets": [
  {
    "target": "93.184.216.34:443",
    "connect_attempts": 2,
    "connect_ok": 1,
    "connect_error": 1,
    "flow_end": 1,
    "dns_names": ["example.com"],
    "matched_domains": [
      { "key": "blocked.test", "count": 1 }
    ]
  }
]
```

## Example

```json
{
  "flow_log": "./flow.jsonl",
  "schema_versions": [1],
  "event_counts": {
    "total": 4,
    "dns_query": 1,
    "dns_answer": 0,
    "connect_attempt": 1,
    "connect_result": 1,
    "policy_violation": 1,
    "flow_end": 0,
    "runtime_failure": 1,
    "unknown_event": 0
  },
  "protocols": {
    "tcp": 3,
    "udp": 1
  },
  "sorted_protocols": [
    { "key": "tcp", "count": 3 },
    { "key": "udp", "count": 1 }
  ],
  "top_dns_names": [
    {
      "qname": "example.com",
      "queries": 1,
      "answers": 1,
      "answer_ips": ["93.184.216.34"]
    }
  ],
  "dns_target_correlations": [
    {
      "qname": "example.com",
      "queries": 1,
      "answers": 1,
      "answer_ips": ["93.184.216.34"],
      "targets": [
        {
          "target": "93.184.216.34:443",
          "connect_attempts": 0,
          "connect_ok": 0,
          "connect_error": 1,
          "flow_end": 1,
          "matched_domains": [
            { "key": "blocked.test", "count": 1 }
          ]
        }
      ]
    }
  ],
  "dns_policy_correlations": [
    {
      "qname": "example.com",
      "queries": 1,
      "answers": 1,
      "answer_ips": ["93.184.216.34"],
      "matched_domains": [
        { "key": "blocked.test", "count": 1 }
      ],
      "targets": [
        {
          "target": "93.184.216.34:443",
          "connect_attempts": 0,
          "connect_ok": 0,
          "connect_error": 1,
          "flow_end": 1,
          "matched_domains": [
            { "key": "blocked.test", "count": 1 }
          ]
        }
      ]
    }
  ],
  "dns_policy_rows": [
    {
      "qname": "example.com",
      "queries": 1,
      "answers": 1,
      "answer_ips": ["93.184.216.34"],
      "target": "93.184.216.34:443",
      "target_ip": "93.184.216.34",
      "connect_attempts": 0,
      "connect_ok": 0,
      "connect_error": 1,
      "flow_end": 1,
      "matched_domains": [
        { "key": "blocked.test", "count": 1 }
      ]
    }
  ],
  "proxy_usage": {
    "proxied_connect_attempts": 1,
    "direct_connect_attempts": 0
  },
  "policy_violations": {
    "proxy_only": 1
  },
  "sorted_policy_violations": [
    { "key": "proxy_only", "count": 1 }
  ],
  "policy_matched_domains": {
    "blocked.test": 1
  },
  "sorted_policy_matched_domains": [
    { "key": "blocked.test", "count": 1 }
  ],
  "connect_errors": {
    "connection refused": 1
  },
  "sorted_connect_errors": [
    { "key": "connection refused", "count": 1 }
  ],
  "runtime_failures": {
    "tap_create_blocked": 1
  },
  "sorted_runtime_failures": [
    { "key": "tap_create_blocked", "count": 1 }
  ],
  "runtime_failure_phases": {
    "child_bootstrap": 1
  },
  "sorted_runtime_failure_phases": [
    { "key": "child_bootstrap", "count": 1 }
  ],
  "top_connection_targets": [
    {
      "target": "93.184.216.34:443",
      "connect_attempts": 1,
      "connect_ok": 0,
      "connect_error": 1,
      "flow_end": 0,
      "dns_names": ["example.com"],
      "matched_domains": [
        { "key": "blocked.test", "count": 1 }
      ]
    }
  ]
}
```

## Compatibility notes

- Additive fields within the current report shape should be considered possible.
- Existing field names and value meanings should remain stable unless a future
  schema version is introduced for the JSON report format.
- Consumers should ignore unknown fields when possible.
- If you only need ranked output, prefer the `sorted_*` arrays over sorting the
  map fields yourself.
