# childflow doctor schema

`childflow --doctor --doctor-format json` emits a machine-readable diagnosis for
the selected backend.

This document describes the current JSON shape of that report.

## Status

- current output format: one JSON object
- current use case: host capability inspection before a run
- current scope: backend, user ids, overall status, capability checks, and preflight checks

## Top-level fields

| Field | Type | Notes |
| --- | --- | --- |
| `backend` | string | Current values include `rootless-internal` and `rootful` |
| `uid` | integer | Real user id |
| `euid` | integer | Effective user id |
| `status` | string | Current values include `ready`, `ready with warnings`, and `blocked` |
| `capabilities` | array | Capability-oriented checks for the selected backend |
| `preflight` | array | Command and host-environment checks from the preflight phase |

## `capabilities`

Each element currently includes:

| Field | Type | Notes |
| --- | --- | --- |
| `key` | string | Stable machine-readable capability key |
| `label` | string | Human-readable label |
| `status` | string | Current values are `available`, `limited`, or `unavailable` |
| `detail` | string | Human-readable explanation |

### Current capability keys

Current `rootless-internal` and `rootful` reports use stable keys such as:

- `root_privileges`
- `external_commands`
- `forwarding_sysctls`
- `af_packet_capture`
- `namespace_handles`
- `user_namespace_quota`
- `unprivileged_user_namespaces`
- `apparmor_userns_policy`
- `uidmap_helpers`
- `subuid_subgid_entries`
- `tun_tap_device`

Not every key appears for every backend.

Example:

```json
"capabilities": [
  {
    "key": "tun_tap_device",
    "label": "TUN/TAP device",
    "status": "limited",
    "detail": "failed to open `/dev/net/tun` (Permission denied)"
  }
]
```

## `preflight`

Each element currently includes:

| Field | Type | Notes |
| --- | --- | --- |
| `label` | string | Human-readable check name |
| `status` | string | Current values are `ok`, `warning`, or `fatal` |
| `detail` | string | Human-readable explanation |
| `hint` | string or null | Optional remediation hint |

Example:

```json
"preflight": [
  {
    "label": "external commands",
    "status": "warning",
    "detail": "missing helper",
    "hint": "install it"
  }
]
```

## Example

```json
{
  "backend": "rootless-internal",
  "uid": 1000,
  "euid": 1000,
  "status": "ready with warnings",
  "capabilities": [
    {
      "key": "namespace_handles",
      "label": "namespace handles",
      "status": "available",
      "detail": "found `/proc/self/ns/{user,net,mnt}` for rootless setup"
    },
    {
      "key": "tun_tap_device",
      "label": "TUN/TAP device",
      "status": "limited",
      "detail": "failed to open `/dev/net/tun` (Permission denied)"
    }
  ],
  "preflight": [
    {
      "label": "external commands",
      "status": "ok",
      "detail": "required commands are available",
      "hint": null
    }
  ]
}
```

## Compatibility notes

- Additive fields within the current doctor JSON shape should be considered possible.
- Existing `key` values for capability checks should remain stable once introduced.
- Consumers should ignore unknown fields when possible.
- Not all capability keys appear for all backends or environments.
