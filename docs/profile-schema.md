# childflow profile schema

`childflow` profiles are currently TOML files loaded with `--profile <path>`.

The current design goal is reproducibility:

- keep reusable sandbox settings in one file
- allow explicit CLI flags to override those settings at run time
- resolve relative artifact paths from the profile file location
- allow the effective merged configuration to be emitted again with `--dump-profile`

## Precedence

When the same setting appears in both places:

1. explicit CLI flags win
2. profile values fill in the remaining defaults
3. built-in defaults are used when neither provides a value

For list-valued settings such as `allow_cidrs` and `deny_cidrs`, explicit CLI flags replace the profile list rather than appending to it.

`--dump-profile` prints the effective merged configuration as TOML and exits without running the command.

Profiles can also inherit from one parent profile with `extends`.

## Relative paths

The following profile keys are resolved relative to the directory containing the profile file when they are not absolute paths:

- `capture`
- `hosts_file`
- `flow_log`

## Supported keys

| Key | Type | Notes |
| --- | --- | --- |
| `extends` | string | Relative or absolute path to a parent TOML profile |
| `capture` | string | Path written by `--capture` |
| `capture_point` | string | One of `child`, `egress`, `wire-egress`, `both` |
| `backend` | string | One of `rootless-internal`, `rootful` |
| `dns` | string | IPv4 or IPv6 resolver address |
| `hosts_file` | string | `/etc/hosts`-format file |
| `proxy` | string | Proxy URI such as `http://127.0.0.1:8080` |
| `proxy_user` | string | Upstream proxy username |
| `proxy_password` | string | Upstream proxy password |
| `proxy_insecure` | bool | Equivalent to `--proxy-insecure` |
| `summary` | bool | Equivalent to `--summary` |
| `flow_log` | string | Path written by `--flow-log` |
| `offline` | bool | Equivalent to `--offline` |
| `block_private` | bool | Equivalent to `--block-private` |
| `block_metadata` | bool | Equivalent to `--block-metadata` |
| `default_policy` | string | One of `allow`, `deny` |
| `allow_cidrs` | array of strings | IPv4 or IPv6 CIDRs |
| `deny_cidrs` | array of strings | IPv4 or IPv6 CIDRs |
| `proxy_only` | bool | Equivalent to `--proxy-only` |
| `fail_on_leak` | bool | Equivalent to `--fail-on-leak` |
| `iface` | string | Host egress interface; useful with `backend = "rootful"` |
| `command` | array of strings | Command and arguments to run |

## Example

```toml
extends = "./base.toml"
capture = "./captures/run.pcapng"
capture_point = "both"
flow_log = "./logs/run.jsonl"
dns = "1.1.1.1"
backend = "rootless-internal"
block_private = true
block_metadata = true
default_policy = "deny"
allow_cidrs = ["203.0.113.10/32"]
command = ["curl", "https://203.0.113.10/healthz"]
```

## Current notes

- profiles currently use TOML only
- unknown keys are rejected so typos fail fast
- `extends` currently supports a single parent profile
- parent profile paths are resolved relative to the child profile file
- inheritance cycles are rejected
- `--root` is intentionally CLI-only; use `backend = "rootful"` inside profiles instead
- `--fail-on-leak` and `--flow-log` keep their current backend limitations even when configured via profile
- `--dump-profile` emits the effective values after profile loading, CLI override application, and relative path resolution
