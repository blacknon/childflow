# Load Testing

Use [load-test.sh](./load-test.sh) inside the `docker/dev` container to exercise long-running `pcap` and `flow_log` behavior.

Build once:

```bash
cargo build
```

Run a simple 10 minute baseline:

```bash
docker/dev/load-test.sh steady-http 600 both
```

Useful scenarios:

- `steady-http`
  Low-rate baseline. Good for file growth and steady RSS checks.
- `short-tcp`
  Many short-lived TCP connections. Good for connect and flow-end pressure.
- `dns-unique`
  Unique `*.example.invalid` names. Good for DNS correlation growth checks.
- `deny-domain-storm`
  Unique denied names under `example.invalid`. Good for `policy_violation` volume.
- `compare-observability`
  Runs the same baseline in `capture`, `flow-log`, and `both` modes.

Artifacts are written under `/tmp/childflow-loadtest/<scenario>-<timestamp>/`.

Each run directory includes:

- `metrics.log`
  Periodic snapshots of RSS, virtual size, flow-log bytes and lines, and capture bytes
- `summary.txt`
  Derived totals, rates, and RSS trend from `metrics.log`
- `childflow.argv`
  The exact wrapped `childflow` command line
- `flow.jsonl`
  Structured flow log when enabled
- `capture.pcapng`
  Packet capture when enabled
- `stdout.log` and `stderr.log`
  Wrapped command output
- `meta.txt`
  Scenario metadata and final sizes

Examples:

```bash
docker/dev/load-test.sh dns-unique 1800 flow-log
docker/dev/load-test.sh short-tcp 900 both
CHILDFLOW_WORKERS=16 docker/dev/load-test.sh short-tcp 300 both
CHILDFLOW_BACKEND_ARGS="--root" docker/dev/load-test.sh steady-http 300 both
docker/dev/summarize-load-test.sh /tmp/childflow-loadtest/steady-http-20260510-114421/steady-http
```

Notes:

- `steady-http` and `short-tcp` intentionally bind the local test server to a discovered non-loopback host IPv4 address.
- Using `127.0.0.1` would stay inside the child namespace loopback and would not produce `childflow` network events.
- If host IP discovery fails in your environment, set `CHILDFLOW_HTTP_HOST` explicitly.
- If `flow.jsonl` is empty, check `stderr.log`, `meta.txt`, and `childflow.argv` first.
- `summary.txt` is auto-generated after each run, and you can regenerate it from `metrics.log` with `summarize-load-test.sh`.
