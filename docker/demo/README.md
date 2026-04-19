# Docker demo

This directory contains a runnable multi-container demo for `childflow`.

The demo brings up:

- `origin-http`: plain HTTP origin server
- `origin-https`: HTTPS origin server with a self-signed certificate
- `proxy-http`: HTTP proxy with Basic auth
- `proxy-https`: HTTPS-wrapped proxy with Basic auth and a self-signed certificate
- `childflow-demo`: privileged runner container that builds `childflow`, runs `cargo test`, and exercises both proxy flows

## Run the demo

```bash
docker compose -f docker/demo/compose.yml run --rm childflow-demo /workspaces/childflow/docker/demo/run-demo.sh
```

The script verifies:

- unit tests pass inside Linux
- direct access to the origin containers is blocked from the demo runner
- HTTP proxy requests fail without credentials
- HTTPS proxy requests fail without `--proxy-insecure`
- HTTP proxy authentication works
- HTTPS upstream proxy works with `--proxy-insecure` while keeping hostname verification
- `childflow` still writes non-empty `pcapng` capture files during the run

The demo runner container defaults to the non-root `childflow` user, then invokes `childflow` itself through `sudo` inside the script so namespace setup stays reliable across CI environments while the demo still exercises the default rootless path.
