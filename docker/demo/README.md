# Docker demo

This directory contains a runnable multi-container demo for `childflow`.

The demo brings up:

- `origin-http`: plain HTTP origin server
- `origin-https`: HTTPS origin server with a self-signed certificate
- `proxy-http`: HTTP proxy with Basic auth
- `proxy-https`: HTTPS-wrapped proxy with Basic auth and a self-signed certificate
- `childflow-demo`: privileged runner container that builds `childflow`, runs `cargo test`, and exercises both proxy flows
- reusable TOML demo profiles under `docker/demo/profiles`

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
- profile-driven HTTP proxy execution works via `extends`
- reusable `deny-domain` and `deny-domain-exact` demo profiles are available under `docker/demo/profiles`
- those deny-domain demo profiles fail at runtime as expected and write flow-log artifacts with matched policy domains
- `childflow --report --report-format markdown` can summarize those deny-domain flow logs
- `--dump-profile` prints the merged effective TOML
- HTTPS upstream proxy works with `--proxy-insecure` while keeping hostname verification
- `childflow` still writes non-empty `pcapng` capture files during the run

The demo runner container defaults to the non-root `childflow` user. The script tries `childflow` without `sudo` first, then falls back to `sudo` only if the rootless namespace bootstrap is blocked by the current host policy (for example Ubuntu 24.04 AppArmor restrictions in CI). Set `CHILDFLOW_SUDO_MODE=never`, `auto`, or `always` to override that behavior.

## Render a GIF

The demo runner image also includes `vhs` and `ffmpeg` so it can record terminal demos.

From the repo root:

```bash
mise run demo:gif
```

That runs [docker/demo/render-gif.sh](render-gif.sh), which builds `childflow` inside the demo runner and renders:

- [docker/demo/tapes/proxy-demo.tape](tapes/proxy-demo.tape) to `img/childflow.gif` and `img/childflow-proxy-demo.gif`
- [docker/demo/tapes/profile-demo.tape](tapes/profile-demo.tape) to `img/childflow-profile-demo.gif`
- [docker/demo/tapes/flow-log-demo.tape](tapes/flow-log-demo.tape) to `img/childflow-flow-log-demo.gif`
