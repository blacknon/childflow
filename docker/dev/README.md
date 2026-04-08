# Docker development environment

This directory provides a simple Linux development environment for `childflow`.

`childflow` needs Linux kernel features and elevated privileges to create namespaces, install `iptables` and TPROXY rules, and open `AF_PACKET` sockets. Because of that, the container is intended to run in `privileged` mode.

## Start an interactive shell

```bash
docker compose -f docker/dev/compose.yml run --rm childflow-dev
```

## Build the project

```bash
cargo build
```

## Run a quick example

```bash
cargo run --release -- \
  -o /tmp/capture.pcapng \
  -- curl https://example.com
```

## Notes

- `network_mode: host` is used so the container can interact with the host-side Linux networking stack more directly.
- This setup is aimed at Linux Docker hosts. On macOS, Docker Desktop runs a Linux VM internally, so behavior may differ from a native Linux machine.
