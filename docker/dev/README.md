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

The development image includes `libssl-dev` and `pkg-config` because HTTPS upstream proxy support now depends on OpenSSL through `native-tls`.
It also installs the Rust `clippy` component so the container can run the repo's lint command directly.
For proxy debugging, it also includes `busybox-static`, so you can use `/bin/busybox wget` as a single-binary HTTP client inside the container.
It also builds a tiny Go single-binary HTTP client at `/usr/local/bin/proxycheck`, which prints the selected proxy and then performs the request.

## Run tests

```bash
cargo test
```

For the ignored rootless relay proxy integration test:

```bash
cargo test --test rootless_proxy -- --ignored --nocapture
```

For the experimental rootless backend, a useful smoke check is:

```bash
cargo run -- --network-backend rootless-internal -- curl https://example.com
cargo run -- --network-backend rootless-internal -o /tmp/rootless.pcapng -- curl https://example.com
```

For a single-binary relay proxy check against something like Burp on `host.docker.internal:8080`:

```bash
cargo run -- --network-backend rootless-internal -p http://host.docker.internal:8080 -- /bin/busybox wget -O - http://example.com
cargo run -- --network-backend rootless-internal -p http://host.docker.internal:8080 -- /usr/local/bin/proxycheck http://example.com
```

If the image build fails during `apt-get install` with a message about free space in `/var/cache/apt/archives`, first retry after rebuilding with the current Dockerfile. If your Docker host or Docker Desktop VM is still short on disk, reclaim space with your usual Docker cleanup flow before rerunning the compose command.

## Run a quick example

```bash
cargo run --release -- \
  --network-backend rootful \
  -o /tmp/capture.pcapng \
  -- curl https://example.com
```

## Notes

- `network_mode: host` is used so the container can interact with the host-side Linux networking stack more directly.
- This setup is aimed at Linux Docker hosts. On macOS, Docker Desktop runs a Linux VM internally, so behavior may differ from a native Linux machine.
