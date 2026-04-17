childflow
===

`childflow` is a Linux-only CLI for running a command tree inside an isolated network namespace with controllable DNS, upstream proxying, and packet capture.

It currently ships with two backends:

- default rootless mode  
  experimental, easy to try, and designed to work without external helpers such as `pasta` or `slirp4netns`
- `rootful`  
  enabled with `--root`; the feature-complete backend built on veth, routing, iptables/ip6tables, and host-side capture

## Highlights

- run a command in an isolated network namespace
- force DNS to a specific resolver
- overlay an `/etc/hosts`-format file for child-side name resolution
- send outbound TCP directly or through HTTP / HTTPS / SOCKS5 upstream proxies
- relay outbound UDP, IPv4 / IPv6 `ping`, and both UDP-style and ICMP-mode `traceroute` on the default rootless backend
- capture child traffic as `pcapng`

## Quick Start

Build locally:

```bash
cargo build --release
sudo install -m 0755 target/release/childflow /usr/local/bin/childflow
```

Show help:

```bash
childflow --help
```

Try the default backend:

```bash
childflow -- curl https://example.com
```

Use the feature-complete backend when you need the current production path:

```bash
sudo childflow --root -o capture.pcapng -- curl https://example.com
```

## Examples

```bash
childflow -o rootless.pcapng -- curl https://example.com
childflow -- ping -c 1 8.8.8.8
childflow -- ping -6 -c 1 2606:4700:4700::1111
childflow -- traceroute -n -q 1 -w 2 8.8.8.8
childflow -- traceroute -I -n -q 1 -w 2 8.8.8.8
childflow --hosts-file ./hosts.override -- curl http://demo.internal
childflow -p http://host.docker.internal:8080 -- curl https://example.com
sudo childflow --root -o capture.pcapng -- curl https://example.com
```

## Main Options

- `--root`  
  switch from the default rootless backend to the rootful backend
- `-o, --output <PATH>`  
  write captured traffic as `pcapng`
- `-d, --dns <IP>`  
  force DNS to a specific IPv4 or IPv6 resolver
- `--hosts-file <PATH>`  
  overlay an `/etc/hosts`-format file so matching names resolve before DNS
- `-p, --proxy <URI>`  
  configure an upstream `http://`, `https://`, or `socks5://` proxy
- `--proxy-user <USER>` / `--proxy-password <PASS>`  
  proxy authentication
- `--proxy-insecure`  
  ignore certificate trust failures for `https://` upstream proxies
- `-i, --iface <NAME>`  
  force direct host-side egress through a specific interface on `--root`

## Choosing A Backend

Start with the default rootless mode when you want the quickest path to isolated execution, DNS control, proxying, and capture without host-wide rootful setup.

Use `--root` when you need the current feature-complete path, including transparent proxying, interface-forced direct egress, and broader raw-ICMP behavior than the current rootless relay engine implements.

If you are evaluating from macOS or another non-Linux environment, use the Docker-based workflow instead of trying to run the binary directly.

## Docker Workflows

- Developer environment: [docker/dev/README.md](docker/dev/README.md)
- Demo environment: [docker/demo/README.md](docker/demo/README.md)

## More Documentation

- Backend matrix, capture behavior, troubleshooting, limitations, and maintainer validation commands: [docs/technical-details.md](docs/technical-details.md)
