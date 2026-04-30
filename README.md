childflow
===

<p align="center">
<img src="./img/childflow.gif" width="720" />
</p>

childflow - isolate one command tree's network, control its DNS / proxy behavior, and capture only its traffic.
**Linux-only** CLI for per-process-tree network isolation, DNS / hosts / proxy forcing, and focused packet capture.

## About

`childflow` runs one command tree in an isolated network context and applies DNS, hosts, proxy, and capture controls only to that tree.

It has two Linux backends: `rootless-internal` for the default day-to-day path, and `rootful` via `--root` when you need host-integrated behavior such as `--iface` or transparent interception.

- affects only the target command tree, not the whole host session
- can force DNS, `/etc/hosts`, proxying, and packet capture per command tree
- defaults to `rootless-internal`
- uses `--root` only for features like `--iface` and transparent interception

## Install

### cargo

```bash
cargo install childflow
```

### Requirements

Host requirements:

- Linux only
- `ip`
- `iptables`
- `ip6tables`

Additional `rootless-internal` requirements:

- user, network, and mount namespace support
- `/dev/net/tun`
- user namespaces enabled on the host
- `uidmap` is recommended on Debian / Ubuntu style systems for `newuidmap` / `newgidmap` fallback

Additional `rootful` requirements:

- root privileges
- writable `/proc/sys/net/ipv4/ip_forward`
- writable `/proc/sys/net/ipv6/conf/all/forwarding`
- Linux features required for TPROXY when proxy interception is used

If you are evaluating from macOS or another non-Linux environment, use the Docker workflows instead of trying to run the binary directly.

## Usage

```shell
$ childflow --help
Launch a child process tree inside its own netns and capture only its packets

Usage:
  childflow [OPTIONS] -- <COMMAND>...

Options:
  -c, --capture <PATH>           Write only the target command tree's traffic as pcapng
  -C, --capture-point <VIEW>     Capture point or view for --capture: child, egress, wire-egress, or both
      --root                     Use the rootful backend
  -d, --dns <IP>                 Force DNS traffic for the child tree to this resolver
      --hosts-file <PATH>        Overlay an /etc/hosts-format file for the child tree
  -p, --proxy <URI>              Upstream proxy: http://, https://, or socks5://
  -U, --proxy-user <USER>        Username for upstream proxy authentication
  -P, --proxy-password <PASS>    Password for upstream proxy authentication
      --proxy-insecure           Ignore certificate trust errors for https proxies
  -i, --iface <NAME>             Force host-side direct egress interface on --root
  -h, --help                     Print help
  -V, --version                  Print version

```

### example

```bash
childflow -- curl https://example.com
```

```bash
childflow -c rootless.pcapng -- curl https://example.com
```

```bash
childflow -d 1.1.1.1 -- curl https://example.com
```

```bash
childflow --hosts-file ./hosts.override -- curl http://demo.internal
```

```bash
childflow -p http://127.0.0.1:8080 -- curl https://example.com
```

```bash
childflow \
  -p https://proxy.example.com:443 \
  -U alice \
  -P secret \
  -- curl https://example.com
```

```bash
sudo childflow --root -c capture.pcapng -- curl https://example.com
```

```bash
childflow -- ping -c 1 8.8.8.8
childflow -- ping -6 -c 1 2606:4700:4700::1111
```

```bash
childflow -- traceroute -n -q 1 -w 2 8.8.8.8
childflow -- traceroute -I -n -q 1 -w 2 8.8.8.8
```

## Description

### Backend Summary

| Feature                    | `rootless-internal`                                               | `rootful`                                                              |
| -------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Isolated execution         | Yes                                                               | Yes                                                                    |
| DNS override               | Yes                                                               | Yes                                                                    |
| `/etc/hosts` override      | Yes                                                               | Yes                                                                    |
| Outbound TCP               | Yes                                                               | Yes                                                                    |
| UDP relay                  | Yes                                                               | Yes                                                                    |
| Proxy support              | Yes, via parent-side relay engine                                 | Yes, via transparent interception path                                 |
| Transparent proxy / TPROXY | No                                                                | Yes                                                                    |
| `--iface`                  | No                                                                | Yes                                                                    |
| Packet capture             | Optional, with `child`, `egress`, `wire-egress`, and `both` views | Optional, with `child`, `egress`, `wire-egress`, and `both` views      |
| Status                     | Default and recommended path                                      | Advanced fallback for features that still require host-side networking |

Use `rootless-internal` by default. It is the main path for isolated execution, DNS control, proxying, packet capture, `ping`, and `traceroute` without host-wide rootful setup.

Use `--root` when you specifically need host-integrated behavior that the rootless path does not expose yet, including:

- transparent proxying
- interface-forced direct egress with `--iface`
- broader raw-ICMP behavior than the current rootless relay engine implements

### Capture Modes

`childflow` is intended to capture only the target command tree's traffic, not unrelated host traffic.

The default `child` mode keeps the isolated child-side view.

- `egress`
  synthetic egress-oriented view on both backends
- `wire-egress`
  real host egress capture on both backends
- `both`
  writes sibling `.child.pcapng` and `.egress.pcapng` files

Generated `pcapng` files also embed metadata describing the capture view, backend, kind, and interface.

For the fuller comparison of current capture points and the planned `child` / `egress` / `wire-egress` / `both` capture-point direction, see [docs/technical-details.md](docs/technical-details.md).


## License

MIT. See [LICENSE](LICENSE).
