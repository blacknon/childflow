childflow
===

<p align="center">
<img src="./img/childflow.gif" width="720" />
</p>

childflow is a per-command-tree network sandbox for Linux.
Run one command and its child processes in an isolated network context, control DNS / hosts / proxy behavior, apply outbound policy, and capture only that tree's traffic.

## About

`childflow` runs one command tree in an isolated network context and applies DNS, hosts, proxy, sandbox, policy, and capture controls only to that tree.

This is useful for tools that do not honor proxy environment variables consistently. `childflow` forces the proxy at the command tree's network path instead of relying on `HTTP_PROXY`, `HTTPS_PROXY`, or `LD_PRELOAD`-style interception.

It has two Linux backends: `rootless-internal` for the default day-to-day path, and `rootful` via `--root` when you need host-integrated behavior such as `--iface` or transparent interception.

- affects only the target command tree, not the whole host session
- can force DNS, `/etc/hosts`, proxying, sandbox policy, and packet capture per command tree
- can force proxying without depending on `HTTP_PROXY`, `HTTPS_PROXY`, or `LD_PRELOAD` tricks
- can apply allow / deny CIDR policy and default-deny rules to outbound traffic
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
Run one command tree inside a controlled network sandbox

Usage: childflow [OPTIONS] [COMMAND]...

Arguments:
  [COMMAND]...  Command to execute

Options:
  -c, --capture <OUTPUT>
          Write only the target command tree's traffic as pcapng
  -C, --capture-point <OUTPUT_VIEW>
          Select which capture point or view `--capture` should write. `child` is the current stable view [default: child] [possible values: child, egress, wire-egress, both]
      --root
          Use the rootful backend. Without this flag, childflow uses the default rootless backend
      --doctor
          Diagnose whether the current host is ready for the selected backend
  -d, --dns <DNS>
          Force DNS traffic for the child tree to this IPv4 or IPv6 resolver
      --hosts-file <HOSTS_FILE>
          Bind-mount an `/etc/hosts`-format file over the child's `/etc/hosts` so those entries are consulted first during name resolution
  -p, --proxy <PROXY>
          Configure an upstream proxy URI, for example http://127.0.0.1:8080, https://proxy.example.com:443, or socks5://host.docker.internal:10080. `--root` uses transparent interception, while the default rootless backend relays outbound TCP through the selected proxy from the parent-side engine
  -U, --proxy-user <PROXY_USER>
          Username for upstream proxy authentication
  -P, --proxy-password <PROXY_PASSWORD>
          Password for upstream proxy authentication
      --proxy-insecure
          Ignore certificate trust errors for https:// upstream proxies while still validating the hostname
      --summary
          Print a post-run summary to stderr
      --offline
          Block all outbound networking for the child tree, including DNS forwarding
      --block-private
          Block child-tree traffic to private, loopback, link-local, and ULA-style destinations
      --block-metadata
          Block common cloud metadata endpoints such as 169.254.169.254
      --default-policy <DEFAULT_POLICY>
          Choose whether unmatched outbound destinations are allowed or denied [default: allow] [possible values: allow, deny]
      --allow-cidr <ALLOW_CIDRS>
          Allow outbound destinations that fall within this IPv4 or IPv6 CIDR
      --deny-cidr <DENY_CIDRS>
          Deny outbound destinations that fall within this IPv4 or IPv6 CIDR
      --proxy-only
          Require outbound traffic to use the configured upstream proxy path
      --fail-on-leak
          Exit non-zero if childflow blocks traffic that the child process did not treat as fatal
  -i, --iface <IFACE>
          Force the host-side egress interface for the child's direct traffic
  -h, --help
          Print help
  -V, --version
          Print version
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
childflow --offline -- cargo test
```

```bash
childflow --block-metadata -- ./my-client
```

```bash
childflow --block-private -- curl https://example.com
```

```bash
childflow \
  --default-policy deny \
  --allow-cidr 203.0.113.10/32 \
  -- curl http://203.0.113.10/
```

```bash
childflow --deny-cidr 10.0.0.0/8 -- ./scanner
```

```bash
childflow \
  --proxy-only \
  -p http://127.0.0.1:8080 \
  -- curl https://example.com
```

```bash
childflow \
  --proxy-only \
  --fail-on-leak \
  -p http://127.0.0.1:8080 \
  -- ./client
```

```bash
childflow -p http://127.0.0.1:8080 -- curl https://example.com
```

```bash
childflow -p http://127.0.0.1:8080 -- gobuster dir -u http://target.local/ -w ./wordlist.txt
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
| Policy controls            | Yes                                                               | Yes                                                                    |
| `--fail-on-leak`           | Yes                                                               | Not yet                                                                |
| Transparent proxy / TPROXY | No                                                                | Yes                                                                    |
| `--iface`                  | No                                                                | Yes                                                                    |
| Packet capture             | Optional, with `child`, `egress`, `wire-egress`, and `both` views | Optional, with `child`, `egress`, `wire-egress`, and `both` views      |
| Status                     | Default and recommended path                                      | Advanced fallback for features that still require host-side networking |

Use `rootless-internal` by default. It is the main path for isolated execution, DNS control, proxying, packet capture, `ping`, and `traceroute` without host-wide rootful setup.

Use `--root` when you specifically need host-integrated behavior that the rootless path does not expose yet, including:

- transparent proxying
- interface-forced direct egress with `--iface`
- broader raw-ICMP behavior than the current rootless relay engine implements

### Policy Controls

`childflow` can treat the command tree as a small outbound policy domain.

- `--offline`
  deny all outbound traffic and disable DNS forwarding
- `--block-private`
  deny private, loopback, link-local, and ULA-style destinations
- `--block-metadata`
  deny common cloud metadata endpoints
- `--default-policy deny`
  deny destinations unless they match an explicit allow rule
- `--allow-cidr`
  allow IPv4 or IPv6 CIDRs
- `--deny-cidr`
  deny IPv4 or IPv6 CIDRs
- `--proxy-only`
  require outbound traffic to use the configured proxy path
- `--fail-on-leak`
  return non-zero when childflow blocks traffic but the child process still exits `0`

Current notes:

- `--proxy-only` is primarily a TCP-focused control; in the rootless backend, direct DNS / UDP / ICMP traffic is also blocked rather than relayed
- `--fail-on-leak` is currently supported only by `rootless-internal`

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
