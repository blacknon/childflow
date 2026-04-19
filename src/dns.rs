// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener,
    TcpStream, UdpSocket,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::network::NetworkBackend;

pub struct DnsPlan {
    resolv_guard: Option<TempFileGuard>,
    rootful_upstream: Option<IpAddr>,
    rootless_upstream: Option<IpAddr>,
}

impl DnsPlan {
    pub fn prepare(
        run_id: &str,
        backend: NetworkBackend,
        dns: Option<IpAddr>,
        inherited_dns_ipv4: Ipv4Addr,
        inherited_dns_ipv6: Ipv6Addr,
    ) -> Result<Self> {
        match backend {
            NetworkBackend::Rootful => {
                prepare_rootful_dns_plan(run_id, dns, inherited_dns_ipv4, inherited_dns_ipv6)
            }
            NetworkBackend::RootlessInternal => {
                prepare_rootless_dns_plan(run_id, dns, inherited_dns_ipv4, inherited_dns_ipv6)
            }
        }
    }

    pub fn resolv_conf_path(&self) -> Option<&Path> {
        self.resolv_guard.as_ref().map(|guard| guard.path.as_path())
    }

    pub fn start_forwarder(
        &self,
        bind_ipv4: Ipv4Addr,
        bind_ipv6: Ipv6Addr,
    ) -> Result<Option<DnsHandle>> {
        self.rootful_upstream
            .map(|upstream| DnsHandle::start(bind_ipv4, bind_ipv6, upstream))
            .transpose()
    }

    pub fn rootless_upstream(&self) -> Option<IpAddr> {
        self.rootless_upstream
    }
}

pub struct DnsHandle {
    stop: Arc<AtomicBool>,
    joins: Vec<JoinHandle<Result<()>>>,
}

impl DnsHandle {
    pub fn start(bind_ipv4: Ipv4Addr, bind_ipv6: Ipv6Addr, upstream_ip: IpAddr) -> Result<Self> {
        let listen_addrs = [
            SocketAddr::V4(SocketAddrV4::new(bind_ipv4, 53)),
            SocketAddr::V6(SocketAddrV6::new(bind_ipv6, 53, 0, 0)),
        ];
        let upstream_addr = SocketAddr::new(upstream_ip, 53);
        let stop = Arc::new(AtomicBool::new(false));
        let mut joins = Vec::new();

        for bind_addr in listen_addrs {
            let udp = UdpSocket::bind(bind_addr)
                .with_context(|| format!("failed to bind UDP DNS forwarder on {bind_addr}"))?;
            udp.set_read_timeout(Some(Duration::from_millis(250)))
                .context("failed to set UDP DNS forwarder read timeout")?;

            let tcp = TcpListener::bind(bind_addr)
                .with_context(|| format!("failed to bind TCP DNS forwarder on {bind_addr}"))?;
            tcp.set_nonblocking(true)
                .context("failed to set TCP DNS forwarder nonblocking")?;

            let udp_stop = Arc::clone(&stop);
            joins.push(thread::spawn(move || {
                udp_loop(udp, upstream_addr, udp_stop)
            }));

            let tcp_stop = Arc::clone(&stop);
            joins.push(thread::spawn(move || {
                tcp_loop(tcp, upstream_addr, tcp_stop)
            }));
        }

        Ok(Self { stop, joins })
    }

    fn stop_and_join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        let mut failures = Vec::new();
        while let Some(join) = self.joins.pop() {
            match join.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    failures.push(format!("{err:#}"));
                }
                Err(_) => failures.push("DNS forwarder thread panicked".to_string()),
            }
        }
        if failures.is_empty() {
            return Ok(());
        }
        anyhow::bail!(failures.join("\n"));
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.stop_and_join()
    }
}

impl Drop for DnsHandle {
    fn drop(&mut self) {
        if let Err(err) = self.stop_and_join() {
            crate::util::warn(format!("DNS forwarder stopped with an error: {err:#}"));
        }
    }
}

fn udp_loop(socket: UdpSocket, upstream_addr: SocketAddr, stop: Arc<AtomicBool>) -> Result<()> {
    let mut buf = [0_u8; 4096];

    while !stop.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let response = forward_udp_query(&buf[..n], upstream_addr)?;
                socket
                    .send_to(&response, peer)
                    .with_context(|| format!("failed to return UDP DNS response to {peer}"))?;
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => return Err(err).context("UDP DNS forwarder recv_from failed"),
        }
    }

    Ok(())
}

fn forward_udp_query(query: &[u8], upstream_addr: SocketAddr) -> Result<Vec<u8>> {
    let bind_addr = match upstream_addr {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
    };
    let upstream = UdpSocket::bind(bind_addr)
        .context("failed to bind UDP upstream socket for DNS forwarder")?;
    upstream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("failed to set UDP upstream read timeout")?;
    upstream
        .connect(upstream_addr)
        .with_context(|| format!("failed to connect UDP DNS upstream {upstream_addr}"))?;
    upstream
        .send(query)
        .with_context(|| format!("failed to send UDP DNS query to {upstream_addr}"))?;

    let mut buf = [0_u8; 4096];
    let n = upstream
        .recv(&mut buf)
        .with_context(|| format!("failed to receive UDP DNS response from {upstream_addr}"))?;
    Ok(buf[..n].to_vec())
}

fn tcp_loop(listener: TcpListener, upstream_addr: SocketAddr, stop: Arc<AtomicBool>) -> Result<()> {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((client, _)) => {
                thread::spawn(move || {
                    let _ = handle_tcp_connection(client, upstream_addr);
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(err).context("TCP DNS forwarder accept failed"),
        }
    }

    Ok(())
}

fn handle_tcp_connection(mut client: TcpStream, upstream_addr: SocketAddr) -> Result<()> {
    let mut upstream = TcpStream::connect(upstream_addr)
        .with_context(|| format!("failed to connect TCP DNS upstream {upstream_addr}"))?;
    relay_bidirectional(&mut client, &mut upstream)?;
    Ok(())
}

fn relay_bidirectional(left: &mut TcpStream, right: &mut TcpStream) -> Result<()> {
    let mut left_reader = left
        .try_clone()
        .context("failed to clone DNS client stream")?;
    let mut left_writer = left
        .try_clone()
        .context("failed to clone DNS client writer")?;
    let mut right_reader = right
        .try_clone()
        .context("failed to clone DNS upstream stream")?;
    let mut right_writer = right
        .try_clone()
        .context("failed to clone DNS upstream writer")?;

    let left_to_right = thread::spawn(move || -> std::io::Result<u64> {
        let copied = std::io::copy(&mut left_reader, &mut right_writer)?;
        let _ = right_writer.shutdown(Shutdown::Write);
        Ok(copied)
    });

    let right_to_left = thread::spawn(move || -> std::io::Result<u64> {
        let copied = std::io::copy(&mut right_reader, &mut left_writer)?;
        let _ = left_writer.shutdown(Shutdown::Write);
        Ok(copied)
    });

    let _ = left_to_right
        .join()
        .map_err(|_| anyhow::anyhow!("DNS TCP client->upstream relay thread panicked"))?
        .context("DNS TCP client->upstream relay failed")?;
    let _ = right_to_left
        .join()
        .map_err(|_| anyhow::anyhow!("DNS TCP upstream->client relay thread panicked"))?
        .context("DNS TCP upstream->client relay failed")?;

    Ok(())
}

fn maybe_write_resolv_conf(run_id: &str, content: &str) -> Result<Option<TempFileGuard>> {
    let path = PathBuf::from(format!("/tmp/childflow-resolv-{run_id}.conf"));
    std::fs::write(&path, content).with_context(|| {
        format!(
            "failed to write temporary resolv.conf at {}",
            path.display()
        )
    })?;

    Ok(Some(TempFileGuard { path }))
}

fn prepare_rootful_dns_plan(
    run_id: &str,
    dns: Option<IpAddr>,
    inherited_dns_ipv4: Ipv4Addr,
    inherited_dns_ipv6: Ipv6Addr,
) -> Result<DnsPlan> {
    if let Some(dns) = dns {
        let content = format!("nameserver {dns}\noptions timeout:1 attempts:1\n");
        return Ok(DnsPlan {
            resolv_guard: maybe_write_resolv_conf(run_id, &content)?,
            rootful_upstream: None,
            rootless_upstream: None,
        });
    }

    let host_resolv =
        std::fs::read_to_string("/etc/resolv.conf").context("failed to read /etc/resolv.conf")?;
    let inherited =
        build_inherited_dns_config(&host_resolv, inherited_dns_ipv4, inherited_dns_ipv6)?;

    Ok(DnsPlan {
        resolv_guard: maybe_write_resolv_conf(run_id, &inherited.resolv_conf)?,
        rootful_upstream: Some(inherited.upstream),
        rootless_upstream: None,
    })
}

fn prepare_rootless_dns_plan(
    run_id: &str,
    dns: Option<IpAddr>,
    gateway_ipv4: Ipv4Addr,
    gateway_ipv6: Ipv6Addr,
) -> Result<DnsPlan> {
    let (upstream, resolv_conf) = if let Some(dns) = dns {
        (
            dns,
            render_gateway_resolv_conf(&[], gateway_ipv4, gateway_ipv6, true),
        )
    } else {
        let host_resolv = std::fs::read_to_string("/etc/resolv.conf")
            .context("failed to read /etc/resolv.conf")?;
        let inherited = build_inherited_dns_config(&host_resolv, gateway_ipv4, gateway_ipv6)?;
        (
            inherited.upstream,
            render_gateway_resolv_conf(
                &inherited.preserved_lines,
                gateway_ipv4,
                gateway_ipv6,
                false,
            ),
        )
    };

    Ok(DnsPlan {
        resolv_guard: maybe_write_resolv_conf(run_id, &resolv_conf)?,
        rootful_upstream: None,
        rootless_upstream: Some(upstream),
    })
}

fn build_inherited_dns_config(
    host_resolv: &str,
    inherited_dns_ipv4: Ipv4Addr,
    inherited_dns_ipv6: Ipv6Addr,
) -> Result<InheritedDnsConfig> {
    let mut preserved_lines = Vec::new();
    let mut upstream = None;

    for line in host_resolv.lines() {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let addr = rest.trim();
            if let Ok(ip) = addr.parse::<IpAddr>() {
                if upstream.is_none() {
                    upstream = Some(ip);
                }
            }
            continue;
        }

        if trimmed.starts_with("search ")
            || trimmed.starts_with("domain ")
            || trimmed.starts_with("options ")
        {
            preserved_lines.push(trimmed.to_string());
        }
    }

    let upstream = upstream
        .ok_or_else(|| anyhow::anyhow!("no usable nameserver found in /etc/resolv.conf"))?;

    Ok(InheritedDnsConfig {
        upstream,
        resolv_conf: render_gateway_resolv_conf(
            &preserved_lines,
            inherited_dns_ipv4,
            inherited_dns_ipv6,
            false,
        ),
        preserved_lines,
    })
}

fn render_gateway_resolv_conf(
    preserved_lines: &[String],
    gateway_ipv4: Ipv4Addr,
    gateway_ipv6: Ipv6Addr,
    force_default_options: bool,
) -> String {
    let mut output = preserved_lines.to_vec();
    output.push(format!("nameserver {gateway_ipv4}"));
    output.push(format!("nameserver {gateway_ipv6}"));
    if force_default_options || !output.iter().any(|line| line.starts_with("options ")) {
        output.push("options timeout:1 attempts:1".to_string());
    }
    format!("{}\n", output.join("\n"))
}

#[derive(Debug)]
struct InheritedDnsConfig {
    upstream: IpAddr,
    resolv_conf: String,
    preserved_lines: Vec<String>,
}

struct TempFileGuard {
    path: PathBuf,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc;

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();

        let join = thread::spawn(move || {
            let accepted = listener.accept().unwrap().0;
            tx.send(accepted).unwrap();
        });

        let client = TcpStream::connect(addr).unwrap();
        let server = rx.recv().unwrap();
        join.join().unwrap();

        (client, server)
    }

    #[test]
    fn forward_udp_query_relays_response_from_upstream() {
        let upstream = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_addr = match upstream.local_addr().unwrap() {
            SocketAddr::V4(addr) => addr,
            SocketAddr::V6(_) => panic!("expected an IPv4 upstream socket"),
        };

        let expected_query = b"\x12\x34dns-query".to_vec();
        let expected_response = b"\x12\x34dns-response".to_vec();

        let join = thread::spawn({
            let expected_query = expected_query.clone();
            let expected_response = expected_response.clone();
            move || {
                let mut buf = [0_u8; 64];
                let (n, peer) = upstream.recv_from(&mut buf).unwrap();
                assert_eq!(&buf[..n], expected_query.as_slice());
                upstream.send_to(&expected_response, peer).unwrap();
            }
        });

        let actual = forward_udp_query(&expected_query, SocketAddr::V4(upstream_addr)).unwrap();
        join.join().unwrap();

        assert_eq!(actual, expected_response);
    }

    #[test]
    fn relay_bidirectional_copies_data_in_both_directions() {
        let (mut left_peer, mut left_relay) = tcp_pair();
        let (mut right_peer, mut right_relay) = tcp_pair();

        let request = b"dns request payload".to_vec();
        let response = b"dns response payload".to_vec();

        let upstream_join = thread::spawn({
            let request = request.clone();
            let response = response.clone();
            move || {
                let mut received = vec![0_u8; request.len()];
                right_peer.read_exact(&mut received).unwrap();
                assert_eq!(received, request);

                right_peer.write_all(&response).unwrap();
                right_peer.shutdown(Shutdown::Write).unwrap();
            }
        });

        left_peer.write_all(&request).unwrap();
        left_peer.shutdown(Shutdown::Write).unwrap();

        relay_bidirectional(&mut left_relay, &mut right_relay).unwrap();
        upstream_join.join().unwrap();

        let mut received = Vec::new();
        left_peer.read_to_end(&mut received).unwrap();
        assert_eq!(received, response);
    }

    #[test]
    fn build_inherited_dns_config_rewrites_nameserver_and_preserves_options() {
        let host_resolv = "\
# Generated by test
nameserver 8.8.8.8
search example.internal
options edns0 trust-ad
";

        let config = build_inherited_dns_config(
            host_resolv,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv6Addr::new(0xfd42, 0, 0, 0, 0, 0, 0, 2),
        )
        .unwrap();

        assert_eq!(config.upstream, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(
            config.resolv_conf,
            "search example.internal\noptions edns0 trust-ad\nnameserver 10.0.0.2\nnameserver fd42::2\n"
        );
    }

    #[test]
    fn build_inherited_dns_config_adds_default_options_when_missing() {
        let host_resolv = "\
nameserver 2001:4860:4860::8888
domain example.internal
nameserver 1.1.1.1
";

        let config = build_inherited_dns_config(
            host_resolv,
            Ipv4Addr::new(172, 16, 0, 10),
            Ipv6Addr::new(0xfd42, 0x1234, 0x5678, 0, 0, 0, 0, 10),
        )
        .unwrap();

        assert_eq!(
            config.upstream,
            IpAddr::V6("2001:4860:4860::8888".parse().unwrap())
        );
        assert_eq!(
            config.resolv_conf,
            "domain example.internal\nnameserver 172.16.0.10\nnameserver fd42:1234:5678::a\noptions timeout:1 attempts:1\n"
        );
    }

    #[test]
    fn build_inherited_dns_config_rejects_missing_nameserver() {
        let host_resolv = "search example.internal\n";

        let err = build_inherited_dns_config(
            host_resolv,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv6Addr::new(0xfd42, 0, 0, 0, 0, 0, 0, 2),
        )
        .unwrap_err();
        assert!(err.to_string().contains("no usable nameserver found"));
    }

    #[test]
    fn render_gateway_resolv_conf_adds_default_options_for_explicit_rootless_dns() {
        let rendered = render_gateway_resolv_conf(
            &[],
            Ipv4Addr::new(10, 240, 1, 1),
            "fd42::1".parse().unwrap(),
            true,
        );

        assert_eq!(
            rendered,
            "nameserver 10.240.1.1\nnameserver fd42::1\noptions timeout:1 attempts:1\n"
        );
    }

    #[test]
    fn prepare_rootless_dns_plan_points_child_to_gateway_and_keeps_upstream() {
        let run_id = format!("unit-test-{}", std::process::id());
        let plan = prepare_rootless_dns_plan(
            &run_id,
            Some("1.1.1.1".parse().unwrap()),
            Ipv4Addr::new(10, 240, 1, 1),
            "fd42::1".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(plan.rootful_upstream, None);
        assert_eq!(plan.rootless_upstream(), Some("1.1.1.1".parse().unwrap()));

        let path = plan.resolv_conf_path().unwrap();
        let content = std::fs::read_to_string(path).unwrap();
        assert_eq!(
            content,
            "nameserver 10.240.1.1\nnameserver fd42::1\noptions timeout:1 attempts:1\n"
        );
    }
}
