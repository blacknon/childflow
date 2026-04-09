use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};

pub struct DnsHandle {
    stop: Arc<AtomicBool>,
    joins: Vec<JoinHandle<Result<()>>>,
}

impl DnsHandle {
    pub fn start(bind_ip: Ipv4Addr, upstream_ip: Ipv4Addr) -> Result<Self> {
        let bind_addr = SocketAddrV4::new(bind_ip, 53);
        let upstream_addr = SocketAddrV4::new(upstream_ip, 53);

        let udp = UdpSocket::bind(bind_addr)
            .with_context(|| format!("failed to bind UDP DNS forwarder on {bind_addr}"))?;
        udp.set_read_timeout(Some(Duration::from_millis(250)))
            .context("failed to set UDP DNS forwarder read timeout")?;

        let tcp = TcpListener::bind(bind_addr)
            .with_context(|| format!("failed to bind TCP DNS forwarder on {bind_addr}"))?;
        tcp.set_nonblocking(true)
            .context("failed to set TCP DNS forwarder nonblocking")?;

        let stop = Arc::new(AtomicBool::new(false));

        let udp_stop = Arc::clone(&stop);
        let udp_join = thread::spawn(move || udp_loop(udp, upstream_addr, udp_stop));

        let tcp_stop = Arc::clone(&stop);
        let tcp_join = thread::spawn(move || tcp_loop(tcp, upstream_addr, tcp_stop));

        Ok(Self {
            stop,
            joins: vec![udp_join, tcp_join],
        })
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        while let Some(join) = self.joins.pop() {
            let _ = join.join();
        }
    }
}

impl Drop for DnsHandle {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn udp_loop(socket: UdpSocket, upstream_addr: SocketAddrV4, stop: Arc<AtomicBool>) -> Result<()> {
    let mut buf = [0_u8; 4096];

    while !stop.load(Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let SocketAddr::V4(peer) = peer else {
                    continue;
                };

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

fn forward_udp_query(query: &[u8], upstream_addr: SocketAddrV4) -> Result<Vec<u8>> {
    let upstream = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
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

fn tcp_loop(
    listener: TcpListener,
    upstream_addr: SocketAddrV4,
    stop: Arc<AtomicBool>,
) -> Result<()> {
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

fn handle_tcp_connection(mut client: TcpStream, upstream_addr: SocketAddrV4) -> Result<()> {
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

        let actual = forward_udp_query(&expected_query, upstream_addr).unwrap();
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
}
