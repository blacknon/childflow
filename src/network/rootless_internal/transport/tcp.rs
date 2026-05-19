// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::proxy::rootless_relay::{self, OutboundStream, ProxyUpstreamConfig};

use super::super::engine::{ConnectionCommand, RemoteEvent};
use super::super::state::FlowKey;

pub(crate) fn connect_remote(
    remote_addr: SocketAddr,
    proxy_upstream: Option<&ProxyUpstreamConfig>,
    event_tx: Sender<RemoteEvent>,
    key: FlowKey,
) -> Result<Sender<ConnectionCommand>> {
    let stream = if let Some(proxy_upstream) = proxy_upstream {
        rootless_relay::connect_via_proxy(proxy_upstream, remote_addr).with_context(|| {
            format!(
                "failed to connect to remote TCP destination {remote_addr} through the configured rootless upstream proxy"
            )
        })?
    } else {
        let stream = match remote_addr {
            SocketAddr::V4(addr) => {
                TcpStream::connect_timeout(&SocketAddr::V4(addr), Duration::from_secs(5))
            }
            SocketAddr::V6(addr) => {
                TcpStream::connect_timeout(&SocketAddr::V6(addr), Duration::from_secs(5))
            }
        }
        .with_context(|| format!("failed to connect to remote TCP destination {remote_addr}"))?;
        stream
            .set_nodelay(true)
            .context("failed to enable TCP_NODELAY for remote TCP socket")?;
        OutboundStream::Tcp(stream)
    };

    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .context("failed to configure the rootless outbound stream read timeout")?;

    let (command_tx, command_rx) = mpsc::channel();
    spawn_remote_worker(event_tx, key, stream, command_rx);
    Ok(command_tx)
}

fn spawn_remote_worker(
    event_tx: Sender<RemoteEvent>,
    key: FlowKey,
    mut stream: OutboundStream,
    command_rx: Receiver<ConnectionCommand>,
) {
    thread::spawn(move || {
        let mut buf = [0_u8; 8192];
        let mut write_closed = false;
        loop {
            match command_rx.recv_timeout(Duration::from_millis(10)) {
                Ok(ConnectionCommand::Write(payload)) => {
                    if stream.write_all(&payload).is_err() {
                        let _ = event_tx.send(RemoteEvent::TcpClosed { key: key.clone() });
                        break;
                    }
                }
                Ok(ConnectionCommand::ShutdownWrite) => {
                    write_closed = true;
                    let _ = stream.shutdown_write();
                }
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {}
            }

            match stream.read(&mut buf) {
                Ok(0) => {
                    let _ = event_tx.send(RemoteEvent::TcpClosed { key: key.clone() });
                    break;
                }
                Ok(n) => {
                    let _ = event_tx.send(RemoteEvent::TcpData {
                        key: key.clone(),
                        payload: buf[..n].to_vec(),
                    });
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
                    ) =>
                {
                    if write_closed {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                Err(_) => {
                    let _ = event_tx.send(RemoteEvent::TcpClosed { key: key.clone() });
                    break;
                }
            }
        }
    });
}
