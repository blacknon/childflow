use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::ProxyStream;

pub(super) fn relay_bidirectional(left: &mut TcpStream, right: &mut ProxyStream) -> Result<()> {
    left.set_nonblocking(true)
        .context("failed to set inbound stream nonblocking")?;
    right
        .set_nonblocking(true)
        .context("failed to set upstream proxy stream nonblocking")?;

    let mut left_to_right = Vec::new();
    let mut right_to_left = Vec::new();
    let mut left_open = true;
    let mut right_open = true;

    while left_open || right_open || !left_to_right.is_empty() || !right_to_left.is_empty() {
        let mut progressed = false;

        if left_open && left_to_right.is_empty() {
            let mut buf = [0_u8; 16 * 1024];
            match left.read(&mut buf) {
                Ok(0) => {
                    left_open = false;
                    let _ = right.shutdown_write();
                    progressed = true;
                }
                Ok(n) => {
                    left_to_right.extend_from_slice(&buf[..n]);
                    progressed = true;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => return Err(err).context("failed to read from inbound stream"),
            }
        }

        if !left_to_right.is_empty() {
            match right.write(&left_to_right) {
                Ok(0) => bail!("upstream proxy stream closed while sending request"),
                Ok(n) => {
                    left_to_right.drain(..n);
                    progressed = true;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => return Err(err).context("failed to write to upstream proxy stream"),
            }
        }

        if right_open && right_to_left.is_empty() {
            let mut buf = [0_u8; 16 * 1024];
            match right.read(&mut buf) {
                Ok(0) => {
                    right_open = false;
                    let _ = left.shutdown(Shutdown::Write);
                    progressed = true;
                }
                Ok(n) => {
                    right_to_left.extend_from_slice(&buf[..n]);
                    progressed = true;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => return Err(err).context("failed to read from upstream proxy stream"),
            }
        }

        if !right_to_left.is_empty() {
            match left.write(&right_to_left) {
                Ok(0) => bail!("inbound stream closed while returning response"),
                Ok(n) => {
                    right_to_left.drain(..n);
                    progressed = true;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => return Err(err).context("failed to write back to inbound stream"),
            }
        }

        if !progressed {
            thread::sleep(Duration::from_millis(10));
        }
    }

    let _ = left.shutdown(Shutdown::Both);
    Ok(())
}
