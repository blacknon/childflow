use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::Ipv4Addr;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use super::temp::unique_temp_profile_dir;

pub(crate) struct LocalDnsServer {
    child: Child,
    queries: Receiver<String>,
}

impl LocalDnsServer {
    pub(crate) fn spawn(bind_ip: &str, expected_qname: &str, answer_ip: Ipv4Addr) -> Result<Self> {
        let script_path = unique_temp_profile_dir("rootless-local-dns").join("dns_server.py");
        fs::write(&script_path, LOCAL_DNS_SERVER_PY)
            .with_context(|| format!("failed to write {}", script_path.display()))?;

        let mut command = if unsafe { nix::libc::geteuid() } == 0 {
            Command::new("python3")
        } else {
            let mut command = Command::new("sudo");
            command.arg("-n").arg("python3");
            command
        };

        let mut child = command
            .arg(script_path.to_str().unwrap())
            .arg(bind_ip)
            .arg(expected_qname)
            .arg(answer_ip.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to start local DNS server helper")?;

        let stdout_pipe = child
            .stdout
            .take()
            .context("local DNS server did not expose stdout")?;
        let mut stdout_reader = BufReader::new(stdout_pipe);
        let mut ready_line = String::new();
        let n = stdout_reader
            .read_line(&mut ready_line)
            .context("failed to read local DNS server readiness signal")?;
        if n == 0 {
            let mut stderr = String::new();
            if let Some(stderr_pipe) = child.stderr.as_mut() {
                let _ = stderr_pipe.read_to_string(&mut stderr);
            }
            bail!(
                "local DNS server exited before readiness; stderr: {}",
                stderr.trim()
            );
        }

        if ready_line.trim() != "READY" {
            bail!(
                "unexpected local DNS server readiness line: {}",
                ready_line.trim()
            );
        }

        let (query_tx, query_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            loop {
                line.clear();
                match stdout_reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if let Some(query) = line.trim().strip_prefix("QUERY ") {
                            let _ = query_tx.send(query.to_string());
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            child,
            queries: query_rx,
        })
    }

    pub(crate) fn recv_query_timeout(&self, timeout: Duration) -> Result<String, RecvTimeoutError> {
        self.queries.recv_timeout(timeout)
    }
}

impl Drop for LocalDnsServer {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
            Err(_) => {}
        }
    }
}

pub(crate) fn unique_loopback_dns_ip() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let a = 20 + ((nanos & 0x7f) as u8);
    let b = 1 + (((nanos >> 8) & 0xfe) as u8);
    let c = 1 + (((nanos >> 16) & 0xfe) as u8);
    format!("127.{a}.{b}.{c}")
}

const LOCAL_DNS_SERVER_PY: &str = r#"#!/usr/bin/env python3
import ipaddress
import socket
import struct
import sys

bind_ip, expected_qname, answer_ip = sys.argv[1], sys.argv[2].rstrip(".").lower(), sys.argv[3]
answer_bytes = ipaddress.IPv4Address(answer_ip).packed

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((bind_ip, 53))
print("READY", flush=True)

data, addr = sock.recvfrom(2048)
if len(data) < 12:
    sys.exit(1)

qid = data[:2]
qdcount = struct.unpack("!H", data[4:6])[0]
if qdcount != 1:
    sys.exit(1)

offset = 12
labels = []
while True:
    if offset >= len(data):
        sys.exit(1)
    length = data[offset]
    offset += 1
    if length == 0:
        break
    labels.append(data[offset:offset + length].decode("ascii"))
    offset += length

question_end = offset + 4
question = data[12:question_end]
qname = ".".join(labels).rstrip(".").lower()
qtype = struct.unpack("!H", data[offset:offset + 2])[0]
print(f"QUERY {qname}", flush=True)

flags = 0x8180
answers = b""
ancount = 0
if qname == expected_qname and qtype == 1:
    answers = struct.pack("!HHHLH4s", 0xC00C, 1, 1, 30, 4, answer_bytes)
    ancount = 1

header = qid + struct.pack("!HHHHH", flags, qdcount, ancount, 0, 0)
sock.sendto(header + question + answers, addr)
"#;
