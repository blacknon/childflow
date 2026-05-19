use std::io::{self, Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

use super::protocol::{
    negotiate_http_connect, negotiate_socks5_connect, normalize_socket_addr,
    render_basic_proxy_auth, render_target_authority,
};
use super::ProxyAuth;

struct ScriptedStream {
    reader: Cursor<Vec<u8>>,
    writes: Vec<u8>,
    flushes: usize,
}

impl ScriptedStream {
    fn new(chunks: &[&[u8]]) -> Self {
        let mut bytes = Vec::new();
        for chunk in chunks {
            bytes.extend_from_slice(chunk);
        }
        Self {
            reader: Cursor::new(bytes),
            writes: Vec::new(),
            flushes: 0,
        }
    }
}

impl Read for ScriptedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

#[test]
fn render_target_authority_brackets_ipv6() {
    let target = SocketAddr::V6(SocketAddrV6::new(
        "2001:db8::10".parse::<Ipv6Addr>().unwrap(),
        443,
        0,
        0,
    ));
    assert_eq!(render_target_authority(target), "[2001:db8::10]:443");
}

#[test]
fn normalize_socket_addr_converts_ipv4_mapped_ipv6() {
    let mapped = SocketAddr::V6(SocketAddrV6::new(
        Ipv4Addr::new(192, 0, 2, 45).to_ipv6_mapped(),
        8443,
        0,
        0,
    ));

    assert_eq!(
        normalize_socket_addr(mapped),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 45)), 8443)
    );
}

#[test]
fn render_basic_proxy_auth_encodes_user_and_password() {
    let auth = ProxyAuth {
        username: "alice".into(),
        password: "s3cret".into(),
    };

    assert_eq!(render_basic_proxy_auth(&auth), "YWxpY2U6czNjcmV0");
}

#[test]
fn http_connect_includes_proxy_authorization_header() {
    let mut stream = ScriptedStream::new(&[b"HTTP/1.1 200 Connection Established\r\n\r\n"]);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 443);
    let auth = ProxyAuth {
        username: "demo".into(),
        password: "pass".into(),
    };

    negotiate_http_connect(&mut stream, target, Some(&auth)).unwrap();

    let written = String::from_utf8(stream.writes).unwrap();
    assert!(written.contains("CONNECT 198.51.100.10:443 HTTP/1.1"));
    assert!(written.contains("Proxy-Authorization: Basic ZGVtbzpwYXNz\r\n"));
    assert_eq!(stream.flushes, 1);
}

#[test]
fn socks5_connect_performs_username_password_authentication() {
    let mut stream = ScriptedStream::new(&[
        &[0x05, 0x02],
        &[0x01, 0x00],
        &[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90],
    ]);
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 8080);
    let auth = ProxyAuth {
        username: "demo".into(),
        password: "pass".into(),
    };

    negotiate_socks5_connect(&mut stream, target, Some(&auth)).unwrap();

    assert!(stream.writes.starts_with(&[0x05, 0x02, 0x00, 0x02]));
    assert!(stream.writes.windows(2).any(|w| w == [0x01, 0x04]));
    assert!(stream.writes.windows(b"demo".len()).any(|w| w == b"demo"));
    assert!(stream.writes.windows(b"pass".len()).any(|w| w == b"pass"));
    assert!(stream
        .writes
        .ends_with(&[0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x1f, 0x90]));
}
