use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;

use super::ProxyAuth;

pub(super) fn negotiate_http_connect<S: Read + Write>(
    stream: &mut S,
    target: SocketAddr,
    auth: Option<&ProxyAuth>,
) -> Result<()> {
    let authority = render_target_authority(target);
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n",
    );
    if let Some(auth) = auth {
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&render_basic_proxy_auth(auth));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .context("failed to write HTTP CONNECT request")?;
    stream
        .flush()
        .context("failed to flush HTTP CONNECT request")?;

    let response = read_headers(stream)?;
    let first_line = response.lines().next().unwrap_or_default();
    if !(first_line.starts_with("HTTP/1.1 200") || first_line.starts_with("HTTP/1.0 200")) {
        bail!("upstream HTTP proxy rejected CONNECT: {first_line}");
    }

    Ok(())
}

pub(super) fn negotiate_socks5_connect<S: Read + Write>(
    stream: &mut S,
    target: SocketAddr,
    auth: Option<&ProxyAuth>,
) -> Result<()> {
    let methods = if auth.is_some() {
        vec![0x00, 0x02]
    } else {
        vec![0x00]
    };
    let mut greeting = vec![0x05, methods.len() as u8];
    greeting.extend_from_slice(&methods);
    stream
        .write_all(&greeting)
        .context("failed to write SOCKS5 greeting")?;
    let mut method_reply = [0_u8; 2];
    stream
        .read_exact(&mut method_reply)
        .context("failed to read SOCKS5 method reply")?;
    if method_reply[0] != 0x05 {
        bail!(
            "unexpected SOCKS5 greeting reply version 0x{:02x}",
            method_reply[0]
        );
    }
    match method_reply[1] {
        0x00 => {}
        0x02 => authenticate_socks5(stream, auth)?,
        0xff => bail!("SOCKS5 proxy did not accept any offered authentication method"),
        other => bail!("SOCKS5 proxy selected unsupported authentication method 0x{other:02x}"),
    }

    let request = match target.ip() {
        IpAddr::V4(ip) => [
            vec![0x05, 0x01, 0x00, 0x01],
            ip.octets().to_vec(),
            target.port().to_be_bytes().to_vec(),
        ]
        .concat(),
        IpAddr::V6(ip) => [
            vec![0x05, 0x01, 0x00, 0x04],
            ip.octets().to_vec(),
            target.port().to_be_bytes().to_vec(),
        ]
        .concat(),
    };
    stream
        .write_all(&request)
        .context("failed to write SOCKS5 CONNECT request")?;

    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .context("failed to read SOCKS5 CONNECT reply header")?;
    if header[1] != 0x00 {
        bail!("SOCKS5 CONNECT failed with reply code 0x{:02x}", header[1]);
    }

    match header[3] {
        0x01 => {
            let mut rest = [0_u8; 6];
            stream
                .read_exact(&mut rest)
                .context("failed to read SOCKS5 IPv4 reply tail")?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream
                .read_exact(&mut len)
                .context("failed to read SOCKS5 domain length")?;
            let mut rest = vec![0_u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .context("failed to read SOCKS5 domain reply tail")?;
        }
        0x04 => {
            let mut rest = [0_u8; 18];
            stream
                .read_exact(&mut rest)
                .context("failed to read SOCKS5 IPv6 reply tail")?;
        }
        other => bail!("unsupported SOCKS5 ATYP in reply: 0x{other:02x}"),
    }

    Ok(())
}

fn authenticate_socks5<S: Read + Write>(stream: &mut S, auth: Option<&ProxyAuth>) -> Result<()> {
    let auth =
        auth.ok_or_else(|| anyhow!("SOCKS5 proxy requested username/password authentication"))?;
    let username = auth.username.as_bytes();
    let password = auth.password.as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        bail!("SOCKS5 proxy credentials must be at most 255 bytes each");
    }

    let mut request = vec![0x01, username.len() as u8];
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream
        .write_all(&request)
        .context("failed to write SOCKS5 username/password authentication request")?;

    let mut reply = [0_u8; 2];
    stream
        .read_exact(&mut reply)
        .context("failed to read SOCKS5 authentication reply")?;
    if reply != [0x01, 0x00] {
        bail!("SOCKS5 authentication failed");
    }

    Ok(())
}

pub(super) fn render_basic_proxy_auth(auth: &ProxyAuth) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", auth.username, auth.password))
}

pub(super) fn render_target_authority(target: SocketAddr) -> String {
    match target {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

pub(super) fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(ipv4) => SocketAddr::new(IpAddr::V4(ipv4), v6.port()),
            None => SocketAddr::V6(v6),
        },
        SocketAddr::V4(_) => addr,
    }
}

fn read_headers<S: Read>(stream: &mut S) -> Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 256];
    loop {
        let n = stream
            .read(&mut chunk)
            .context("failed to read proxy response")?;
        if n == 0 {
            bail!("proxy closed connection while reading response headers");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            bail!("proxy response headers are too large");
        }
    }

    String::from_utf8(buf).map_err(|err| anyhow!("proxy response is not valid UTF-8: {err}"))
}
