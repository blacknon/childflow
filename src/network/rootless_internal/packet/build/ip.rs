use std::net::IpAddr;

use anyhow::{anyhow, bail, Context, Result};
use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, Ipv6Header};

use super::IpKind;

pub(super) fn build_ip_frame<F>(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    transport_proto: IpNumber,
    write_transport: F,
) -> Result<Vec<u8>>
where
    F: FnOnce(IpKind<'_>, &mut Vec<u8>) -> Result<()>,
{
    let eth = Ethernet2Header {
        source: src_mac,
        destination: dst_mac,
        ether_type: match (src_ip, dst_ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) => etherparse::EtherType::IPV4,
            (IpAddr::V6(_), IpAddr::V6(_)) => etherparse::EtherType::IPV6,
            _ => bail!("source and destination IP versions must match"),
        },
    };

    let mut payload = Vec::new();
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let ip = Ipv4Header::new(0, 64, transport_proto, src.octets(), dst.octets())
                .context("failed to create IPv4 header")?;
            write_transport(IpKind::V4(&ip), &mut payload)?;
            let ip = Ipv4Header::new(
                payload
                    .len()
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv4 header"))?,
                64,
                transport_proto,
                src.octets(),
                dst.octets(),
            )
            .context("failed to create IPv4 header")?;

            let mut bytes =
                Vec::with_capacity(Ethernet2Header::LEN + ip.header_len() + payload.len());
            eth.write(&mut bytes)
                .context("failed to serialize Ethernet header")?;
            ip.write(&mut bytes)
                .context("failed to serialize IPv4 header")?;
            bytes.extend_from_slice(&payload);
            Ok(bytes)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let ip = Ipv6Header {
                traffic_class: 0,
                flow_label: Default::default(),
                payload_length: 0,
                next_header: transport_proto,
                hop_limit: 64,
                source: src.octets(),
                destination: dst.octets(),
            };
            write_transport(IpKind::V6(&ip), &mut payload)?;
            let ip = Ipv6Header {
                traffic_class: 0,
                flow_label: Default::default(),
                payload_length: payload
                    .len()
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv6 header"))?,
                next_header: transport_proto,
                hop_limit: 64,
                source: src.octets(),
                destination: dst.octets(),
            };

            let mut bytes =
                Vec::with_capacity(Ethernet2Header::LEN + Ipv6Header::LEN + payload.len());
            eth.write(&mut bytes)
                .context("failed to serialize Ethernet header")?;
            ip.write(&mut bytes)
                .context("failed to serialize IPv6 header")?;
            bytes.extend_from_slice(&payload);
            Ok(bytes)
        }
        _ => bail!("source and destination IP versions must match"),
    }
}

pub(super) fn build_ip_packet<F>(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    payload_len: usize,
    hop_limit: u8,
    transport_proto: IpNumber,
    write_transport: F,
) -> Result<Vec<u8>>
where
    F: FnOnce(IpKind<'_>, &mut Vec<u8>) -> Result<()>,
{
    let mut payload = Vec::with_capacity(payload_len);
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let ip = Ipv4Header::new(
                payload_len
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv4 header"))?,
                hop_limit,
                transport_proto,
                src.octets(),
                dst.octets(),
            )
            .context("failed to create IPv4 header")?;
            write_transport(IpKind::V4(&ip), &mut payload)?;
            let ip = Ipv4Header::new(
                payload
                    .len()
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv4 header"))?,
                hop_limit,
                transport_proto,
                src.octets(),
                dst.octets(),
            )
            .context("failed to create IPv4 header")?;
            let mut bytes = Vec::with_capacity(ip.header_len() + payload.len());
            ip.write(&mut bytes)
                .context("failed to serialize IPv4 header")?;
            bytes.extend_from_slice(&payload);
            Ok(bytes)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let ip = Ipv6Header {
                traffic_class: 0,
                flow_label: Default::default(),
                payload_length: payload_len
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv6 header"))?,
                next_header: transport_proto,
                hop_limit,
                source: src.octets(),
                destination: dst.octets(),
            };
            write_transport(IpKind::V6(&ip), &mut payload)?;
            let ip = Ipv6Header {
                traffic_class: 0,
                flow_label: Default::default(),
                payload_length: payload
                    .len()
                    .try_into()
                    .map_err(|_| anyhow!("payload too large for IPv6 header"))?,
                next_header: transport_proto,
                hop_limit,
                source: src.octets(),
                destination: dst.octets(),
            };
            let mut bytes = Vec::with_capacity(Ipv6Header::LEN + payload.len());
            ip.write(&mut bytes)
                .context("failed to serialize IPv6 header")?;
            bytes.extend_from_slice(&payload);
            Ok(bytes)
        }
        _ => bail!("source and destination IP versions must match"),
    }
}

pub(super) fn wrap_ipv4_packet_with_ethernet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    ip_packet: &[u8],
) -> Result<Vec<u8>> {
    let eth = Ethernet2Header {
        source: src_mac,
        destination: dst_mac,
        ether_type: etherparse::EtherType::IPV4,
    };
    let mut bytes = Vec::with_capacity(Ethernet2Header::LEN + ip_packet.len());
    eth.write(&mut bytes)
        .context("failed to serialize Ethernet header")?;
    bytes.extend_from_slice(ip_packet);
    Ok(bytes)
}

pub(super) fn wrap_ipv6_packet_with_ethernet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    ip_packet: &[u8],
) -> Result<Vec<u8>> {
    let eth = Ethernet2Header {
        source: src_mac,
        destination: dst_mac,
        ether_type: etherparse::EtherType::IPV6,
    };
    let mut bytes = Vec::with_capacity(Ethernet2Header::LEN + ip_packet.len());
    eth.write(&mut bytes)
        .context("failed to serialize Ethernet header")?;
    bytes.extend_from_slice(ip_packet);
    Ok(bytes)
}
