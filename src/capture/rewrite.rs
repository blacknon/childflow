use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use etherparse::{EtherType, Ethernet2HeaderSlice};

use super::RootfulEgressRewrite;
use crate::network::rootless_internal::packet::{
    self, Icmpv4EchoFrame, Icmpv6EchoFrame, ParsedPacket, TcpReply,
};

pub(super) fn rewrite_rootful_egress_frame(
    frame: &[u8],
    rewrite: RootfulEgressRewrite,
) -> Result<Option<Vec<u8>>> {
    let eth = Ethernet2HeaderSlice::from_slice(frame).context("failed to parse Ethernet header")?;

    match eth.ether_type() {
        EtherType::IPV4 | EtherType::IPV6 => {}
        _ => return Ok(None),
    }

    match packet::parse_frame(frame) {
        Ok(ParsedPacket::Tcp(tcp)) => {
            let Some((src_ip, dst_ip)) = rewrite_ips(tcp.meta.src_ip, tcp.meta.dst_ip, rewrite)?
            else {
                return Ok(None);
            };
            Ok(Some(packet::build_tcp_frame(TcpReply {
                src_mac: tcp.meta.src_mac,
                dst_mac: tcp.meta.dst_mac,
                src_ip,
                dst_ip,
                src_port: tcp.src_port,
                dst_port: tcp.dst_port,
                seq: tcp.sequence_number,
                ack: tcp.acknowledgment_number,
                syn: tcp.syn,
                ack_flag: tcp.ack,
                fin: tcp.fin,
                rst: tcp.rst,
                psh: tcp.psh,
                payload: &tcp.payload,
            })?))
        }
        Ok(ParsedPacket::Udp(udp)) => {
            let Some((src_ip, dst_ip)) = rewrite_ips(udp.meta.src_ip, udp.meta.dst_ip, rewrite)?
            else {
                return Ok(None);
            };
            Ok(Some(packet::build_udp_frame(
                udp.meta.src_mac,
                udp.meta.dst_mac,
                src_ip,
                dst_ip,
                udp.src_port,
                udp.dst_port,
                &udp.payload,
            )?))
        }
        Ok(ParsedPacket::Icmpv4(icmp)) => {
            let Some((src_ip, dst_ip)) = rewrite_ips(icmp.meta.src_ip, icmp.meta.dst_ip, rewrite)?
            else {
                return Ok(None);
            };
            let (src_ip, dst_ip) = match (src_ip, dst_ip) {
                (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => (src_ip, dst_ip),
                _ => return Ok(None),
            };
            Ok(Some(packet::build_icmpv4_echo_frame(Icmpv4EchoFrame {
                src_mac: icmp.meta.src_mac,
                dst_mac: icmp.meta.dst_mac,
                src_ip,
                dst_ip,
                icmp_type: icmp.icmp_type,
                code: icmp.code,
                identifier: icmp.identifier,
                sequence: icmp.sequence,
                payload: &icmp.payload,
            })?))
        }
        Ok(ParsedPacket::Icmpv6(icmp)) => {
            let Some((src_ip, dst_ip)) = rewrite_ips(icmp.meta.src_ip, icmp.meta.dst_ip, rewrite)?
            else {
                return Ok(None);
            };
            let (src_ip, dst_ip) = match (src_ip, dst_ip) {
                (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => (src_ip, dst_ip),
                _ => return Ok(None),
            };
            Ok(Some(packet::build_icmpv6_echo_frame(Icmpv6EchoFrame {
                src_mac: icmp.meta.src_mac,
                dst_mac: icmp.meta.dst_mac,
                src_ip,
                dst_ip,
                icmp_type: icmp.icmp_type,
                code: icmp.code,
                identifier: icmp.identifier,
                sequence: icmp.sequence,
                payload: &icmp.payload,
            })?))
        }
        Ok(ParsedPacket::Unsupported) => Ok(None),
        Err(_) => Ok(None),
    }
}

fn rewrite_ips(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    rewrite: RootfulEgressRewrite,
) -> Result<Option<(IpAddr, IpAddr)>> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let Some(host_ip) = rewrite.host_egress_ipv4 else {
                return Ok(None);
            };
            Ok(Some((
                if src == rewrite.child_ipv4 {
                    IpAddr::V4(host_ip)
                } else {
                    IpAddr::V4(src)
                },
                if dst == rewrite.child_ipv4 {
                    IpAddr::V4(host_ip)
                } else {
                    IpAddr::V4(dst)
                },
            )))
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let Some(host_ip) = rewrite.host_egress_ipv6 else {
                return Ok(None);
            };
            Ok(Some((
                if src == rewrite.child_ipv6 {
                    IpAddr::V6(host_ip)
                } else {
                    IpAddr::V6(src)
                },
                if dst == rewrite.child_ipv6 {
                    IpAddr::V6(host_ip)
                } else {
                    IpAddr::V6(dst)
                },
            )))
        }
        _ => bail!("mixed IPv4/IPv6 packet addresses are unsupported for capture rewriting"),
    }
}
