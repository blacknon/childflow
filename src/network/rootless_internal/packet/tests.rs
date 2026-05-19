use std::net::{IpAddr, Ipv4Addr};

use super::*;

#[test]
fn build_tcp_frame_emits_ipv4_ethernet_packet() {
    let frame = build_tcp_frame(TcpReply {
        src_mac: [0x02, 0xcf, 0, 0, 0, 1],
        dst_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        src_port: 443,
        dst_port: 40000,
        seq: 1,
        ack: 2,
        syn: true,
        ack_flag: true,
        fin: false,
        rst: false,
        psh: false,
        payload: &[],
    })
    .unwrap();

    match parse_frame(&frame).unwrap() {
        ParsedPacket::Tcp(packet) => {
            assert_eq!(packet.src_port, 443);
            assert_eq!(packet.dst_port, 40000);
            assert!(packet.syn);
            assert!(packet.ack);
            assert_eq!(packet.meta.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
            assert_eq!(packet.meta.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        }
        other => panic!("unexpected packet: {other:?}"),
    }
}

#[test]
fn build_udp_frame_round_trips_ipv6_payload() {
    let payload = b"dns".to_vec();
    let frame = build_udp_frame(
        [0x02, 0xcf, 0, 0, 0, 1],
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        IpAddr::V6("fd42::1".parse().unwrap()),
        IpAddr::V6("fd42::2".parse().unwrap()),
        53,
        40000,
        &payload,
    )
    .unwrap();

    match parse_frame(&frame).unwrap() {
        ParsedPacket::Udp(packet) => {
            assert_eq!(packet.src_port, 53);
            assert_eq!(packet.dst_port, 40000);
            assert_eq!(packet.payload, payload);
            assert_eq!(packet.meta.src_ip, IpAddr::V6("fd42::1".parse().unwrap()));
            assert_eq!(packet.meta.dst_ip, IpAddr::V6("fd42::2".parse().unwrap()));
        }
        other => panic!("unexpected packet: {other:?}"),
    }
}

#[test]
fn build_icmpv4_echo_frame_round_trips_payload() {
    let payload = b"ping-data".to_vec();
    let frame = build_icmpv4_echo_frame(Icmpv4EchoFrame {
        src_mac: [0x02, 0xcf, 0, 0, 0, 1],
        dst_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        src_ip: Ipv4Addr::new(1, 1, 1, 1),
        dst_ip: Ipv4Addr::new(10, 0, 0, 2),
        icmp_type: 0,
        code: 0,
        identifier: 0x1234,
        sequence: 7,
        payload: &payload,
    })
    .unwrap();

    match parse_frame(&frame).unwrap() {
        ParsedPacket::Icmpv4(packet) => {
            assert_eq!(packet.icmp_type, 0);
            assert_eq!(packet.code, 0);
            assert_eq!(packet.identifier, 0x1234);
            assert_eq!(packet.sequence, 7);
            assert_eq!(packet.payload, payload);
            assert_eq!(packet.meta.src_ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
            assert_eq!(packet.meta.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        }
        other => panic!("unexpected packet: {other:?}"),
    }
}

#[test]
fn build_icmpv6_echo_frame_round_trips_payload() {
    let payload = b"ping6-data".to_vec();
    let src_ip = "2001:db8::1".parse().unwrap();
    let dst_ip = "fd42::2".parse().unwrap();
    let frame = build_icmpv6_echo_frame(Icmpv6EchoFrame {
        src_mac: [0x02, 0xcf, 0, 0, 0, 1],
        dst_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        src_ip,
        dst_ip,
        icmp_type: 129,
        code: 0,
        identifier: 0x4321,
        sequence: 9,
        payload: &payload,
    })
    .unwrap();

    match parse_frame(&frame).unwrap() {
        ParsedPacket::Icmpv6(packet) => {
            assert_eq!(packet.icmp_type, 129);
            assert_eq!(packet.code, 0);
            assert_eq!(packet.identifier, 0x4321);
            assert_eq!(packet.sequence, 9);
            assert_eq!(packet.payload, payload);
            assert_eq!(packet.meta.src_ip, IpAddr::V6(src_ip));
            assert_eq!(packet.meta.dst_ip, IpAddr::V6(dst_ip));
        }
        other => panic!("unexpected packet: {other:?}"),
    }
}
