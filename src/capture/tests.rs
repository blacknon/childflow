use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use super::rewrite::rewrite_rootful_egress_frame;
use super::*;
use crate::network::rootless_internal::packet::{build_tcp_frame, ParsedPacket, TcpReply};

#[test]
fn derive_output_paths_for_both_appends_child_and_egress_suffixes() {
    let (child, egress) =
        derive_output_paths(Path::new("/tmp/capture.pcapng"), OutputView::Both).unwrap();

    assert_eq!(child, PathBuf::from("/tmp/capture.child.pcapng"));
    assert_eq!(egress, PathBuf::from("/tmp/capture.egress.pcapng"));
}

#[test]
fn effective_view_name_expands_both_to_child_and_egress() {
    assert_eq!(requested_view_name(OutputView::Child), "child");
    assert_eq!(requested_view_name(OutputView::WireEgress), "wire-egress");
    assert_eq!(effective_view_name(OutputView::Child), "child");
    assert_eq!(effective_view_name(OutputView::Both), "child+egress");
}

#[test]
fn rewrite_rootful_egress_frame_rewrites_child_ipv4_endpoint_to_host_ipv4() {
    let frame = build_tcp_frame(TcpReply {
        src_mac: [0, 1, 2, 3, 4, 5],
        dst_mac: [6, 7, 8, 9, 10, 11],
        src_ip: IpAddr::V4(Ipv4Addr::new(10, 240, 0, 2)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        src_port: 12345,
        dst_port: 443,
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

    let rewritten = rewrite_rootful_egress_frame(
        &frame,
        RootfulEgressRewrite {
            child_ipv4: Ipv4Addr::new(10, 240, 0, 2),
            child_ipv6: "fd42::2".parse().unwrap(),
            host_egress_ipv4: Some(Ipv4Addr::new(192, 0, 2, 10)),
            host_egress_ipv6: Some("2001:db8::10".parse().unwrap()),
        },
    )
    .unwrap()
    .unwrap();

    match crate::network::rootless_internal::packet::parse_frame(&rewritten).unwrap() {
        ParsedPacket::Tcp(tcp) => {
            assert_eq!(tcp.meta.src_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
            assert_eq!(tcp.meta.dst_ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        }
        other => panic!("expected rewritten TCP packet, got {other:?}"),
    }
}

#[test]
fn rewrite_rootful_egress_frame_skips_ipv6_when_no_ipv6_egress_is_known() {
    let frame = build_tcp_frame(TcpReply {
        src_mac: [0, 1, 2, 3, 4, 5],
        dst_mac: [6, 7, 8, 9, 10, 11],
        src_ip: IpAddr::V6("fd42::2".parse().unwrap()),
        dst_ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
        src_port: 12345,
        dst_port: 443,
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

    let rewritten = rewrite_rootful_egress_frame(
        &frame,
        RootfulEgressRewrite {
            child_ipv4: Ipv4Addr::new(10, 240, 0, 2),
            child_ipv6: "fd42::2".parse().unwrap(),
            host_egress_ipv4: Some(Ipv4Addr::new(192, 0, 2, 10)),
            host_egress_ipv6: None,
        },
    )
    .unwrap();

    assert!(rewritten.is_none());
}
