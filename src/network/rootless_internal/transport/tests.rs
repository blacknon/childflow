use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use super::super::engine::RemoteEvent;
use super::super::state::FlowKey;
use super::dns::{
    dns_answer_ips, dns_query_name, dns_query_type, synthesize_empty_dns_response, DNS_TYPE_AAAA,
};
use super::tcp::connect_remote;
use super::udp::{relay_dns_udp_to, relay_udp_payload, UdpRelayOutcome};

#[test]
fn relay_dns_udp_forwards_payload_and_response() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let request = b"query".to_vec();
    let response = b"reply".to_vec();

    let join = thread::spawn({
        let request = request.clone();
        let response = response.clone();
        move || {
            let mut buf = [0_u8; 64];
            let (n, peer) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], request.as_slice());
            upstream.send_to(&response, peer).unwrap();
        }
    });

    let actual = relay_dns_udp_to(upstream_addr, &request).unwrap();
    join.join().unwrap();
    assert_eq!(actual, response);
}

#[test]
fn relay_udp_payload_forwards_payload_and_response() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let request = b"udp-request".to_vec();
    let response = b"udp-response".to_vec();

    let join = thread::spawn({
        let request = request.clone();
        let response = response.clone();
        move || {
            let mut buf = [0_u8; 64];
            let (n, peer) = upstream.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], request.as_slice());
            upstream.send_to(&response, peer).unwrap();
        }
    });

    let actual = relay_udp_payload(upstream_addr, 64, &request).unwrap();
    join.join().unwrap();
    assert_eq!(actual, UdpRelayOutcome::Payload(response));
}

#[test]
fn connect_remote_reaches_tcp_listener() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = mpsc::channel();
    let join = thread::spawn(move || {
        let _ = listener.accept().unwrap();
        accepted_tx.send(()).unwrap();
    });

    let (event_tx, _event_rx) = mpsc::channel::<RemoteEvent>();
    let key = FlowKey {
        child_ip: IpAddr::V4(Ipv4Addr::new(10, 240, 0, 2)),
        child_port: 40000,
        remote_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        remote_port: addr.port(),
    };
    let command_tx = connect_remote(addr, None, event_tx, key).unwrap();
    accepted_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    drop(command_tx);
    join.join().unwrap();
}

#[test]
fn dns_query_type_detects_aaaa_question() {
    let query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00, 0x01,
    ];
    assert_eq!(dns_query_type(&query), Some(DNS_TYPE_AAAA));
}

#[test]
fn dns_query_name_extracts_normalized_qname() {
    let query = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'E', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'C', b'O', b'M', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];

    assert_eq!(dns_query_name(&query).as_deref(), Some("example.com"));
}

#[test]
fn dns_answer_ips_extracts_a_and_aaaa_records() {
    let response = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xC0,
        0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184, 216, 34, 0xC0,
        0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ];

    assert_eq!(
        dns_answer_ips(&response),
        vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6(Ipv6Addr::from([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
        ]
    );
}

#[test]
fn synthesize_empty_dns_response_preserves_question() {
    let query = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00, 0x01,
    ];
    let response = synthesize_empty_dns_response(&query).unwrap();
    assert_eq!(&response[..2], &query[..2]);
    assert_eq!(u16::from_be_bytes([response[4], response[5]]), 1);
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    assert_eq!(&response[12..], &query[12..]);
    assert_ne!(response[2] & 0x80, 0);
}
