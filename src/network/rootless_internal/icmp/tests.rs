use std::net::IpAddr;
use std::process::{ExitStatus, Output};

use super::relay::{parse_ping_helper_output, parse_unreachable_code};
use super::IcmpRelayOutcome;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

fn successful_status() -> ExitStatus {
    #[cfg(unix)]
    {
        ExitStatusExt::from_raw(0)
    }
    #[cfg(not(unix))]
    {
        std::process::Command::new("true").status().unwrap()
    }
}

#[test]
fn parse_unreachable_code_maps_ipv4_port_unreachable() {
    assert_eq!(
        parse_unreachable_code(
            "From 192.0.2.1 icmp_seq=1 Destination Port Unreachable",
            false
        ),
        3
    );
}

#[test]
fn parse_unreachable_code_maps_ipv6_admin_prohibited() {
    assert_eq!(
        parse_unreachable_code(
            "From 2001:db8::1 icmp_seq=1 Destination unreachable: Administratively prohibited",
            true
        ),
        1
    );
}

#[test]
fn parse_ping_helper_output_recognizes_success() {
    let output = Output {
        status: successful_status(),
        stdout: b"64 bytes from 93.184.216.34: icmp_seq=1 ttl=57 time=10.0 ms\n".to_vec(),
        stderr: Vec::new(),
    };

    let outcome = parse_ping_helper_output(IpAddr::from([93, 184, 216, 34]), false, &output)
        .expect("success output should parse");

    assert!(matches!(outcome, IcmpRelayOutcome::Message(payload) if payload.is_empty()));
}

#[test]
fn parse_ping_helper_output_recognizes_ipv4_unreachable() {
    let output = Output {
        status: successful_status(),
        stdout: b"From 192.0.2.1 icmp_seq=1 Destination Host Unreachable\n".to_vec(),
        stderr: Vec::new(),
    };

    let outcome = parse_ping_helper_output(IpAddr::from([93, 184, 216, 34]), false, &output)
        .expect("error output should parse");

    match outcome {
        IcmpRelayOutcome::Error {
            source_ip,
            icmp_type,
            code,
        } => {
            assert_eq!(source_ip, IpAddr::from([192, 0, 2, 1]));
            assert_eq!(icmp_type, 3);
            assert_eq!(code, 1);
        }
        IcmpRelayOutcome::Message(_) => panic!("expected ICMP error outcome"),
    }
}
