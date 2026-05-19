use std::net::Ipv4Addr;

pub(crate) use capture::{
    assert_capture_file_written, assert_capture_has_enhanced_packets, unique_temp_capture_path,
    unique_temp_flow_log_path,
};
pub(crate) use command::run_childflow_command;
pub(crate) use dns::{unique_loopback_dns_ip, LocalDnsServer};
pub(crate) use http::{
    assert_connects_to_https_target, spawn_bound_http_server, spawn_http_connect_proxy,
    spawn_local_http_server, spawn_local_tcp_server, spawn_local_udp_server,
};
pub(crate) use net::{discover_reachable_host_ipv4, LoopbackAliasGuard};
pub(crate) use temp::unique_temp_profile_dir;

mod capture;
mod command;
mod dns;
mod http;
mod net;
mod temp;

pub(crate) fn privileged_ip_program() -> std::process::Command {
    if unsafe { nix::libc::geteuid() } == 0 {
        std::process::Command::new("ip")
    } else {
        let mut command = std::process::Command::new("sudo");
        command.arg("-n").arg("ip");
        command
    }
}

pub(crate) fn loopback_metadata_ip() -> Ipv4Addr {
    Ipv4Addr::new(169, 254, 169, 254)
}
