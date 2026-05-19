mod frames;
mod v4;
mod v6;

pub(in crate::network::rootless_internal::icmp) use self::v4::{
    spawn_icmpv4_echo_worker, spawn_icmpv4_raw_worker,
};
pub(in crate::network::rootless_internal::icmp) use self::v6::{
    spawn_icmpv6_echo_worker, spawn_icmpv6_raw_worker,
};

pub(super) fn should_relay_icmpv4_request(icmp_type: u8) -> bool {
    !matches!(icmp_type, 0 | 3 | 4 | 5 | 11 | 12)
}

pub(super) fn should_relay_icmpv6_request(icmp_type: u8, dst_ip: std::net::Ipv6Addr) -> bool {
    !dst_ip.is_multicast() && icmp_type >= 128 && !matches!(icmp_type, 128 | 129 | 130..=137 | 143)
}
