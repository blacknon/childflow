mod lifecycle;
mod loop_;

pub(in crate::network::rootless_internal::engine) use lifecycle::detect_ipv6_outbound;
