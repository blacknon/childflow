use std::net::{Ipv4Addr, Ipv6Addr};

pub fn lo_up_args() -> Vec<String> {
    vec!["link".into(), "set".into(), "lo".into(), "up".into()]
}

pub fn addr_add_v4_args(iface: &str, ip: Ipv4Addr, prefix_len: u8) -> Vec<String> {
    vec![
        "addr".into(),
        "add".into(),
        format!("{ip}/{prefix_len}"),
        "dev".into(),
        iface.into(),
    ]
}

pub fn addr_add_v6_args(iface: &str, ip: Ipv6Addr, prefix_len: u8) -> Vec<String> {
    vec![
        "-6".into(),
        "addr".into(),
        "add".into(),
        format!("{ip}/{prefix_len}"),
        "dev".into(),
        iface.into(),
        "nodad".into(),
    ]
}

pub fn link_up_args(iface: &str) -> Vec<String> {
    vec!["link".into(), "set".into(), iface.into(), "up".into()]
}

pub fn default_route_v4_args(gateway: Ipv4Addr, iface: &str) -> Vec<String> {
    vec![
        "route".into(),
        "add".into(),
        "default".into(),
        "via".into(),
        gateway.to_string(),
        "dev".into(),
        iface.into(),
    ]
}

pub fn default_route_v6_args(gateway: Ipv6Addr, iface: &str) -> Vec<String> {
    vec![
        "-6".into(),
        "route".into(),
        "add".into(),
        "default".into(),
        "via".into(),
        gateway.to_string(),
        "dev".into(),
        iface.into(),
    ]
}

pub fn neigh_add_v4_args(neighbor: Ipv4Addr, mac: &str, iface: &str) -> Vec<String> {
    vec![
        "neigh".into(),
        "add".into(),
        neighbor.to_string(),
        "lladdr".into(),
        mac.into(),
        "dev".into(),
        iface.into(),
        "nud".into(),
        "permanent".into(),
    ]
}

pub fn neigh_add_v6_args(neighbor: Ipv6Addr, mac: &str, iface: &str) -> Vec<String> {
    vec![
        "-6".into(),
        "neigh".into(),
        "add".into(),
        neighbor.to_string(),
        "lladdr".into(),
        mac.into(),
        "dev".into(),
        iface.into(),
        "nud".into(),
        "permanent".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_helpers_render_expected_strings() {
        assert_eq!(
            addr_add_v4_args("tap0", Ipv4Addr::new(10, 0, 0, 2), 30),
            vec!["addr", "add", "10.0.0.2/30", "dev", "tap0"]
        );
        assert_eq!(
            addr_add_v6_args("tap0", "fd42::2".parse().unwrap(), 64),
            vec!["-6", "addr", "add", "fd42::2/64", "dev", "tap0", "nodad"]
        );
    }

    #[test]
    fn route_helpers_render_default_routes() {
        assert_eq!(
            default_route_v4_args(Ipv4Addr::new(10, 0, 0, 1), "tap0"),
            vec!["route", "add", "default", "via", "10.0.0.1", "dev", "tap0"]
        );
        assert_eq!(
            default_route_v6_args("fd42::1".parse().unwrap(), "tap0"),
            vec!["-6", "route", "add", "default", "via", "fd42::1", "dev", "tap0"]
        );
    }

    #[test]
    fn neigh_helpers_render_static_neighbors() {
        assert_eq!(
            neigh_add_v4_args(Ipv4Addr::new(10, 0, 0, 1), "02:cf:00:00:00:01", "tap0"),
            vec![
                "neigh",
                "add",
                "10.0.0.1",
                "lladdr",
                "02:cf:00:00:00:01",
                "dev",
                "tap0",
                "nud",
                "permanent"
            ]
        );
        assert_eq!(
            neigh_add_v6_args("fd42::1".parse().unwrap(), "02:cf:00:00:00:01", "tap0"),
            vec![
                "-6",
                "neigh",
                "add",
                "fd42::1",
                "lladdr",
                "02:cf:00:00:00:01",
                "dev",
                "tap0",
                "nud",
                "permanent"
            ]
        );
    }
}
