// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::ffi::CString;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{bail, Context, Result};

const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FR_ACT_TO_TBL: u8 = 1;
const VETH_INFO_PEER: u16 = 1;

#[repr(C)]
struct In6IfReq {
    ifr6_addr: nix::libc::in6_addr,
    ifr6_prefixlen: u32,
    ifr6_ifindex: i32,
}

#[repr(C)]
struct NdMsg {
    ndm_family: u8,
    ndm_pad1: u8,
    ndm_pad2: u16,
    ndm_ifindex: i32,
    ndm_state: u16,
    ndm_flags: u8,
    ndm_type: u8,
}

#[repr(C)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[repr(C)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

#[repr(C)]
struct FibRuleHdr {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    res1: u8,
    res2: u8,
    action: u8,
    flags: u32,
}

#[repr(C)]
struct IfInfoMsg {
    ifi_family: u8,
    __ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

pub fn link_set_up(iface: &str) -> Result<()> {
    let socket = open_control_socket()?;
    let mut ifreq = named_ifreq(iface)?;
    let rc = unsafe {
        // SAFETY: `socket` is a valid datagram socket and `ifreq` points to initialized writable
        // storage. The kernel writes interface flags into the union field.
        nix::libc::ioctl(socket.as_raw_fd(), nix::libc::SIOCGIFFLAGS as _, &mut ifreq)
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .with_context(|| format!("failed to read interface flags for `{iface}`"));
    }

    let flags = unsafe {
        // SAFETY: `SIOCGIFFLAGS` initialized the `ifru_flags` field above.
        ifreq.ifr_ifru.ifru_flags
    };
    let updated_flags = flags | (nix::libc::IFF_UP as nix::libc::c_short);
    ifreq.ifr_ifru.ifru_flags = updated_flags;

    let rc = unsafe {
        // SAFETY: `socket` remains valid and `ifreq` contains a valid interface name plus flags.
        nix::libc::ioctl(socket.as_raw_fd(), nix::libc::SIOCSIFFLAGS as _, &mut ifreq)
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .with_context(|| format!("failed to bring interface `{iface}` up"));
    }

    Ok(())
}

pub fn loopback_set_up() -> Result<()> {
    link_set_up("lo").context("failed to bring loopback up")
}

pub fn addr_add_v4(iface: &str, ip: Ipv4Addr, prefix_len: u8) -> Result<()> {
    let socket = open_control_socket()?;
    let addr = sockaddr_for_ipv4(ip);
    let mut ifreq = named_ifreq_with_sockaddr(iface, addr)?;
    let rc = unsafe {
        // SAFETY: `socket` is valid and `ifreq` contains a Linux `sockaddr_in` payload for
        // `SIOCSIFADDR` in the expected union field.
        nix::libc::ioctl(socket.as_raw_fd(), nix::libc::SIOCSIFADDR as _, &mut ifreq)
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .with_context(|| format!("failed to assign IPv4 address `{ip}` to `{iface}`"));
    }

    let netmask = prefix_len_to_netmask_v4(prefix_len)?;
    let mut ifreq = named_ifreq_with_sockaddr(iface, sockaddr_for_ipv4(netmask))?;
    let rc = unsafe {
        // SAFETY: `socket` is valid and `ifreq` contains a Linux `sockaddr_in` payload for
        // `SIOCSIFNETMASK` in the expected union field.
        nix::libc::ioctl(
            socket.as_raw_fd(),
            nix::libc::SIOCSIFNETMASK as _,
            &mut ifreq,
        )
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error())).with_context(|| {
            format!("failed to assign IPv4 netmask for `{ip}/{prefix_len}` on `{iface}`")
        });
    }

    Ok(())
}

pub fn addr_add_v6(iface: &str, ip: Ipv6Addr, prefix_len: u8) -> Result<()> {
    if prefix_len > 128 {
        bail!("IPv6 prefix length must be <= 128, got {prefix_len}");
    }

    let socket = open_control_socket_for_family(nix::libc::AF_INET6)
        .context("failed to open an IPv6 control socket for address assignment")?;
    let ifindex = interface_index(iface)?;
    let mut req = In6IfReq {
        ifr6_addr: in6_addr_for_ipv6(ip),
        ifr6_prefixlen: u32::from(prefix_len),
        ifr6_ifindex: ifindex,
    };
    let rc = unsafe {
        // SAFETY: `socket` is valid and `req` matches the Linux `in6_ifreq` layout expected by
        // `SIOCSIFADDR` for IPv6 address assignment.
        nix::libc::ioctl(socket.as_raw_fd(), nix::libc::SIOCSIFADDR as _, &mut req)
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error())).with_context(|| {
            format!("failed to assign IPv6 address `{ip}/{prefix_len}` to `{iface}`")
        });
    }

    Ok(())
}

pub fn neigh_add_v4(iface: &str, neighbor: Ipv4Addr, mac: &str) -> Result<()> {
    let socket = open_control_socket()?;
    let mut req = named_arpreq(iface, neighbor, mac)?;
    let rc = unsafe {
        // SAFETY: `socket` is valid and `req` is a fully initialized `arpreq` structure for
        // `SIOCSARP`.
        nix::libc::ioctl(socket.as_raw_fd(), nix::libc::SIOCSARP as _, &mut req)
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .with_context(|| format!("failed to install IPv4 neighbor `{neighbor}` on `{iface}`"));
    }

    Ok(())
}

pub fn neigh_add_v6(iface: &str, neighbor: Ipv6Addr, mac: &str) -> Result<()> {
    let ifindex = interface_index(iface)?;
    let mac = parse_mac(mac)?;
    with_netlink_route_socket(|socket, seq| {
        let mut msg = NetlinkMessage::new(
            nix::libc::RTM_NEWNEIGH,
            (nix::libc::NLM_F_REQUEST
                | nix::libc::NLM_F_CREATE
                | nix::libc::NLM_F_EXCL
                | nix::libc::NLM_F_ACK) as u16,
            seq,
        );
        let ndmsg = NdMsg {
            ndm_family: nix::libc::AF_INET6 as u8,
            ndm_pad1: 0,
            ndm_pad2: 0,
            ndm_ifindex: ifindex,
            ndm_state: nix::libc::NUD_PERMANENT,
            ndm_flags: 0,
            ndm_type: nix::libc::RTN_UNICAST,
        };
        msg.push_value(&ndmsg);
        msg.push_attr_bytes(nix::libc::NDA_DST, &neighbor.octets());
        msg.push_attr_bytes(nix::libc::NDA_LLADDR, &mac);
        send_netlink_request(socket, seq, &msg.bytes)
            .with_context(|| format!("failed to install IPv6 neighbor `{neighbor}` on `{iface}`"))
    })
}

pub fn default_route_add_v4(iface: &str, gateway: Ipv4Addr) -> Result<()> {
    let socket = open_control_socket()?;
    let iface = CString::new(iface)
        .with_context(|| format!("interface name `{iface}` contains an interior NUL byte"))?;
    let mut route = default_route_entry_v4(gateway, &iface);
    let rc = unsafe {
        // SAFETY: `socket` is valid and `route` points to initialized `rtentry` storage expected
        // by `SIOCADDRT`. The `iface` CString outlives the ioctl call.
        nix::libc::ioctl(socket.as_raw_fd(), nix::libc::SIOCADDRT as _, &mut route)
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error())).with_context(|| {
            format!(
                "failed to install IPv4 default route via `{gateway}` on `{}`",
                iface.to_string_lossy()
            )
        });
    }

    Ok(())
}

pub fn default_route_add_v6(iface: &str, gateway: Ipv6Addr) -> Result<()> {
    let ifindex = interface_index(iface)? as u32;
    with_netlink_route_socket(|socket, seq| {
        let mut msg = NetlinkMessage::new(
            nix::libc::RTM_NEWROUTE,
            (nix::libc::NLM_F_REQUEST
                | nix::libc::NLM_F_CREATE
                | nix::libc::NLM_F_EXCL
                | nix::libc::NLM_F_ACK) as u16,
            seq,
        );
        let rtmsg = RtMsg {
            rtm_family: nix::libc::AF_INET6 as u8,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: nix::libc::RT_TABLE_MAIN,
            rtm_protocol: nix::libc::RTPROT_BOOT,
            rtm_scope: nix::libc::RT_SCOPE_UNIVERSE,
            rtm_type: nix::libc::RTN_UNICAST,
            rtm_flags: 0,
        };
        msg.push_value(&rtmsg);
        msg.push_attr_bytes(nix::libc::RTA_GATEWAY, &gateway.octets());
        msg.push_attr_bytes(nix::libc::RTA_OIF, &ifindex.to_ne_bytes());
        send_netlink_request(socket, seq, &msg.bytes).with_context(|| {
            format!("failed to install IPv6 default route via `{gateway}` on `{iface}`")
        })
    })
}

pub fn policy_rule_add_v4(fwmark: u32, table: u32, priority: u32) -> Result<()> {
    add_policy_rule(nix::libc::AF_INET as u8, fwmark, table, priority)
}

pub fn policy_rule_del_v4(fwmark: u32, table: u32, priority: u32) -> Result<()> {
    delete_policy_rule(nix::libc::AF_INET as u8, fwmark, table, priority)
}

pub fn policy_rule_add_v6(fwmark: u32, table: u32, priority: u32) -> Result<()> {
    add_policy_rule(nix::libc::AF_INET6 as u8, fwmark, table, priority)
}

pub fn policy_rule_del_v6(fwmark: u32, table: u32, priority: u32) -> Result<()> {
    delete_policy_rule(nix::libc::AF_INET6 as u8, fwmark, table, priority)
}

pub fn route_add_default_v4_table(
    iface: &str,
    gateway: Option<Ipv4Addr>,
    table: u32,
) -> Result<()> {
    add_default_route_v4(iface, gateway, table)
}

pub fn route_del_default_v4_table(
    iface: &str,
    gateway: Option<Ipv4Addr>,
    table: u32,
) -> Result<()> {
    delete_default_route_v4(iface, gateway, table)
}

pub fn route_add_default_v6_table(
    iface: &str,
    gateway: Option<Ipv6Addr>,
    table: u32,
) -> Result<()> {
    add_default_route_v6(iface, gateway, table)
}

pub fn route_del_default_v6_table(
    iface: &str,
    gateway: Option<Ipv6Addr>,
    table: u32,
) -> Result<()> {
    delete_default_route_v6(iface, gateway, table)
}

pub fn route_add_local_v4_table(table: u32) -> Result<()> {
    add_local_route_v4(table)
}

pub fn route_del_local_v4_table(table: u32) -> Result<()> {
    delete_local_route_v4(table)
}

pub fn route_add_local_v6_table(table: u32) -> Result<()> {
    add_local_route_v6(table)
}

pub fn route_del_local_v6_table(table: u32) -> Result<()> {
    delete_local_route_v6(table)
}

pub fn veth_pair_create(host_ifname: &str, peer_ifname: &str) -> Result<()> {
    with_netlink_route_socket(|socket, seq| {
        let mut msg = NetlinkMessage::new(
            nix::libc::RTM_NEWLINK,
            (nix::libc::NLM_F_REQUEST
                | nix::libc::NLM_F_CREATE
                | nix::libc::NLM_F_EXCL
                | nix::libc::NLM_F_ACK) as u16,
            seq,
        );
        let ifinfo = IfInfoMsg {
            ifi_family: nix::libc::AF_UNSPEC as u8,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: 0,
            ifi_flags: 0,
            ifi_change: u32::MAX,
        };
        msg.push_value(&ifinfo);
        msg.push_attr_bytes(
            nix::libc::IFLA_IFNAME,
            cstring_bytes(host_ifname)?.as_slice(),
        );
        msg.push_nested_attr(nix::libc::IFLA_LINKINFO, |msg| {
            msg.push_attr_bytes(nix::libc::IFLA_INFO_KIND, b"veth\0");
            msg.push_nested_attr(nix::libc::IFLA_INFO_DATA, |msg| {
                msg.push_nested_attr(VETH_INFO_PEER, |msg| {
                    let peer_ifinfo = IfInfoMsg {
                        ifi_family: nix::libc::AF_UNSPEC as u8,
                        __ifi_pad: 0,
                        ifi_type: 0,
                        ifi_index: 0,
                        ifi_flags: 0,
                        ifi_change: u32::MAX,
                    };
                    msg.push_value(&peer_ifinfo);
                    msg.push_attr_bytes(
                        nix::libc::IFLA_IFNAME,
                        cstring_bytes(peer_ifname)?.as_slice(),
                    );
                    Ok(())
                })
            })
        })?;
        send_netlink_request(socket, seq, &msg.bytes).with_context(|| {
            format!("failed to create veth pair `{host_ifname}` <-> `{peer_ifname}`")
        })
    })
}

pub fn link_delete(iface: &str) -> Result<()> {
    let ifindex = interface_index(iface)?;
    with_netlink_route_socket(|socket, seq| {
        let mut msg = NetlinkMessage::new(
            nix::libc::RTM_DELLINK,
            (nix::libc::NLM_F_REQUEST | nix::libc::NLM_F_ACK) as u16,
            seq,
        );
        let ifinfo = IfInfoMsg {
            ifi_family: nix::libc::AF_UNSPEC as u8,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: ifindex,
            ifi_flags: 0,
            ifi_change: u32::MAX,
        };
        msg.push_value(&ifinfo);
        send_netlink_request(socket, seq, &msg.bytes)
            .with_context(|| format!("failed to delete interface `{iface}`"))
    })
}

pub fn link_set_netns_pid(iface: &str, pid: i32) -> Result<()> {
    let ifindex = interface_index(iface)?;
    with_netlink_route_socket(|socket, seq| {
        let mut msg = NetlinkMessage::new(
            nix::libc::RTM_NEWLINK,
            (nix::libc::NLM_F_REQUEST | nix::libc::NLM_F_ACK) as u16,
            seq,
        );
        let ifinfo = IfInfoMsg {
            ifi_family: nix::libc::AF_UNSPEC as u8,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: ifindex,
            ifi_flags: 0,
            ifi_change: u32::MAX,
        };
        msg.push_value(&ifinfo);
        msg.push_attr_bytes(nix::libc::IFLA_NET_NS_PID, &pid.to_ne_bytes());
        send_netlink_request(socket, seq, &msg.bytes)
            .with_context(|| format!("failed to move interface `{iface}` into netns pid={pid}"))
    })
}

pub fn discover_egress_src_v4(destination: Ipv4Addr) -> Result<Ipv4Addr> {
    discover_egress_src_v4_with_iface(destination, None)
}

pub fn discover_egress_src_v4_on_iface(destination: Ipv4Addr, iface: &str) -> Result<Ipv4Addr> {
    discover_egress_src_v4_with_iface(destination, Some(iface))
}

fn discover_egress_src_v4_with_iface(
    destination: Ipv4Addr,
    iface: Option<&str>,
) -> Result<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .context("failed to bind an IPv4 UDP socket for route discovery")?;
    if let Some(iface) = iface {
        bind_socket_to_device(&socket, iface).with_context(|| {
            format!("failed to bind IPv4 route discovery to interface `{iface}`")
        })?;
    }
    socket
        .connect(SocketAddr::from((destination, 80)))
        .with_context(|| format!("failed to probe IPv4 route toward `{destination}`"))?;
    match socket
        .local_addr()
        .context("failed to inspect the local IPv4 route-discovery socket")?
        .ip()
    {
        IpAddr::V4(ip) => Ok(ip),
        other => bail!("expected an IPv4 local address during route discovery, got `{other}`"),
    }
}

pub fn discover_egress_src_v6(destination: Ipv6Addr) -> Result<Ipv6Addr> {
    discover_egress_src_v6_with_iface(destination, None)
}

pub fn discover_egress_src_v6_on_iface(destination: Ipv6Addr, iface: &str) -> Result<Ipv6Addr> {
    discover_egress_src_v6_with_iface(destination, Some(iface))
}

fn discover_egress_src_v6_with_iface(
    destination: Ipv6Addr,
    iface: Option<&str>,
) -> Result<Ipv6Addr> {
    let socket = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))
        .context("failed to bind an IPv6 UDP socket for route discovery")?;
    if let Some(iface) = iface {
        bind_socket_to_device(&socket, iface).with_context(|| {
            format!("failed to bind IPv6 route discovery to interface `{iface}`")
        })?;
    }
    socket
        .connect(SocketAddr::from((destination, 80)))
        .with_context(|| format!("failed to probe IPv6 route toward `{destination}`"))?;
    match socket
        .local_addr()
        .context("failed to inspect the local IPv6 route-discovery socket")?
        .ip()
    {
        IpAddr::V6(ip) => Ok(ip),
        other => bail!("expected an IPv6 local address during route discovery, got `{other}`"),
    }
}

pub fn discover_interface_for_source_ip(source_ip: IpAddr) -> Result<String> {
    let interface = pnet_datalink::interfaces()
        .into_iter()
        .find(|iface| iface.ips.iter().any(|network| network.ip() == source_ip))
        .ok_or_else(|| anyhow::anyhow!("no interface found that owns source IP `{source_ip}`"))?;
    Ok(interface.name)
}

fn open_control_socket() -> Result<OwnedFd> {
    open_control_socket_for_family(nix::libc::AF_INET)
}

fn bind_socket_to_device(socket: &UdpSocket, iface: &str) -> Result<()> {
    let iface = CString::new(iface)
        .with_context(|| format!("interface name `{iface}` contains an interior NUL byte"))?;
    let rc = unsafe {
        // SAFETY: `socket` is valid and `iface` points to a stable NUL-terminated byte string.
        nix::libc::setsockopt(
            socket.as_raw_fd(),
            nix::libc::SOL_SOCKET,
            nix::libc::SO_BINDTODEVICE,
            iface.as_ptr().cast(),
            (iface.as_bytes_with_nul().len()) as nix::libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error())).with_context(|| {
            format!(
                "failed to bind socket to interface `{}`",
                iface.to_string_lossy()
            )
        });
    }
    Ok(())
}

fn open_control_socket_for_family(family: nix::libc::c_int) -> Result<OwnedFd> {
    let fd = unsafe {
        // SAFETY: `socket` does not dereference user pointers. We validate the returned fd below.
        nix::libc::socket(family, nix::libc::SOCK_DGRAM | nix::libc::SOCK_CLOEXEC, 0)
    };
    if fd < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error())).with_context(|| {
            format!("failed to open a control socket for interface configuration (family={family})")
        });
    }

    Ok(unsafe {
        // SAFETY: `fd` is a fresh owned descriptor returned by `socket`.
        OwnedFd::from_raw_fd(fd)
    })
}

fn interface_index(name: &str) -> Result<i32> {
    let c_name = CString::new(name)
        .with_context(|| format!("interface name `{name}` contains an interior NUL byte"))?;
    let index = unsafe {
        // SAFETY: `c_name` is a valid NUL-terminated interface name string.
        nix::libc::if_nametoindex(c_name.as_ptr())
    };
    if index == 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .with_context(|| format!("failed to resolve interface index for `{name}`"));
    }
    Ok(index as i32)
}

fn named_ifreq(name: &str) -> Result<nix::libc::ifreq> {
    if name.is_empty() {
        bail!("interface name must not be empty");
    }
    if name.len() >= nix::libc::IFNAMSIZ {
        bail!(
            "interface name `{name}` is too long for Linux IFNAMSIZ={}",
            nix::libc::IFNAMSIZ
        );
    }

    let mut ifreq = nix::libc::ifreq {
        ifr_name: [0; nix::libc::IFNAMSIZ],
        ifr_ifru: unsafe {
            // SAFETY: zero initialization is valid for the `ifreq` union before the kernel fills
            // or reads the relevant field.
            std::mem::zeroed()
        },
    };
    for (idx, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[idx] = *byte as nix::libc::c_char;
    }
    Ok(ifreq)
}

fn named_ifreq_with_sockaddr(
    name: &str,
    sockaddr: nix::libc::sockaddr,
) -> Result<nix::libc::ifreq> {
    let mut ifreq = named_ifreq(name)?;
    ifreq.ifr_ifru.ifru_addr = sockaddr;
    Ok(ifreq)
}

fn sockaddr_for_ipv4(ip: Ipv4Addr) -> nix::libc::sockaddr {
    let sockaddr_in = nix::libc::sockaddr_in {
        sin_family: nix::libc::AF_INET as nix::libc::sa_family_t,
        sin_port: 0,
        sin_addr: nix::libc::in_addr {
            // `sockaddr_in` is passed to the kernel as raw bytes. Using native-endian assembly
            // preserves the network-order octets in memory on little-endian hosts.
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    };
    unsafe {
        // SAFETY: Linux `sockaddr` and `sockaddr_in` share the same memory layout prefix for
        // AF_INET socket addresses, and `sockaddr_in` is fully initialized above.
        std::mem::transmute(sockaddr_in)
    }
}

fn in6_addr_for_ipv6(ip: Ipv6Addr) -> nix::libc::in6_addr {
    nix::libc::in6_addr {
        s6_addr: ip.octets(),
    }
}

fn prefix_len_to_netmask_v4(prefix_len: u8) -> Result<Ipv4Addr> {
    if prefix_len > 32 {
        bail!("IPv4 prefix length must be <= 32, got {prefix_len}");
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ok(Ipv4Addr::from(mask.to_be_bytes()))
}

fn add_policy_rule(family: u8, fwmark: u32, table: u32, priority: u32) -> Result<()> {
    with_netlink_route_socket(|socket, seq| {
        let mut msg = NetlinkMessage::new(
            nix::libc::RTM_NEWRULE,
            (nix::libc::NLM_F_REQUEST
                | nix::libc::NLM_F_CREATE
                | nix::libc::NLM_F_EXCL
                | nix::libc::NLM_F_ACK) as u16,
            seq,
        );
        let rule = FibRuleHdr {
            family,
            dst_len: 0,
            src_len: 0,
            tos: 0,
            table: table_header_value(table),
            res1: 0,
            res2: 0,
            action: FR_ACT_TO_TBL,
            flags: 0,
        };
        msg.push_value(&rule);
        msg.push_attr_bytes(FRA_FWMARK, &fwmark.to_ne_bytes());
        msg.push_attr_bytes(FRA_FWMASK, &u32::MAX.to_ne_bytes());
        msg.push_attr_bytes(FRA_PRIORITY, &priority.to_ne_bytes());
        msg.push_attr_bytes(FRA_TABLE, &table.to_ne_bytes());
        send_netlink_request(socket, seq, &msg.bytes).with_context(|| {
            format!(
                "failed to install policy rule for family={family} fwmark={fwmark:#x} table={table} priority={priority}"
            )
        })
    })
}

fn delete_policy_rule(family: u8, fwmark: u32, table: u32, priority: u32) -> Result<()> {
    with_netlink_route_socket(|socket, seq| {
        let mut msg = NetlinkMessage::new(
            nix::libc::RTM_DELRULE,
            (nix::libc::NLM_F_REQUEST | nix::libc::NLM_F_ACK) as u16,
            seq,
        );
        let rule = FibRuleHdr {
            family,
            dst_len: 0,
            src_len: 0,
            tos: 0,
            table: table_header_value(table),
            res1: 0,
            res2: 0,
            action: FR_ACT_TO_TBL,
            flags: 0,
        };
        msg.push_value(&rule);
        msg.push_attr_bytes(FRA_FWMARK, &fwmark.to_ne_bytes());
        msg.push_attr_bytes(FRA_FWMASK, &u32::MAX.to_ne_bytes());
        msg.push_attr_bytes(FRA_PRIORITY, &priority.to_ne_bytes());
        msg.push_attr_bytes(FRA_TABLE, &table.to_ne_bytes());
        send_netlink_request(socket, seq, &msg.bytes).with_context(|| {
            format!(
                "failed to remove policy rule for family={family} fwmark={fwmark:#x} table={table} priority={priority}"
            )
        })
    })
}

fn add_default_route_v4(iface: &str, gateway: Option<Ipv4Addr>, table: u32) -> Result<()> {
    change_default_route_v4(nix::libc::RTM_NEWROUTE, true, iface, gateway, table)
}

fn delete_default_route_v4(iface: &str, gateway: Option<Ipv4Addr>, table: u32) -> Result<()> {
    change_default_route_v4(nix::libc::RTM_DELROUTE, false, iface, gateway, table)
}

fn change_default_route_v4(
    msg_type: u16,
    create: bool,
    iface: &str,
    gateway: Option<Ipv4Addr>,
    table: u32,
) -> Result<()> {
    let ifindex = interface_index(iface)? as u32;
    with_netlink_route_socket(|socket, seq| {
        let mut msg = NetlinkMessage::new(
            msg_type,
            ((nix::libc::NLM_F_REQUEST | nix::libc::NLM_F_ACK)
                | if create {
                    nix::libc::NLM_F_CREATE | nix::libc::NLM_F_EXCL
                } else {
                    0
                }) as u16,
            seq,
        );
        let rtmsg = RtMsg {
            rtm_family: nix::libc::AF_INET as u8,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: table_header_value(table),
            rtm_protocol: nix::libc::RTPROT_BOOT,
            rtm_scope: if gateway.is_some() {
                nix::libc::RT_SCOPE_UNIVERSE
            } else {
                nix::libc::RT_SCOPE_LINK
            },
            rtm_type: nix::libc::RTN_UNICAST,
            rtm_flags: 0,
        };
        msg.push_value(&rtmsg);
        maybe_push_table_attr(&mut msg, table);
        if let Some(gateway) = gateway {
            msg.push_attr_bytes(nix::libc::RTA_GATEWAY, &gateway.octets());
        }
        msg.push_attr_bytes(nix::libc::RTA_OIF, &ifindex.to_ne_bytes());
        send_netlink_request(socket, seq, &msg.bytes).with_context(|| {
            format!(
                "failed to {} IPv4 default route on `{iface}` in table {table}",
                if create { "install" } else { "remove" }
            )
        })
    })
}

fn add_default_route_v6(iface: &str, gateway: Option<Ipv6Addr>, table: u32) -> Result<()> {
    change_default_route_v6(nix::libc::RTM_NEWROUTE, true, iface, gateway, table)
}

fn delete_default_route_v6(iface: &str, gateway: Option<Ipv6Addr>, table: u32) -> Result<()> {
    change_default_route_v6(nix::libc::RTM_DELROUTE, false, iface, gateway, table)
}

fn change_default_route_v6(
    msg_type: u16,
    create: bool,
    iface: &str,
    gateway: Option<Ipv6Addr>,
    table: u32,
) -> Result<()> {
    let ifindex = interface_index(iface)? as u32;
    with_netlink_route_socket(|socket, seq| {
        let mut msg = NetlinkMessage::new(
            msg_type,
            ((nix::libc::NLM_F_REQUEST | nix::libc::NLM_F_ACK)
                | if create {
                    nix::libc::NLM_F_CREATE | nix::libc::NLM_F_EXCL
                } else {
                    0
                }) as u16,
            seq,
        );
        let rtmsg = RtMsg {
            rtm_family: nix::libc::AF_INET6 as u8,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: table_header_value(table),
            rtm_protocol: nix::libc::RTPROT_BOOT,
            rtm_scope: if gateway.is_some() {
                nix::libc::RT_SCOPE_UNIVERSE
            } else {
                nix::libc::RT_SCOPE_LINK
            },
            rtm_type: nix::libc::RTN_UNICAST,
            rtm_flags: 0,
        };
        msg.push_value(&rtmsg);
        maybe_push_table_attr(&mut msg, table);
        if let Some(gateway) = gateway {
            msg.push_attr_bytes(nix::libc::RTA_GATEWAY, &gateway.octets());
        }
        msg.push_attr_bytes(nix::libc::RTA_OIF, &ifindex.to_ne_bytes());
        send_netlink_request(socket, seq, &msg.bytes).with_context(|| {
            format!(
                "failed to {} IPv6 default route on `{iface}` in table {table}",
                if create { "install" } else { "remove" }
            )
        })
    })
}

fn add_local_route_v4(table: u32) -> Result<()> {
    change_local_route_v4(nix::libc::RTM_NEWROUTE, true, table)
}

fn delete_local_route_v4(table: u32) -> Result<()> {
    change_local_route_v4(nix::libc::RTM_DELROUTE, false, table)
}

fn change_local_route_v4(msg_type: u16, create: bool, table: u32) -> Result<()> {
    let lo_index = interface_index("lo")? as u32;
    with_netlink_route_socket(|socket, seq| {
        let mut msg = NetlinkMessage::new(
            msg_type,
            ((nix::libc::NLM_F_REQUEST | nix::libc::NLM_F_ACK)
                | if create {
                    nix::libc::NLM_F_CREATE | nix::libc::NLM_F_EXCL
                } else {
                    0
                }) as u16,
            seq,
        );
        let rtmsg = RtMsg {
            rtm_family: nix::libc::AF_INET as u8,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: table_header_value(table),
            rtm_protocol: nix::libc::RTPROT_BOOT,
            rtm_scope: nix::libc::RT_SCOPE_HOST,
            rtm_type: nix::libc::RTN_LOCAL,
            rtm_flags: 0,
        };
        msg.push_value(&rtmsg);
        maybe_push_table_attr(&mut msg, table);
        msg.push_attr_bytes(nix::libc::RTA_OIF, &lo_index.to_ne_bytes());
        send_netlink_request(socket, seq, &msg.bytes).with_context(|| {
            format!(
                "failed to {} IPv4 local route in table {table}",
                if create { "install" } else { "remove" }
            )
        })
    })
}

fn add_local_route_v6(table: u32) -> Result<()> {
    change_local_route_v6(nix::libc::RTM_NEWROUTE, true, table)
}

fn delete_local_route_v6(table: u32) -> Result<()> {
    change_local_route_v6(nix::libc::RTM_DELROUTE, false, table)
}

fn change_local_route_v6(msg_type: u16, create: bool, table: u32) -> Result<()> {
    let lo_index = interface_index("lo")? as u32;
    with_netlink_route_socket(|socket, seq| {
        let mut msg = NetlinkMessage::new(
            msg_type,
            ((nix::libc::NLM_F_REQUEST | nix::libc::NLM_F_ACK)
                | if create {
                    nix::libc::NLM_F_CREATE | nix::libc::NLM_F_EXCL
                } else {
                    0
                }) as u16,
            seq,
        );
        let rtmsg = RtMsg {
            rtm_family: nix::libc::AF_INET6 as u8,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: table_header_value(table),
            rtm_protocol: nix::libc::RTPROT_BOOT,
            rtm_scope: nix::libc::RT_SCOPE_HOST,
            rtm_type: nix::libc::RTN_LOCAL,
            rtm_flags: 0,
        };
        msg.push_value(&rtmsg);
        maybe_push_table_attr(&mut msg, table);
        msg.push_attr_bytes(nix::libc::RTA_OIF, &lo_index.to_ne_bytes());
        send_netlink_request(socket, seq, &msg.bytes).with_context(|| {
            format!(
                "failed to {} IPv6 local route in table {table}",
                if create { "install" } else { "remove" }
            )
        })
    })
}

fn with_netlink_route_socket<T>(f: impl FnOnce(&OwnedFd, u32) -> Result<T>) -> Result<T> {
    let socket = open_netlink_route_socket()?;
    let seq = run_netlink_seq();
    f(&socket, seq)
}

fn open_netlink_route_socket() -> Result<OwnedFd> {
    let fd = unsafe {
        // SAFETY: `socket` does not dereference user pointers. We validate the returned fd below.
        nix::libc::socket(
            nix::libc::AF_NETLINK,
            nix::libc::SOCK_RAW | nix::libc::SOCK_CLOEXEC,
            nix::libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .context("failed to open a NETLINK_ROUTE socket");
    }

    let socket = unsafe {
        // SAFETY: `fd` is a fresh owned descriptor returned by `socket`.
        OwnedFd::from_raw_fd(fd)
    };
    let mut addr: nix::libc::sockaddr_nl = unsafe {
        // SAFETY: zeroed initialization is valid for `sockaddr_nl` before filling fields.
        mem::zeroed()
    };
    addr.nl_family = nix::libc::AF_NETLINK as nix::libc::sa_family_t;
    let rc = unsafe {
        // SAFETY: `socket` is valid and `addr` points to initialized local storage.
        nix::libc::bind(
            socket.as_raw_fd(),
            (&addr as *const nix::libc::sockaddr_nl).cast(),
            mem::size_of::<nix::libc::sockaddr_nl>() as nix::libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .context("failed to bind the NETLINK_ROUTE socket");
    }

    Ok(socket)
}

fn send_netlink_request(socket: &OwnedFd, seq: u32, message: &[u8]) -> Result<()> {
    let mut addr: nix::libc::sockaddr_nl = unsafe {
        // SAFETY: zeroed initialization is valid for `sockaddr_nl` before filling fields.
        mem::zeroed()
    };
    addr.nl_family = nix::libc::AF_NETLINK as nix::libc::sa_family_t;

    let rc = unsafe {
        // SAFETY: `socket` is valid, `message` points to initialized bytes, and `addr` is a valid
        // netlink destination address for the kernel.
        nix::libc::sendto(
            socket.as_raw_fd(),
            message.as_ptr().cast(),
            message.len(),
            0,
            (&addr as *const nix::libc::sockaddr_nl).cast(),
            mem::size_of::<nix::libc::sockaddr_nl>() as nix::libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .context("failed to send a netlink route request");
    }

    receive_netlink_ack(socket, seq)
}

fn receive_netlink_ack(socket: &OwnedFd, seq: u32) -> Result<()> {
    let mut buffer = vec![0_u8; 4096];
    let len = unsafe {
        // SAFETY: `socket` is valid and `buffer` points to writable storage for the kernel.
        nix::libc::recv(
            socket.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            0,
        )
    };
    if len < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .context("failed to receive a netlink route reply");
    }
    let len = len as usize;
    let mut offset = 0usize;
    while offset + mem::size_of::<nix::libc::nlmsghdr>() <= len {
        let header = unsafe {
            // SAFETY: bounds checked above and netlink headers are aligned to 4 bytes.
            &*(buffer[offset..].as_ptr().cast::<nix::libc::nlmsghdr>())
        };
        if header.nlmsg_len as usize > len - offset || header.nlmsg_len == 0 {
            bail!("received a malformed netlink reply");
        }
        if header.nlmsg_seq != seq {
            offset += nlmsg_align(header.nlmsg_len as usize);
            continue;
        }
        match header.nlmsg_type as i32 {
            nix::libc::NLMSG_ERROR => {
                if (header.nlmsg_len as usize)
                    < mem::size_of::<nix::libc::nlmsghdr>() + mem::size_of::<nix::libc::nlmsgerr>()
                {
                    bail!("received a truncated netlink error reply");
                }
                let err = unsafe {
                    // SAFETY: size validated above.
                    &*(buffer[offset + mem::size_of::<nix::libc::nlmsghdr>()..]
                        .as_ptr()
                        .cast::<nix::libc::nlmsgerr>())
                };
                if err.error == 0 {
                    return Ok(());
                }
                return Err(anyhow::Error::from(std::io::Error::from_raw_os_error(
                    -err.error,
                )))
                .context("kernel rejected the netlink route request");
            }
            x if x == nix::libc::NLMSG_DONE => return Ok(()),
            _ => {
                offset += nlmsg_align(header.nlmsg_len as usize);
            }
        }
    }

    bail!("did not receive a netlink ACK from the kernel")
}

fn run_netlink_seq() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_nanos() & 0xffff_ffff) as u32)
        .unwrap_or(1)
}

struct NetlinkMessage {
    bytes: Vec<u8>,
}

impl NetlinkMessage {
    fn new(msg_type: u16, flags: u16, seq: u32) -> Self {
        let header = nix::libc::nlmsghdr {
            nlmsg_len: mem::size_of::<nix::libc::nlmsghdr>() as u32,
            nlmsg_type: msg_type,
            nlmsg_flags: flags,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        };
        let mut bytes = Vec::with_capacity(256);
        push_bytes(&mut bytes, &header);
        Self { bytes }
    }

    fn push_value<T>(&mut self, value: &T) {
        push_bytes(&mut self.bytes, value);
        self.refresh_len();
    }

    fn push_attr_bytes(&mut self, kind: u16, value: &[u8]) {
        let header = RtAttr {
            rta_len: (mem::size_of::<RtAttr>() + value.len()) as u16,
            rta_type: kind,
        };
        push_bytes(&mut self.bytes, &header);
        self.bytes.extend_from_slice(value);
        let aligned_len = rta_align(header.rta_len as usize);
        if aligned_len > header.rta_len as usize {
            self.bytes.resize(
                self.bytes.len() + (aligned_len - header.rta_len as usize),
                0,
            );
        }
        self.refresh_len();
    }

    fn push_nested_attr(
        &mut self,
        kind: u16,
        f: impl FnOnce(&mut NetlinkMessage) -> Result<()>,
    ) -> Result<()> {
        let start = self.bytes.len();
        let header = RtAttr {
            rta_len: mem::size_of::<RtAttr>() as u16,
            rta_type: kind,
        };
        push_bytes(&mut self.bytes, &header);
        f(self)?;
        let payload_len = self.bytes.len() - start;
        let aligned_len = rta_align(payload_len);
        if aligned_len > payload_len {
            self.bytes
                .resize(self.bytes.len() + (aligned_len - payload_len), 0);
        }
        let header = unsafe {
            // SAFETY: `start` points to the nested attribute header we just wrote.
            &mut *(self.bytes[start..].as_mut_ptr().cast::<RtAttr>())
        };
        header.rta_len = payload_len as u16;
        self.refresh_len();
        Ok(())
    }

    fn refresh_len(&mut self) {
        let len = self.bytes.len() as u32;
        let header = unsafe {
            // SAFETY: `bytes` always starts with `nlmsghdr` from `new`.
            &mut *(self.bytes.as_mut_ptr().cast::<nix::libc::nlmsghdr>())
        };
        header.nlmsg_len = len;
    }
}

fn push_bytes<T>(bytes: &mut Vec<u8>, value: &T) {
    let len = mem::size_of::<T>();
    let ptr = (value as *const T).cast::<u8>();
    let slice = unsafe {
        // SAFETY: `value` points to `len` initialized bytes that remain valid for this copy.
        std::slice::from_raw_parts(ptr, len)
    };
    bytes.extend_from_slice(slice);
}

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

fn rta_align(len: usize) -> usize {
    (len + 3) & !3
}

fn table_header_value(table: u32) -> u8 {
    u8::try_from(table).unwrap_or(nix::libc::RT_TABLE_UNSPEC)
}

fn maybe_push_table_attr(msg: &mut NetlinkMessage, table: u32) {
    if table > u32::from(u8::MAX) {
        msg.push_attr_bytes(nix::libc::RTA_TABLE, &table.to_ne_bytes());
    }
}

fn named_arpreq(iface: &str, neighbor: Ipv4Addr, mac: &str) -> Result<nix::libc::arpreq> {
    let mac = parse_mac(mac)?;
    let mut req = nix::libc::arpreq {
        arp_pa: sockaddr_for_ipv4(neighbor),
        arp_ha: sockaddr_for_mac(mac),
        arp_flags: nix::libc::ATF_COM | nix::libc::ATF_PERM,
        arp_netmask: zero_sockaddr(),
        arp_dev: [0; 16],
    };
    if iface.is_empty() {
        bail!("interface name must not be empty");
    }
    if iface.len() >= req.arp_dev.len() {
        bail!(
            "interface name `{iface}` is too long for arpreq device field size={}",
            req.arp_dev.len()
        );
    }
    for (idx, byte) in iface.as_bytes().iter().enumerate() {
        req.arp_dev[idx] = *byte as nix::libc::c_char;
    }
    Ok(req)
}

fn sockaddr_for_mac(mac: [u8; 6]) -> nix::libc::sockaddr {
    let mut sockaddr = zero_sockaddr();
    sockaddr.sa_family = nix::libc::ARPHRD_ETHER as nix::libc::sa_family_t;
    for (idx, byte) in mac.iter().enumerate() {
        sockaddr.sa_data[idx] = *byte as nix::libc::c_char;
    }
    sockaddr
}

fn default_route_entry_v4(gateway: Ipv4Addr, iface: &CString) -> nix::libc::rtentry {
    nix::libc::rtentry {
        rt_pad1: 0,
        rt_dst: sockaddr_for_ipv4(Ipv4Addr::UNSPECIFIED),
        rt_gateway: sockaddr_for_ipv4(gateway),
        rt_genmask: sockaddr_for_ipv4(Ipv4Addr::UNSPECIFIED),
        rt_flags: (nix::libc::RTF_UP | nix::libc::RTF_GATEWAY) as nix::libc::c_ushort,
        rt_pad2: 0,
        rt_pad3: 0,
        rt_tos: 0,
        rt_class: 0,
        rt_pad4: [0; 3],
        rt_metric: 0,
        rt_dev: iface.as_ptr() as *mut nix::libc::c_char,
        rt_mtu: 0,
        rt_window: 0,
        rt_irtt: 0,
    }
}

fn zero_sockaddr() -> nix::libc::sockaddr {
    nix::libc::sockaddr {
        sa_family: 0,
        sa_data: [0; 14],
    }
}

fn parse_mac(mac: &str) -> Result<[u8; 6]> {
    let parts = mac.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        bail!("MAC address `{mac}` must contain 6 octets");
    }
    let mut bytes = [0_u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            bail!("MAC address `{mac}` contains a non-2-digit octet `{part}`");
        }
        bytes[idx] = u8::from_str_radix(part, 16)
            .with_context(|| format!("failed to parse MAC address octet `{part}` in `{mac}`"))?;
    }
    Ok(bytes)
}

fn cstring_bytes(value: &str) -> Result<Vec<u8>> {
    let value = CString::new(value)
        .with_context(|| format!("interface name `{value}` contains an interior NUL byte"))?;
    Ok(value.as_bytes_with_nul().to_vec())
}
