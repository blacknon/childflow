// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod build;
mod checksum;
mod parse;
mod types;

#[cfg(test)]
mod tests;

pub use self::build::{
    build_icmpv4_echo_frame, build_icmpv4_echo_ip_packet, build_icmpv4_error_frame,
    build_icmpv4_frame_from_message, build_icmpv4_ip_packet_from_message,
    build_icmpv4_message_from_parsed, build_icmpv6_echo_frame, build_icmpv6_echo_ip_packet,
    build_icmpv6_error_frame, build_icmpv6_frame_from_message, build_icmpv6_ip_packet_from_message,
    build_icmpv6_message_from_parsed, build_tcp_frame, build_udp_frame, build_udp_ip_packet,
};
pub(crate) use self::checksum::{
    icmpv6_checksum, internet_checksum, normalize_icmpv4_message, normalize_icmpv6_message,
};
pub use self::parse::parse_frame;
pub(crate) use self::types::IpKind;
pub use self::types::{
    Icmpv4EchoFrame, Icmpv4ErrorFrame, Icmpv6EchoFrame, Icmpv6ErrorFrame, PacketMeta,
    ParsedIcmpv4Packet, ParsedIcmpv6Packet, ParsedPacket, ParsedTcpPacket, ParsedUdpPacket,
    TcpReply,
};
