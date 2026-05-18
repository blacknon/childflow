// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod dns;
mod tcp;
mod udp;

#[cfg(test)]
mod tests;

pub(super) use self::dns::{
    dns_answer_ips, dns_query_name, dns_query_type, synthesize_empty_dns_response, DNS_TYPE_AAAA,
};
pub(super) use self::tcp::connect_remote;
pub(super) use self::udp::{relay_dns_udp, relay_udp_payload, UdpRelayOutcome};
