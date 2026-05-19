// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};

pub(crate) const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_A: u16 = 1;
const DNS_CLASS_IN: u16 = 1;
const DNS_HEADER_LEN: usize = 12;

pub(crate) fn dns_query_type(payload: &[u8]) -> Option<u16> {
    if payload.len() < DNS_HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount != 1 {
        return None;
    }
    let question_end = dns_question_end(payload)?;
    let qtype_offset = question_end.checked_sub(4)?;
    Some(u16::from_be_bytes([
        payload[qtype_offset],
        payload[qtype_offset + 1],
    ]))
}

pub(crate) fn dns_query_name(payload: &[u8]) -> Option<String> {
    if payload.len() < DNS_HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount != 1 {
        return None;
    }

    let mut offset = DNS_HEADER_LEN;
    let mut labels = Vec::new();
    while offset < payload.len() {
        let label_len = payload[offset] as usize;
        offset += 1;
        if label_len == 0 {
            return (!labels.is_empty()).then(|| labels.join(".").to_ascii_lowercase());
        }
        let end = offset.checked_add(label_len)?;
        let label = std::str::from_utf8(payload.get(offset..end)?).ok()?;
        labels.push(label.to_string());
        offset = end;
    }
    None
}

pub(crate) fn dns_answer_ips(payload: &[u8]) -> Vec<IpAddr> {
    if payload.len() < DNS_HEADER_LEN {
        return Vec::new();
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;

    let mut offset = DNS_HEADER_LEN;
    for _ in 0..qdcount {
        let Some(next) = dns_name_end(payload, offset) else {
            return Vec::new();
        };
        let Some(question_end) = next.checked_add(4) else {
            return Vec::new();
        };
        if question_end > payload.len() {
            return Vec::new();
        }
        offset = question_end;
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        let Some(next) = dns_name_end(payload, offset) else {
            break;
        };
        let Some(header_end) = next.checked_add(10) else {
            break;
        };
        if header_end > payload.len() {
            break;
        }

        let rr_type = u16::from_be_bytes([payload[next], payload[next + 1]]);
        let rr_class = u16::from_be_bytes([payload[next + 2], payload[next + 3]]);
        let rdlength = u16::from_be_bytes([payload[next + 8], payload[next + 9]]) as usize;
        let rdata_start = header_end;
        let Some(rdata_end) = rdata_start.checked_add(rdlength) else {
            break;
        };
        if rdata_end > payload.len() {
            break;
        }

        if rr_class == DNS_CLASS_IN {
            match (rr_type, rdlength) {
                (DNS_TYPE_A, 4) => {
                    ips.push(IpAddr::V4(Ipv4Addr::new(
                        payload[rdata_start],
                        payload[rdata_start + 1],
                        payload[rdata_start + 2],
                        payload[rdata_start + 3],
                    )));
                }
                (DNS_TYPE_AAAA, 16) => {
                    let mut octets = [0_u8; 16];
                    octets.copy_from_slice(&payload[rdata_start..rdata_end]);
                    ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }

        offset = rdata_end;
    }

    ips
}

pub(crate) fn synthesize_empty_dns_response(query: &[u8]) -> Result<Vec<u8>> {
    let question_end = dns_question_end(query).context("failed to parse DNS question")?;
    let mut response = query[..question_end].to_vec();
    let flags = u16::from_be_bytes([response[2], response[3]]);
    let response_flags = (flags | 0x8000 | 0x0080) & !0x0200;
    response[2..4].copy_from_slice(&response_flags.to_be_bytes());
    response[6..8].copy_from_slice(&0_u16.to_be_bytes());
    response[8..10].copy_from_slice(&0_u16.to_be_bytes());
    response[10..12].copy_from_slice(&0_u16.to_be_bytes());
    Ok(response)
}

fn dns_question_end(payload: &[u8]) -> Option<usize> {
    let mut offset = DNS_HEADER_LEN;
    while offset < payload.len() {
        let label_len = payload[offset] as usize;
        offset += 1;
        if label_len == 0 {
            return offset.checked_add(4).filter(|end| *end <= payload.len());
        }
        offset = offset.checked_add(label_len)?;
    }
    None
}

fn dns_name_end(payload: &[u8], start: usize) -> Option<usize> {
    let mut offset = start;
    while offset < payload.len() {
        let len = payload[offset];
        if len & 0xC0 == 0xC0 {
            return offset.checked_add(2).filter(|end| *end <= payload.len());
        }
        offset += 1;
        if len == 0 {
            return Some(offset);
        }
        offset = offset.checked_add(len as usize)?;
    }
    None
}
