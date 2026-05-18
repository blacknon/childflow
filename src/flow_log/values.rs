use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsAnswerMode {
    Relayed,
    SyntheticEmpty,
}

impl DnsAnswerMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Relayed => "relayed",
            Self::SyntheticEmpty => "synthetic_empty",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectResultStatus {
    Ok,
    Error,
}

impl ConnectResultStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

pub struct PolicyViolationEvent<'a> {
    pub protocol: &'static str,
    pub remote: &'a str,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub reason_code: &'static str,
    pub control: &'static str,
    pub matched_cidr: Option<&'a str>,
    pub matched_domain: Option<&'a str>,
    pub reason: &'a str,
}

pub struct RuntimeFailureEvent<'a> {
    pub phase: &'a str,
    pub reason_code: &'a str,
    pub detail: &'a str,
}
