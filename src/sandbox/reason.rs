use std::borrow::Cow;

use ipnetwork::IpNetwork;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockReason {
    Offline,
    Metadata,
    Private,
    DeniedCidr(IpNetwork),
    DeniedExactDomain(String),
    DeniedDomain(String),
    DefaultDeny,
    ProxyOnly,
}

impl BlockReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Metadata => "metadata",
            Self::Private => "private",
            Self::DeniedCidr(_) => "deny_cidr",
            Self::DeniedExactDomain(_) => "deny_domain_exact",
            Self::DeniedDomain(_) => "deny_domain",
            Self::DefaultDeny => "default_deny",
            Self::ProxyOnly => "proxy_only",
        }
    }

    pub fn control(&self) -> &'static str {
        match self {
            Self::Offline => "--offline",
            Self::Metadata => "--block-metadata",
            Self::Private => "--block-private",
            Self::DeniedCidr(_) => "--deny-cidr",
            Self::DeniedExactDomain(_) => "--deny-domain-exact",
            Self::DeniedDomain(_) => "--deny-domain",
            Self::DefaultDeny => "--default-policy",
            Self::ProxyOnly => "--proxy-only",
        }
    }

    pub fn matched_cidr(&self) -> Option<IpNetwork> {
        match self {
            Self::DeniedCidr(cidr) => Some(*cidr),
            _ => None,
        }
    }

    pub fn matched_domain(&self) -> Option<&str> {
        match self {
            Self::DeniedExactDomain(domain) | Self::DeniedDomain(domain) => Some(domain.as_str()),
            _ => None,
        }
    }

    pub fn describe(&self) -> Cow<'static, str> {
        match self {
            Self::Offline => Cow::Borrowed("blocked by `--offline`"),
            Self::Metadata => Cow::Borrowed("blocked by `--block-metadata`"),
            Self::Private => Cow::Borrowed("blocked by `--block-private`"),
            Self::DeniedCidr(cidr) => Cow::Owned(format!("blocked by `--deny-cidr {cidr}`")),
            Self::DeniedExactDomain(domain) => {
                Cow::Owned(format!("blocked by `--deny-domain-exact {domain}`"))
            }
            Self::DeniedDomain(domain) => {
                Cow::Owned(format!("blocked by `--deny-domain {domain}`"))
            }
            Self::DefaultDeny => Cow::Borrowed("blocked by `--default-policy deny`"),
            Self::ProxyOnly => Cow::Borrowed("blocked by `--proxy-only`"),
        }
    }
}
