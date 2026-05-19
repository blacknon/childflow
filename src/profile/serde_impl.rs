use serde::{Deserialize, Serializer};

use crate::cli::ProxySpec;

pub(crate) fn deserialize_optional_proxy_spec<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<ProxySpec>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|raw| raw.parse::<ProxySpec>().map_err(serde::de::Error::custom))
        .transpose()
}

pub(crate) fn serialize_optional_proxy_spec<S>(
    value: &Option<ProxySpec>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(spec) => serializer.serialize_some(&spec.to_string()),
        None => serializer.serialize_none(),
    }
}
