#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyEnvVar {
    pub key: String,
    pub value: String,
}

impl ProxyEnvVar {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}
