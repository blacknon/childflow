// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

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