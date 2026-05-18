// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod args;
mod merge;
mod types;
mod validate;

#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::Parser;

use crate::network::NetworkBackend;
use crate::profile::Profile;

pub use self::args::Cli;
use self::args::RawCli;
use self::merge::merge_cli;
pub use self::types::{
    DefaultPolicy, DoctorFormat, OutputView, ProxyScheme, ProxySpec, ProxyType, ReportFormat,
    SummaryFormat,
};
use self::validate::validate_cli;

impl Cli {
    pub fn parse_effective() -> Result<Self> {
        Self::from_raw(RawCli::parse())
    }

    pub fn selected_backend(&self) -> NetworkBackend {
        if self.root {
            NetworkBackend::Rootful
        } else {
            self.network_backend
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_cli(self)
    }

    fn from_raw(raw: RawCli) -> Result<Self> {
        let profile = raw.profile.as_deref().map(Profile::load).transpose()?;
        Ok(merge_cli(raw, profile.as_ref()))
    }

    #[cfg(test)]
    fn parse_from<I, T>(itr: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::from_raw(RawCli::parse_from(itr)).unwrap()
    }
}
