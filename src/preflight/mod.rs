// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

mod inspect;

#[cfg(test)]
mod tests;

use anyhow::{bail, Result};

use crate::cli::Cli;
use crate::network::NetworkBackend;

pub use self::inspect::find_missing_commands;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckStatus {
    Ok,
    Warning,
    Fatal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreflightCheck {
    pub label: String,
    pub status: CheckStatus,
    pub detail: String,
    pub hint: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PreflightReport {
    backend_name: String,
    checks: Vec<PreflightCheck>,
}

impl PreflightReport {
    pub(crate) fn new(backend_name: impl Into<String>) -> Self {
        Self {
            backend_name: backend_name.into(),
            checks: Vec::new(),
        }
    }

    pub(crate) fn push(
        &mut self,
        status: CheckStatus,
        label: impl Into<String>,
        detail: impl Into<String>,
        hint: Option<String>,
    ) {
        self.checks.push(PreflightCheck {
            label: label.into(),
            status,
            detail: detail.into(),
            hint,
        });
    }

    pub(crate) fn push_ok(&mut self, label: impl Into<String>, detail: impl Into<String>) {
        self.push(CheckStatus::Ok, label, detail, None);
    }

    pub(crate) fn push_warning(
        &mut self,
        label: impl Into<String>,
        detail: impl Into<String>,
        hint: impl Into<String>,
    ) {
        self.push(CheckStatus::Warning, label, detail, Some(hint.into()));
    }

    pub(crate) fn push_fatal(
        &mut self,
        label: impl Into<String>,
        detail: impl Into<String>,
        hint: impl Into<String>,
    ) {
        self.push(CheckStatus::Fatal, label, detail, Some(hint.into()));
    }

    pub fn backend_name(&self) -> &str {
        &self.backend_name
    }

    pub fn checks(&self) -> &[PreflightCheck] {
        &self.checks
    }

    pub fn has_fatal(&self) -> bool {
        self.checks
            .iter()
            .any(|check| matches!(check.status, CheckStatus::Fatal))
    }

    pub fn has_warnings(&self) -> bool {
        self.checks
            .iter()
            .any(|check| matches!(check.status, CheckStatus::Warning))
    }

    fn emit_warnings(&self) {
        for check in self
            .checks
            .iter()
            .filter(|check| matches!(check.status, CheckStatus::Warning))
        {
            crate::util::warn(format!("preflight: {}: {}", check.label, check.detail));
        }
    }

    fn finish(self) -> Result<()> {
        self.emit_warnings();

        if !self.has_fatal() {
            return Ok(());
        }

        let fatal = self
            .checks
            .iter()
            .filter(|check| matches!(check.status, CheckStatus::Fatal))
            .map(render_check)
            .collect::<Vec<_>>();

        bail!(
            "preflight checks failed for the `{}` backend:\n{}",
            self.backend_name,
            render_issue_list(&fatal)
        );
    }
}

pub fn run(cli: &Cli) -> Result<()> {
    inspect(cli.selected_backend(), cli.proxy.is_some()).finish()
}

pub fn inspect(backend: NetworkBackend, proxy_requested: bool) -> PreflightReport {
    inspect::inspect(backend, proxy_requested)
}

fn render_issue_list(issues: &[String]) -> String {
    issues
        .iter()
        .map(|issue| format!("- {issue}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_check(check: &PreflightCheck) -> String {
    match &check.hint {
        Some(hint) => format!("{}: {}. Hint: {}", check.label, check.detail, hint),
        None => format!("{}: {}", check.label, check.detail),
    }
}
