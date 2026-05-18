use anyhow::{Error, Result};

use crate::cli::Cli;
use crate::flow_log;
use crate::profile::Profile;
use crate::runtime_failure;
use crate::util;

mod run;

pub(crate) fn real_main() -> Result<i32> {
    let cli = Cli::parse_effective()?;
    if let Some(exit_code) = dispatch_immediate(&cli)? {
        return Ok(exit_code);
    }

    if let Err(err) = cli.validate() {
        log_runtime_failure_event(&cli, "cli_validate", &err);
        return Err(err);
    }
    if let Err(err) = crate::preflight::run(&cli) {
        log_runtime_failure_event(&cli, "preflight", &err);
        return Err(err);
    }
    match run::run_command_tree(&cli) {
        Ok(code) => Ok(code),
        Err(err) => {
            log_runtime_failure_event(&cli, "run", &err);
            Err(err)
        }
    }
}

fn dispatch_immediate(cli: &Cli) -> Result<Option<i32>> {
    if cli.dump_profile {
        print!("{}", Profile::from_cli(cli).render_toml()?);
        return Ok(Some(0));
    }

    if cli.doctor {
        return crate::doctor::run(cli).map(Some);
    }

    if cli.report.is_some() {
        return crate::report::run(cli).map(Some);
    }

    Ok(None)
}

fn log_runtime_failure_event(cli: &Cli, phase: &str, err: &Error) {
    let Some(path) = cli.flow_log.as_deref() else {
        return;
    };

    let reason_code = runtime_failure::classify_or_unknown(err);
    let detail = format!("{err:#}");
    if let Err(log_err) = flow_log::append_runtime_failure(
        path,
        flow_log::RuntimeFailureEvent {
            phase,
            reason_code: reason_code.as_str(),
            detail: &detail,
        },
    ) {
        util::debug(format!(
            "failed to append runtime failure event to {}: {log_err:#}",
            path.display()
        ));
    }
}
