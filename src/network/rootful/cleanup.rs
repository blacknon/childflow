use std::fs;
use std::os::fd::AsFd;

use anyhow::{anyhow, Context, Result};
use nix::sched::{setns, CloneFlags};
use nix::unistd::Pid;

use crate::linux_net;
use crate::util::run_command;

pub(super) enum CleanupAction {
    RestoreFile {
        path: String,
        value: String,
    },
    RunIptables {
        label: &'static str,
        table: &'static str,
        args: Vec<String>,
    },
    RunIp6tables {
        label: &'static str,
        table: &'static str,
        args: Vec<String>,
    },
    DeletePolicyRuleV4 {
        fwmark: u32,
        table: u32,
        priority: u32,
    },
    DeletePolicyRuleV6 {
        fwmark: u32,
        table: u32,
        priority: u32,
    },
    DeleteDefaultRouteV4 {
        iface: String,
        gateway: Option<std::net::Ipv4Addr>,
        table: u32,
    },
    DeleteDefaultRouteV6 {
        iface: String,
        gateway: Option<std::net::Ipv6Addr>,
        table: u32,
    },
    DeleteLocalRouteV4 {
        table: u32,
    },
    DeleteLocalRouteV6 {
        table: u32,
    },
    DeleteLink {
        iface: String,
    },
}

pub(super) fn with_netns<T, F>(pid: Pid, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let original = fs::File::open("/proc/self/ns/net").context("failed to open current netns")?;
    let target_path = format!("/proc/{}/ns/net", pid.as_raw());
    let target = fs::File::open(&target_path)
        .with_context(|| format!("failed to open target netns {target_path}"))?;

    setns(target.as_fd(), CloneFlags::CLONE_NEWNET).context("setns(target) failed")?;
    let result = f();
    let restore = setns(original.as_fd(), CloneFlags::CLONE_NEWNET);

    match (result, restore) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(err)) => Err(anyhow!("failed to restore original netns: {err}")),
        (Err(err), Err(restore_err)) => Err(anyhow!(
            "{err:#}; additionally failed to restore original netns: {restore_err}"
        )),
    }
}

pub(super) fn run_cleanup_action(action: &CleanupAction) -> Result<()> {
    match action {
        CleanupAction::RestoreFile { path, value } => {
            fs::write(path, format!("{value}\n")).with_context(|| format!("cleanup `{path}`"))
        }
        CleanupAction::RunIptables { label, table, args } => run_iptables(table, args.to_vec())
            .map(|_| ())
            .with_context(|| format!("cleanup `{label}`")),
        CleanupAction::RunIp6tables { label, table, args } => run_ip6tables(table, args.to_vec())
            .map(|_| ())
            .with_context(|| format!("cleanup `{label}`")),
        CleanupAction::DeletePolicyRuleV4 {
            fwmark,
            table,
            priority,
        } => linux_net::policy_rule_del_v4(*fwmark, *table, *priority)
            .context("cleanup `remove IPv4 policy rule`"),
        CleanupAction::DeletePolicyRuleV6 {
            fwmark,
            table,
            priority,
        } => linux_net::policy_rule_del_v6(*fwmark, *table, *priority)
            .context("cleanup `remove IPv6 policy rule`"),
        CleanupAction::DeleteDefaultRouteV4 {
            iface,
            gateway,
            table,
        } => linux_net::route_del_default_v4_table(iface, *gateway, *table)
            .context("cleanup `remove IPv4 default route`"),
        CleanupAction::DeleteDefaultRouteV6 {
            iface,
            gateway,
            table,
        } => linux_net::route_del_default_v6_table(iface, *gateway, *table)
            .context("cleanup `remove IPv6 default route`"),
        CleanupAction::DeleteLocalRouteV4 { table } => {
            linux_net::route_del_local_v4_table(*table).context("cleanup `remove IPv4 local route`")
        }
        CleanupAction::DeleteLocalRouteV6 { table } => {
            linux_net::route_del_local_v6_table(*table).context("cleanup `remove IPv6 local route`")
        }
        CleanupAction::DeleteLink { iface } => {
            linux_net::link_delete(iface).with_context(|| format!("cleanup `delete link {iface}`"))
        }
    }
}

pub(super) fn is_ignorable_cleanup_error(action: &CleanupAction, err: &anyhow::Error) -> bool {
    match action {
        CleanupAction::RestoreFile { path, .. } => {
            path.contains("/proc/sys/net/ipv4/conf/")
                && path.ends_with("/rp_filter")
                && error_chain_has_io_kind(err, std::io::ErrorKind::NotFound)
        }
        CleanupAction::DeleteLink { .. } => error_chain_contains(err, "No such device"),
        CleanupAction::RunIptables { .. }
        | CleanupAction::RunIp6tables { .. }
        | CleanupAction::DeletePolicyRuleV4 { .. }
        | CleanupAction::DeletePolicyRuleV6 { .. }
        | CleanupAction::DeleteDefaultRouteV4 { .. }
        | CleanupAction::DeleteDefaultRouteV6 { .. }
        | CleanupAction::DeleteLocalRouteV4 { .. }
        | CleanupAction::DeleteLocalRouteV6 { .. } => false,
    }
}

pub(super) fn error_chain_has_io_kind(err: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    err.chain()
        .filter_map(|source| source.downcast_ref::<std::io::Error>())
        .any(|io_err| io_err.kind() == kind)
}

pub(super) fn error_chain_contains(err: &anyhow::Error, needle: &str) -> bool {
    err.chain()
        .any(|source| source.to_string().contains(needle))
}

pub(super) fn replace_action_flag(args: &[String], from: &str, to: &str) -> Vec<String> {
    let mut replaced = args.to_vec();
    if let Some(slot) = replaced.iter_mut().find(|arg| arg.as_str() == from) {
        *slot = to.to_string();
    }
    replaced
}

pub(super) fn run_iptables(table: &str, mut args: Vec<String>) -> Result<String> {
    let mut final_args = Vec::with_capacity(args.len() + 3);
    final_args.push("-w".into());
    final_args.push("-t".into());
    final_args.push(table.into());
    final_args.append(&mut args);
    run_command("iptables", final_args)
}

pub(super) fn run_ip6tables(table: &str, mut args: Vec<String>) -> Result<String> {
    let mut final_args = Vec::with_capacity(args.len() + 3);
    final_args.push("-w".into());
    final_args.push("-t".into());
    final_args.push(table.into());
    final_args.append(&mut args);
    run_command("ip6tables", final_args)
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::*;

    #[test]
    fn replace_action_flag_swaps_the_first_matching_token() {
        let replaced =
            replace_action_flag(&["-A".into(), "FORWARD".into(), "-A".into()], "-A", "-D");
        assert_eq!(replaced, vec!["-D", "FORWARD", "-A"]);
    }

    #[test]
    fn error_chain_has_io_kind_finds_context_wrapped_not_found() {
        let err = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("cleanup `/proc/sys/net/ipv4/conf/test/rp_filter`");
        assert!(error_chain_has_io_kind(&err, std::io::ErrorKind::NotFound));
    }

    #[test]
    fn error_chain_contains_finds_nested_command_error_message() {
        let err = anyhow!("command failed: `ip link del cfh123`")
            .context("stderr: Cannot find device \"cfh123\"")
            .context("cleanup `delete host veth pair`");
        assert!(error_chain_contains(&err, "Cannot find device"));
    }
}
