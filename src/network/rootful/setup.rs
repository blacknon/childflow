use super::cleanup::CleanupAction;
use super::NetworkContext;

impl NetworkContext {
    pub(super) fn push_cleanup_command(
        &mut self,
        label: &'static str,
        program: &'static str,
        args: Vec<String>,
    ) {
        self.cleanup_actions.push(CleanupAction::RunCommand {
            label,
            program,
            args,
        });
    }

    pub(super) fn push_cleanup_iptables(
        &mut self,
        label: &'static str,
        table: &'static str,
        args: Vec<String>,
    ) {
        self.cleanup_actions
            .push(CleanupAction::RunIptables { label, table, args });
    }

    pub(super) fn push_cleanup_ip6tables(
        &mut self,
        label: &'static str,
        table: &'static str,
        args: Vec<String>,
    ) {
        self.cleanup_actions
            .push(CleanupAction::RunIp6tables { label, table, args });
    }

    pub(super) fn push_restore_file(&mut self, path: impl Into<String>, value: impl Into<String>) {
        self.cleanup_actions.push(CleanupAction::RestoreFile {
            path: path.into(),
            value: value.into(),
        });
    }
}
