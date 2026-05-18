use super::cleanup::{is_ignorable_cleanup_error, run_cleanup_action};
use super::NetworkContext;
use crate::util::{debug, warn};

impl NetworkContext {
    fn cleanup_best_effort(&mut self) {
        let mut failures = Vec::new();

        while let Some(action) = self.cleanup_actions.pop() {
            match run_cleanup_action(&action) {
                Ok(()) => {}
                Err(err) if is_ignorable_cleanup_error(&action, &err) => {
                    debug(format!("{err:#}"));
                }
                Err(err) => {
                    failures.push(format!("{err:#}"));
                }
            }
        }

        if failures.is_empty() {
            return;
        }

        warn(format!(
            "cleanup left {} warning(s). Re-run with `CHILDFLOW_DEBUG=1` for detailed cleanup diagnostics.",
            failures.len()
        ));
        for failure in failures {
            debug(failure);
        }
    }
}

impl Drop for NetworkContext {
    fn drop(&mut self) {
        self.cleanup_best_effort();
    }
}
