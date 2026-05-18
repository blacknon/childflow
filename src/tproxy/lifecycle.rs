use std::sync::atomic::Ordering;

use anyhow::{bail, Context, Result};

use super::TproxyHandle;

impl TproxyHandle {
    fn stop_and_join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            match join.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return Err(err).context("transparent proxy stopped with an error");
                }
                Err(_) => bail!("transparent proxy thread panicked"),
            }
        }
        Ok(())
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.stop_and_join()
    }
}

impl Drop for TproxyHandle {
    fn drop(&mut self) {
        if let Err(err) = self.stop_and_join() {
            crate::util::warn(format!("{err:#}"));
        }
    }
}
