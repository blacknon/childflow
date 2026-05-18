use std::os::fd::{BorrowedFd, RawFd};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use nix::fcntl::{fcntl, FcntlArg, OFlag};

use crate::util;

use super::loop_::run_engine;
use crate::network::rootless_internal::engine::{AddressPlan, EngineConfig, EngineHandle};
use crate::network::rootless_internal::tap::TapHandle;

impl EngineHandle {
    pub(in crate::network::rootless_internal) fn start(
        tap: TapHandle,
        addr_plan: AddressPlan,
        config: EngineConfig,
    ) -> Result<Self> {
        set_nonblocking(tap.raw_fd())?;

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let leak_detected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let leak_detected_for_thread = Arc::clone(&leak_detected);
        let join = thread::spawn(move || {
            run_engine(
                tap,
                addr_plan,
                config,
                stop_for_thread,
                leak_detected_for_thread,
            )
        });

        Ok(Self {
            stop,
            leak_detected,
            join: Some(join),
        })
    }

    fn stop_and_join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            match join.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return Err(err).context("rootless-internal engine stopped with an error");
                }
                Err(_) => anyhow::bail!("rootless-internal engine thread panicked"),
            }
        }
        Ok(())
    }

    pub(in crate::network::rootless_internal) fn shutdown(mut self) -> Result<()> {
        self.stop_and_join()
    }

    pub(in crate::network::rootless_internal) fn leak_detected(&self) -> bool {
        self.leak_detected.load(Ordering::Relaxed)
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        if let Err(err) = self.stop_and_join() {
            util::warn(format!("{err:#}"));
        }
    }
}

pub(in crate::network::rootless_internal::engine) fn detect_ipv6_outbound() -> bool {
    let Ok(routes) = std::fs::read_to_string("/proc/net/ipv6_route") else {
        return false;
    };
    routes.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.len() > 9
            && fields[0] == "00000000000000000000000000000000"
            && fields[1] == "00000000"
            && fields[9] != "lo"
    })
}

fn set_nonblocking(fd: RawFd) -> Result<()> {
    // SAFETY: `fd` comes from `TapHandle` and stays open for the duration of this call.
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let flags = OFlag::from_bits_truncate(
        fcntl(fd, FcntlArg::F_GETFL).context("failed to read tap fd flags")?,
    );
    fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
        .context("failed to set tap fd nonblocking")?;
    Ok(())
}
