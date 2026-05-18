use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use pnet_datalink::{self, Channel::Ethernet};

use super::CaptureWriters;
use crate::capture::CapturePlan;

pub struct CaptureHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<()>>>,
}

impl CaptureHandle {
    pub fn start(plan: CapturePlan) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let join = thread::spawn(move || capture_loop(plan, stop_for_thread));

        Ok(Self {
            stop,
            join: Some(join),
        })
    }

    fn stop_and_join(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            match join.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    return Err(err).context("packet capture stopped with an error");
                }
                Err(_) => {
                    bail!("packet capture thread panicked");
                }
            }
        }
        Ok(())
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.stop_and_join()
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        if let Err(err) = self.stop_and_join() {
            crate::util::warn(format!("{err:#}"));
        }
    }
}

fn capture_loop(plan: CapturePlan, stop: Arc<AtomicBool>) -> Result<()> {
    let interface_name = match &plan {
        CapturePlan::ChildOnly { mode, .. }
        | CapturePlan::RootfulSyntheticEgress { mode, .. }
        | CapturePlan::RootfulChildAndSyntheticEgress { mode, .. } => match mode {
            crate::capture::CaptureMode::AfPacket { interface_name } => interface_name.clone(),
        },
    };

    let interface = pnet_datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| anyhow!("capture interface not found: {interface_name}"))?;

    let config = pnet_datalink::Config {
        read_timeout: Some(Duration::from_millis(250)),
        read_buffer_size: 65_535,
        promiscuous: true,
        ..Default::default()
    };

    let (_, mut rx) = match pnet_datalink::channel(&interface, config)
        .with_context(|| format!("failed to open AF_PACKET channel on {interface_name}"))?
    {
        Ethernet(tx, rx) => (tx, rx),
        _ => bail!("unsupported datalink channel type"),
    };

    let mut writers = CaptureWriters::open(plan)?;

    while !stop.load(Ordering::Relaxed) {
        match rx.next() {
            Ok(packet) => {
                writers.write(packet)?;
            }
            Err(err)
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut => {}
            Err(err) => {
                if stop.load(Ordering::Relaxed) {
                    crate::util::debug(format!(
                        "stopping AF_PACKET capture on {interface_name} after shutdown signal: {err}"
                    ));
                    break;
                }
                return Err(err)
                    .with_context(|| format!("AF_PACKET receive failed on {interface_name}"));
            }
        }
    }

    writers.flush()?;
    Ok(())
}
