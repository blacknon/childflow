use std::borrow::Cow;
use std::fs::File;
use std::io::{BufWriter, ErrorKind, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;
use pnet_datalink::{self, Channel::Ethernet};

use super::rewrite::rewrite_rootful_egress_frame;
use super::{CaptureMetadata, CaptureMode, CapturePlan, RootfulEgressRewrite};

pub struct FrameCaptureWriter {
    pcap: Option<PcapNgWriter<BufWriter<File>>>,
}

impl FrameCaptureWriter {
    pub fn open(output_path: &Path, metadata: &CaptureMetadata) -> Result<Self> {
        let pcap = open_pcap_writer(output_path, metadata)?;
        Ok(Self { pcap: Some(pcap) })
    }

    pub fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        let timestamp = capture_timestamp();
        let block = EnhancedPacketBlock {
            interface_id: 0,
            timestamp,
            original_len: frame.len() as u32,
            data: Cow::Owned(frame.to_vec()),
            options: vec![],
        };
        self.pcap
            .as_mut()
            .ok_or_else(|| anyhow!("rootless frame capture writer is already closed"))?
            .write_pcapng_block(block)
            .context("failed to append enhanced packet block")?;
        self.flush()?;
        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        let Some(pcap) = self.pcap.take() else {
            return Ok(());
        };
        let mut writer = pcap.into_inner();
        writer
            .flush()
            .context("failed to flush rootless pcapng output")?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        let Some(pcap) = self.pcap.as_mut() else {
            return Ok(());
        };
        pcap.get_mut()
            .flush()
            .context("failed to flush rootless pcapng output")?;
        Ok(())
    }
}

impl Drop for FrameCaptureWriter {
    fn drop(&mut self) {
        if let Err(err) = self.close() {
            crate::util::warn(format!(
                "failed to finalize rootless packet capture output: {err:#}"
            ));
        }
    }
}

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
            CaptureMode::AfPacket { interface_name } => interface_name.clone(),
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

pub struct CaptureWriters {
    child: Option<FrameCaptureWriter>,
    egress: Option<FrameCaptureWriter>,
    rewrite: Option<RootfulEgressRewrite>,
}

impl CaptureWriters {
    fn open(plan: CapturePlan) -> Result<Self> {
        match plan {
            CapturePlan::ChildOnly {
                output_path,
                metadata,
                ..
            } => Self::open_child_only(&output_path, metadata),
            CapturePlan::RootfulSyntheticEgress {
                output_path,
                rewrite,
                ..
            } => Self::open_synthetic_egress(
                &output_path,
                rewrite,
                CaptureMetadata::new("egress", "rootful", "synthetic", "synthetic-egress"),
            ),
            CapturePlan::RootfulChildAndSyntheticEgress {
                mode,
                child_output_path,
                egress_output_path,
                rewrite,
            } => Self::open_child_and_synthetic_egress(
                &child_output_path,
                &egress_output_path,
                rewrite,
                CaptureMetadata::new(
                    "child",
                    "rootful",
                    "isolated",
                    match mode {
                        CaptureMode::AfPacket { interface_name } => interface_name,
                    },
                ),
                CaptureMetadata::new("egress", "rootful", "synthetic", "synthetic-egress"),
            ),
        }
    }

    pub fn open_child_only(output_path: &Path, metadata: CaptureMetadata) -> Result<Self> {
        Ok(Self {
            child: Some(FrameCaptureWriter::open(output_path, &metadata)?),
            egress: None,
            rewrite: None,
        })
    }

    pub fn open_synthetic_egress(
        output_path: &Path,
        rewrite: RootfulEgressRewrite,
        metadata: CaptureMetadata,
    ) -> Result<Self> {
        Ok(Self {
            child: None,
            egress: Some(FrameCaptureWriter::open(output_path, &metadata)?),
            rewrite: Some(rewrite),
        })
    }

    pub fn open_child_and_synthetic_egress(
        child_output_path: &Path,
        egress_output_path: &Path,
        rewrite: RootfulEgressRewrite,
        child_metadata: CaptureMetadata,
        egress_metadata: CaptureMetadata,
    ) -> Result<Self> {
        Ok(Self {
            child: Some(FrameCaptureWriter::open(
                child_output_path,
                &child_metadata,
            )?),
            egress: Some(FrameCaptureWriter::open(
                egress_output_path,
                &egress_metadata,
            )?),
            rewrite: Some(rewrite),
        })
    }

    pub fn write(&mut self, packet: &[u8]) -> Result<()> {
        if let Some(writer) = self.child.as_mut() {
            writer.write_frame(packet)?;
        }

        if let Some(writer) = self.egress.as_mut() {
            if let Some(rewrite) = self.rewrite {
                if let Some(frame) = rewrite_rootful_egress_frame(packet, rewrite)? {
                    writer.write_frame(&frame)?;
                }
            } else {
                writer.write_frame(packet)?;
            }
        }

        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        if let Some(writer) = self.child.as_mut() {
            writer.flush()?;
        }
        if let Some(writer) = self.egress.as_mut() {
            writer.flush()?;
        }
        Ok(())
    }
}

fn open_pcap_writer(
    output_path: &Path,
    metadata: &CaptureMetadata,
) -> Result<PcapNgWriter<BufWriter<File>>> {
    let file = File::create(output_path)
        .with_context(|| format!("failed to create {}", output_path.display()))?;
    let writer = BufWriter::new(file);
    let mut pcap = PcapNgWriter::new(writer).context("failed to create pcapng writer")?;

    let idb = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 65_535,
        options: vec![
            InterfaceDescriptionOption::IfTsResol(9),
            InterfaceDescriptionOption::IfName(metadata.interface_name.clone().into()),
            InterfaceDescriptionOption::IfDescription(metadata.description().into()),
        ],
    };
    pcap.write_pcapng_block(idb)
        .context("failed to write pcapng interface description block")?;
    pcap.get_mut()
        .flush()
        .context("failed to flush the initial pcapng header")?;
    Ok(pcap)
}

fn capture_timestamp() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
}
