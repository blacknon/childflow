use std::borrow::Cow;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;

use crate::capture::CaptureMetadata;

pub(super) struct FrameCaptureWriter {
    pcap: Option<PcapNgWriter<BufWriter<File>>>,
}

impl FrameCaptureWriter {
    pub(super) fn open(output_path: &Path, metadata: &CaptureMetadata) -> Result<Self> {
        let pcap = open_pcap_writer(output_path, metadata)?;
        Ok(Self { pcap: Some(pcap) })
    }

    pub(super) fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
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

    pub(super) fn close(&mut self) -> Result<()> {
        let Some(pcap) = self.pcap.take() else {
            return Ok(());
        };
        let mut writer = pcap.into_inner();
        writer
            .flush()
            .context("failed to flush rootless pcapng output")?;
        Ok(())
    }

    pub(super) fn flush(&mut self) -> Result<()> {
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
