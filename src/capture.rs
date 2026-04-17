use std::borrow::Cow;
use std::fs::File;
use std::io::{BufWriter, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;
use pnet_datalink::{self, Channel::Ethernet};

pub struct CaptureHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<Result<()>>>,
}

impl CaptureHandle {
    pub fn start(interface_name: &str, output_path: &Path) -> Result<Self> {
        let interface_name = interface_name.to_string();
        let output_path = output_path.to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);

        let join =
            thread::spawn(move || capture_loop(&interface_name, &output_path, stop_for_thread));

        Ok(Self {
            stop,
            join: Some(join),
        })
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            match join.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    crate::util::warn(format!("packet capture stopped with an error: {err:#}"));
                }
                Err(_) => {
                    crate::util::warn("packet capture thread panicked");
                }
            }
        }
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

fn capture_loop(interface_name: &str, output_path: &PathBuf, stop: Arc<AtomicBool>) -> Result<()> {
    let interface = pnet_datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| anyhow!("capture interface not found: {interface_name}"))?;

    let mut config = pnet_datalink::Config::default();
    config.read_timeout = Some(Duration::from_millis(250));
    config.read_buffer_size = 65_535;
    config.promiscuous = true;

    let (_, mut rx) = match pnet_datalink::channel(&interface, config)
        .with_context(|| format!("failed to open AF_PACKET channel on {interface_name}"))?
    {
        Ethernet(tx, rx) => (tx, rx),
        _ => bail!("unsupported datalink channel type"),
    };

    let file = File::create(output_path)
        .with_context(|| format!("failed to create {}", output_path.display()))?;
    let writer = BufWriter::new(file);
    let mut pcap = PcapNgWriter::new(writer).context("failed to create pcapng writer")?;

    let idb = InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 65_535,
        options: vec![],
    };
    pcap.write_pcapng_block(idb)
        .context("failed to write pcapng interface description block")?;

    while !stop.load(Ordering::Relaxed) {
        match rx.next() {
            Ok(packet) => {
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0));
                let block = EnhancedPacketBlock {
                    interface_id: 0,
                    timestamp,
                    original_len: packet.len() as u32,
                    data: Cow::Owned(packet.to_vec()),
                    options: vec![],
                };
                pcap.write_pcapng_block(block)
                    .context("failed to append enhanced packet block")?;
            }
            Err(err)
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("AF_PACKET receive failed on {interface_name}"));
            }
        }
    }

    let mut writer = pcap.into_inner();
    writer.flush().context("failed to flush pcapng output")?;
    Ok(())
}
