// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::borrow::Cow;
use std::fs::File;
use std::io::{BufWriter, ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use etherparse::{EtherType, Ethernet2HeaderSlice};
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::DataLink;
use pnet_datalink::{self, Channel::Ethernet};

use crate::cli::OutputView;
use crate::network::rootless_internal::packet::{
    self, Icmpv4EchoFrame, Icmpv6EchoFrame, ParsedPacket, TcpReply,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureMode {
    AfPacket { interface_name: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapturePlan {
    ChildOnly {
        mode: CaptureMode,
        output_path: PathBuf,
        metadata: CaptureMetadata,
    },
    RootfulSyntheticEgress {
        mode: CaptureMode,
        output_path: PathBuf,
        rewrite: RootfulEgressRewrite,
    },
    RootfulChildAndSyntheticEgress {
        mode: CaptureMode,
        child_output_path: PathBuf,
        egress_output_path: PathBuf,
        rewrite: RootfulEgressRewrite,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RootfulEgressRewrite {
    pub child_ipv4: Ipv4Addr,
    pub child_ipv6: Ipv6Addr,
    pub host_egress_ipv4: Option<Ipv4Addr>,
    pub host_egress_ipv6: Option<Ipv6Addr>,
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureMetadata {
    view: &'static str,
    backend: &'static str,
    kind: &'static str,
    interface_name: String,
}

impl CaptureMetadata {
    pub fn new(
        view: &'static str,
        backend: &'static str,
        kind: &'static str,
        interface_name: impl Into<String>,
    ) -> Self {
        Self {
            view,
            backend,
            kind,
            interface_name: interface_name.into(),
        }
    }

    fn description(&self) -> String {
        format!(
            "childflow view={} backend={} kind={} interface={}",
            self.view, self.backend, self.kind, self.interface_name
        )
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
        // `pcap-file` serializes EPB timestamps as raw nanoseconds. Advertise that
        // resolution explicitly so readers such as tcpdump do not assume the pcapng
        // default of microseconds and inflate wall-clock time by 1000x.
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

pub fn derive_output_paths(base: &Path, output_view: OutputView) -> Result<(PathBuf, PathBuf)> {
    match output_view {
        OutputView::Child | OutputView::Egress | OutputView::WireEgress => {
            Ok((base.to_path_buf(), base.to_path_buf()))
        }
        OutputView::Both => {
            let parent = base.parent().unwrap_or_else(|| Path::new("."));
            let file_name = base
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow!("output path must end with a valid UTF-8 file name"))?;
            let stem = file_name.strip_suffix(".pcapng").unwrap_or(file_name);
            Ok((
                parent.join(format!("{stem}.child.pcapng")),
                parent.join(format!("{stem}.egress.pcapng")),
            ))
        }
    }
}

fn rewrite_rootful_egress_frame(
    frame: &[u8],
    rewrite: RootfulEgressRewrite,
) -> Result<Option<Vec<u8>>> {
    let eth = Ethernet2HeaderSlice::from_slice(frame).context("failed to parse Ethernet header")?;

    match eth.ether_type() {
        EtherType::IPV4 | EtherType::IPV6 => {}
        _ => return Ok(None),
    }

    match packet::parse_frame(frame) {
        Ok(ParsedPacket::Tcp(tcp)) => {
            let Some((src_ip, dst_ip)) = rewrite_ips(tcp.meta.src_ip, tcp.meta.dst_ip, rewrite)?
            else {
                return Ok(None);
            };
            Ok(Some(packet::build_tcp_frame(TcpReply {
                src_mac: tcp.meta.src_mac,
                dst_mac: tcp.meta.dst_mac,
                src_ip,
                dst_ip,
                src_port: tcp.src_port,
                dst_port: tcp.dst_port,
                seq: tcp.sequence_number,
                ack: tcp.acknowledgment_number,
                syn: tcp.syn,
                ack_flag: tcp.ack,
                fin: tcp.fin,
                rst: tcp.rst,
                psh: tcp.psh,
                payload: &tcp.payload,
            })?))
        }
        Ok(ParsedPacket::Udp(udp)) => {
            let Some((src_ip, dst_ip)) = rewrite_ips(udp.meta.src_ip, udp.meta.dst_ip, rewrite)?
            else {
                return Ok(None);
            };
            Ok(Some(packet::build_udp_frame(
                udp.meta.src_mac,
                udp.meta.dst_mac,
                src_ip,
                dst_ip,
                udp.src_port,
                udp.dst_port,
                &udp.payload,
            )?))
        }
        Ok(ParsedPacket::Icmpv4(icmp)) => {
            let Some((src_ip, dst_ip)) = rewrite_ips(icmp.meta.src_ip, icmp.meta.dst_ip, rewrite)?
            else {
                return Ok(None);
            };
            let (src_ip, dst_ip) = match (src_ip, dst_ip) {
                (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => (src_ip, dst_ip),
                _ => return Ok(None),
            };
            Ok(Some(packet::build_icmpv4_echo_frame(Icmpv4EchoFrame {
                src_mac: icmp.meta.src_mac,
                dst_mac: icmp.meta.dst_mac,
                src_ip,
                dst_ip,
                icmp_type: icmp.icmp_type,
                code: icmp.code,
                identifier: icmp.identifier,
                sequence: icmp.sequence,
                payload: &icmp.payload,
            })?))
        }
        Ok(ParsedPacket::Icmpv6(icmp)) => {
            let Some((src_ip, dst_ip)) = rewrite_ips(icmp.meta.src_ip, icmp.meta.dst_ip, rewrite)?
            else {
                return Ok(None);
            };
            let (src_ip, dst_ip) = match (src_ip, dst_ip) {
                (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => (src_ip, dst_ip),
                _ => return Ok(None),
            };
            Ok(Some(packet::build_icmpv6_echo_frame(Icmpv6EchoFrame {
                src_mac: icmp.meta.src_mac,
                dst_mac: icmp.meta.dst_mac,
                src_ip,
                dst_ip,
                icmp_type: icmp.icmp_type,
                code: icmp.code,
                identifier: icmp.identifier,
                sequence: icmp.sequence,
                payload: &icmp.payload,
            })?))
        }
        Ok(ParsedPacket::Unsupported) => Ok(None),
        Err(_) => Ok(None),
    }
}

fn rewrite_ips(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    rewrite: RootfulEgressRewrite,
) -> Result<Option<(IpAddr, IpAddr)>> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let Some(host_ip) = rewrite.host_egress_ipv4 else {
                return Ok(None);
            };
            Ok(Some((
                if src == rewrite.child_ipv4 {
                    IpAddr::V4(host_ip)
                } else {
                    IpAddr::V4(src)
                },
                if dst == rewrite.child_ipv4 {
                    IpAddr::V4(host_ip)
                } else {
                    IpAddr::V4(dst)
                },
            )))
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let Some(host_ip) = rewrite.host_egress_ipv6 else {
                return Ok(None);
            };
            Ok(Some((
                if src == rewrite.child_ipv6 {
                    IpAddr::V6(host_ip)
                } else {
                    IpAddr::V6(src)
                },
                if dst == rewrite.child_ipv6 {
                    IpAddr::V6(host_ip)
                } else {
                    IpAddr::V6(dst)
                },
            )))
        }
        _ => bail!("mixed IPv4/IPv6 packet addresses are unsupported for capture rewriting"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::rootless_internal::packet::{build_tcp_frame, ParsedPacket, TcpReply};

    #[test]
    fn derive_output_paths_for_both_appends_child_and_egress_suffixes() {
        let (child, egress) =
            derive_output_paths(Path::new("/tmp/capture.pcapng"), OutputView::Both).unwrap();

        assert_eq!(child, PathBuf::from("/tmp/capture.child.pcapng"));
        assert_eq!(egress, PathBuf::from("/tmp/capture.egress.pcapng"));
    }

    #[test]
    fn rewrite_rootful_egress_frame_rewrites_child_ipv4_endpoint_to_host_ipv4() {
        let frame = build_tcp_frame(TcpReply {
            src_mac: [0, 1, 2, 3, 4, 5],
            dst_mac: [6, 7, 8, 9, 10, 11],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 240, 0, 2)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            src_port: 12345,
            dst_port: 443,
            seq: 1,
            ack: 2,
            syn: true,
            ack_flag: true,
            fin: false,
            rst: false,
            psh: false,
            payload: &[],
        })
        .unwrap();

        let rewritten = rewrite_rootful_egress_frame(
            &frame,
            RootfulEgressRewrite {
                child_ipv4: Ipv4Addr::new(10, 240, 0, 2),
                child_ipv6: "fd42::2".parse().unwrap(),
                host_egress_ipv4: Some(Ipv4Addr::new(192, 0, 2, 10)),
                host_egress_ipv6: Some("2001:db8::10".parse().unwrap()),
            },
        )
        .unwrap()
        .unwrap();

        match packet::parse_frame(&rewritten).unwrap() {
            ParsedPacket::Tcp(tcp) => {
                assert_eq!(tcp.meta.src_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
                assert_eq!(tcp.meta.dst_ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
            }
            other => panic!("expected rewritten TCP packet, got {other:?}"),
        }
    }

    #[test]
    fn rewrite_rootful_egress_frame_skips_ipv6_when_no_ipv6_egress_is_known() {
        let frame = build_tcp_frame(TcpReply {
            src_mac: [0, 1, 2, 3, 4, 5],
            dst_mac: [6, 7, 8, 9, 10, 11],
            src_ip: IpAddr::V6("fd42::2".parse().unwrap()),
            dst_ip: IpAddr::V6("2001:db8::1".parse().unwrap()),
            src_port: 12345,
            dst_port: 443,
            seq: 1,
            ack: 2,
            syn: true,
            ack_flag: true,
            fin: false,
            rst: false,
            psh: false,
            payload: &[],
        })
        .unwrap();

        let rewritten = rewrite_rootful_egress_frame(
            &frame,
            RootfulEgressRewrite {
                child_ipv4: Ipv4Addr::new(10, 240, 0, 2),
                child_ipv6: "fd42::2".parse().unwrap(),
                host_egress_ipv4: Some(Ipv4Addr::new(192, 0, 2, 10)),
                host_egress_ipv6: None,
            },
        )
        .unwrap();

        assert!(rewritten.is_none());
    }
}
