use anyhow::Result;

mod af_packet;
mod pcap;

pub use self::af_packet::CaptureHandle;
use self::pcap::FrameCaptureWriter;
use super::{
    rewrite::rewrite_rootful_egress_frame, CaptureMetadata, CaptureMode, CapturePlan,
    RootfulEgressRewrite,
};

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

    pub fn open_child_only(
        output_path: &std::path::Path,
        metadata: CaptureMetadata,
    ) -> Result<Self> {
        Ok(Self {
            child: Some(FrameCaptureWriter::open(output_path, &metadata)?),
            egress: None,
            rewrite: None,
        })
    }

    pub fn open_synthetic_egress(
        output_path: &std::path::Path,
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
        child_output_path: &std::path::Path,
        egress_output_path: &std::path::Path,
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
