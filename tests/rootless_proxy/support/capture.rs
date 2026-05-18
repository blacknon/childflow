use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

pub(crate) fn assert_capture_file_written(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat capture output {}", path.display()))?;
    assert!(
        metadata.len() > 0,
        "expected a non-empty capture output at {}",
        path.display()
    );
    Ok(())
}

pub(crate) fn assert_capture_has_enhanced_packets(
    path: &Path,
    minimum_packets: usize,
) -> Result<()> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read capture output {}", path.display()))?;
    let packet_count = count_pcapng_enhanced_packets(&bytes).with_context(|| {
        format!(
            "failed to parse pcapng blocks while checking {}",
            path.display()
        )
    })?;

    assert!(
        packet_count >= minimum_packets,
        "expected at least {minimum_packets} enhanced packet blocks in {}, found {packet_count}",
        path.display()
    );
    Ok(())
}

pub(crate) fn unique_temp_capture_path(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}.pcapng"))
}

pub(crate) fn unique_temp_flow_log_path(prefix: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}.jsonl"))
}

fn count_pcapng_enhanced_packets(bytes: &[u8]) -> Result<usize> {
    const SECTION_HEADER_BLOCK: u32 = 0x0A0D0D0A;
    const ENHANCED_PACKET_BLOCK: u32 = 0x00000006;
    const BYTE_ORDER_MAGIC: u32 = 0x1A2B3C4D;
    const SWAPPED_BYTE_ORDER_MAGIC: u32 = 0x4D3C2B1A;

    if bytes.len() < 12 {
        bail!("pcapng file is too short to contain a section header");
    }

    let mut offset = 0usize;
    let mut little_endian = true;
    let mut saw_section_header = false;
    let mut packet_count = 0usize;

    while offset + 12 <= bytes.len() {
        let block_type = read_u32_le(bytes, offset)?;
        let total_length_le = read_u32_le(bytes, offset + 4)?;

        if block_type == SECTION_HEADER_BLOCK {
            let magic = read_u32_le(bytes, offset + 8)?;
            little_endian = match magic {
                BYTE_ORDER_MAGIC => true,
                SWAPPED_BYTE_ORDER_MAGIC => false,
                other => bail!("unexpected pcapng byte-order magic: 0x{other:08x}"),
            };
            saw_section_header = true;
        }

        let total_length = if little_endian {
            total_length_le
        } else {
            read_u32_be(bytes, offset + 4)?
        } as usize;

        if total_length < 12 {
            bail!("pcapng block at offset {offset} has an invalid length of {total_length}");
        }

        let block_end = offset
            .checked_add(total_length)
            .ok_or_else(|| anyhow!("pcapng block length overflowed at offset {offset}"))?;
        if block_end > bytes.len() {
            bail!(
                "pcapng block at offset {offset} extends past the end of the file (len {total_length})"
            );
        }

        let trailing_length = if little_endian {
            read_u32_le(bytes, block_end - 4)?
        } else {
            read_u32_be(bytes, block_end - 4)?
        } as usize;
        if trailing_length != total_length {
            bail!(
                "pcapng block at offset {offset} has mismatched lengths: {total_length} vs {trailing_length}"
            );
        }

        let normalized_block_type = if little_endian {
            block_type
        } else {
            read_u32_be(bytes, offset)?
        };
        if normalized_block_type == ENHANCED_PACKET_BLOCK {
            packet_count += 1;
        }

        offset = block_end;
    }

    if !saw_section_header {
        bail!("pcapng file did not contain a section header block");
    }
    if offset != bytes.len() {
        bail!(
            "pcapng file has {} trailing bytes after the last full block",
            bytes.len() - offset
        );
    }

    Ok(packet_count)
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| anyhow!("offset overflow while reading little-endian u32"))?;
    let slice = bytes.get(offset..end).ok_or_else(|| {
        anyhow!("unexpected EOF while reading little-endian u32 at offset {offset}")
    })?;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

fn read_u32_be(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| anyhow!("offset overflow while reading big-endian u32"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| anyhow!("unexpected EOF while reading big-endian u32 at offset {offset}"))?;
    Ok(u32::from_be_bytes(slice.try_into().unwrap()))
}
