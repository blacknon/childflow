use std::fs::File;
use std::fs::OpenOptions;

use anyhow::{anyhow, bail, Context, Result};

pub(super) fn create_tap_device(name: &str) -> Result<(File, String)> {
    if name.is_empty() {
        bail!("tap device name must not be empty");
    }
    if name.len() >= nix::libc::IFNAMSIZ {
        bail!(
            "tap device name `{name}` is too long for Linux IFNAMSIZ={}",
            nix::libc::IFNAMSIZ
        );
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .context("failed to open `/dev/net/tun` while creating the rootless-internal tap inside the child namespace")?;

    let mut ifreq = nix::libc::ifreq {
        ifr_name: [0; nix::libc::IFNAMSIZ],
        ifr_ifru: nix::libc::__c_anonymous_ifr_ifru {
            ifru_flags: (nix::libc::IFF_TAP | nix::libc::IFF_NO_PI) as nix::libc::c_short,
        },
    };

    for (idx, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[idx] = *byte as nix::libc::c_char;
    }

    let rc = unsafe {
        // SAFETY: `file` is an open `/dev/net/tun` descriptor and `ifreq` points to initialized
        // writable storage whose lifetime covers the ioctl call. The kernel writes the chosen
        // interface name back into the same struct.
        nix::libc::ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&file),
            nix::libc::TUNSETIFF as _,
            &mut ifreq,
        )
    };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error())).context(
            format!(
                "failed to create tap device `{name}` inside the rootless-internal child namespace using TUNSETIFF"
            ),
        );
    }

    let actual_name = ifreq_name_to_string(&ifreq.ifr_name)?;
    if actual_name.is_empty() {
        bail!("kernel returned an empty tap device name after TUNSETIFF");
    }

    Ok((file, actual_name))
}

fn ifreq_name_to_string(raw_name: &[nix::libc::c_char; nix::libc::IFNAMSIZ]) -> Result<String> {
    let end = raw_name
        .iter()
        .position(|ch| *ch == 0)
        .unwrap_or(raw_name.len());
    let bytes = raw_name[..end]
        .iter()
        .map(|&ch| ch.to_ne_bytes()[0])
        .collect();
    String::from_utf8(bytes)
        .map_err(|err| anyhow!("kernel returned a non-UTF8 tap device name: {err}"))
}
