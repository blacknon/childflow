// Copyright (c) 2026 Blacknon. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

use std::fs::File;
use std::io::{Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};

pub struct TapHandle {
    file: File,
}

impl TapHandle {
    pub fn receive_from_stream(stream: &UnixStream) -> Result<Self> {
        let fd = recv_fd(stream).context("failed to receive the rootless tap fd from the child")?;
        let file = unsafe { File::from_raw_fd(fd) };
        Ok(Self { file })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

pub fn send_fd_over_stream(stream: &UnixStream, file: &File) -> Result<()> {
    let payload = [1_u8];
    let mut iov = nix::libc::iovec {
        iov_base: payload.as_ptr() as *mut nix::libc::c_void,
        iov_len: payload.len(),
    };
    let fd = file.as_raw_fd();
    let mut control =
        vec![0_u8; unsafe { nix::libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize }];
    let mut msg: nix::libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut nix::libc::c_void;
    msg.msg_controllen = control.len();

    unsafe {
        let cmsg = nix::libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            anyhow::bail!("failed to allocate control message buffer for tap fd transfer");
        }
        (*cmsg).cmsg_level = nix::libc::SOL_SOCKET;
        (*cmsg).cmsg_type = nix::libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = nix::libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            nix::libc::CMSG_DATA(cmsg),
            size_of::<RawFd>(),
        );
        msg.msg_controllen = (*cmsg).cmsg_len;
    }

    let rc = unsafe { nix::libc::sendmsg(stream.as_raw_fd(), &msg, 0) };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .context("failed to send the rootless tap fd to the parent process");
    }
    Ok(())
}

fn recv_fd(stream: &UnixStream) -> Result<RawFd> {
    let mut payload = [0_u8; 1];
    let mut iov = nix::libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut nix::libc::c_void,
        iov_len: payload.len(),
    };
    let mut control =
        vec![0_u8; unsafe { nix::libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize }];
    let mut msg: nix::libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut nix::libc::c_void;
    msg.msg_controllen = control.len();

    let rc = unsafe { nix::libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if rc < 0 {
        return Err(anyhow::Error::new(std::io::Error::last_os_error()))
            .context("failed to receive the rootless tap fd from the child process");
    }
    if rc == 0 {
        anyhow::bail!("child closed the tap fd transfer socket before sending a descriptor");
    }

    let cmsg = unsafe { nix::libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        anyhow::bail!("child did not send a control message containing the tap fd");
    }
    let is_fd = unsafe {
        (*cmsg).cmsg_level == nix::libc::SOL_SOCKET && (*cmsg).cmsg_type == nix::libc::SCM_RIGHTS
    };
    if !is_fd {
        anyhow::bail!("child sent an unexpected control message while transferring the tap fd");
    }

    let mut fd = -1_i32;
    unsafe {
        std::ptr::copy_nonoverlapping(
            nix::libc::CMSG_DATA(cmsg),
            &mut fd as *mut RawFd as *mut u8,
            size_of::<RawFd>(),
        );
    }
    if fd < 0 {
        anyhow::bail!("received an invalid tap fd from the child process");
    }
    Ok(fd)
}

impl Read for TapHandle {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for TapHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}