//! A TUN device opened with `TUNSETIFF` (Linux), read and written through
//! tokio's readiness API.

#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

use tokio::io::unix::AsyncFd;

/// `_IOW('T', 202, int)`, the same encoding on every architecture Linux
/// runs this relay on (x86_64, aarch64).
const TUNSETIFF: u64 = 0x4004_54ca;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const IFNAMSIZ: usize = 16;

/// `struct ifreq` as `TUNSETIFF` reads it: the name, then the flags.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: i16,
    _pad: [u8; 22],
}

pub(crate) struct TunFd {
    fd: AsyncFd<File>,
}

impl TunFd {
    /// Creates the TUN device `name` (no packet information header) in the
    /// calling thread's network namespace.
    pub(crate) fn open(name: &str) -> io::Result<Self> {
        if name.is_empty() || name.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad interface name",
            ));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")?;
        let mut req = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: `file` is an open /dev/net/tun descriptor and `req` is a
        // live, properly sized `struct ifreq` that the kernel reads and may
        // write back for the duration of the call only.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &mut req as *mut IfReq) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: AsyncFd::new(file)?,
        })
    }

    pub(crate) async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| inner.get_ref().read(buf)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub(crate) async fn write(&self, packet: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| inner.get_ref().write(packet)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}
