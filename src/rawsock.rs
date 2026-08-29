//! Our own AF_PACKET socket for receiving.
//!
//! `pnet` transmits well, but its socket hands back a copy of every frame we
//! send ourselves. During a sweep of millions of ARP requests that saturates
//! the receive queue and the kernel starts dropping — and what it drops is
//! precisely the replies we are looking for. The effect is measurable: the same
//! /24 finds far fewer hosts when a large block is swept alongside it.
//!
//! By owning the socket we can turn on PACKET_IGNORE_OUTGOING, enlarge the
//! receive buffer, and read the kernel's drop counter, so we can warn instead
//! of silently losing hosts.

use anyhow::{bail, Context, Result};
use std::io;
use std::os::unix::io::RawFd;

/// Not exposed by the libc crate; defined in <linux/if_packet.h> since 4.20.
const PACKET_IGNORE_OUTGOING: libc::c_int = 23;
/// PACKET_STATISTICS, also from <linux/if_packet.h>.
const PACKET_STATISTICS: libc::c_int = 6;

const ETH_P_ALL: u16 = 0x0003;
/// 16 MiB of headroom: absorbs reply bursts without relying on the scheduler.
const RCVBUF: libc::c_int = 16 * 1024 * 1024;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct TpacketStats {
    tp_packets: libc::c_uint,
    tp_drops: libc::c_uint,
}

pub struct RawSocket {
    fd: RawFd,
    buf: Vec<u8>,
    /// True if the kernel agreed to ignore our own outgoing frames.
    pub ignores_outgoing: bool,
}

impl RawSocket {
    pub fn open(if_index: u32, read_timeout_ms: i64) -> Result<RawSocket> {
        // SAFETY: libc calls with validated arguments; the fd is closed in Drop.
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ALL.to_be() as i32) };
        if fd < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::PermissionDenied {
                bail!("{}", crate::iface::permission_hint());
            }
            return Err(e).context("creating AF_PACKET socket");
        }
        let sock = RawSocket { fd, buf: vec![0u8; 65536], ignores_outgoing: false };

        sock.bind(if_index)?;
        sock.set_promiscuous(if_index)?;
        sock.set_rcvbuf();
        sock.set_timeout(read_timeout_ms)?;

        let mut sock = sock;
        sock.ignores_outgoing = sock.set_ignore_outgoing();
        Ok(sock)
    }

    fn bind(&self, if_index: u32) -> Result<()> {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = ETH_P_ALL.to_be();
        addr.sll_ifindex = if_index as i32;

        let rc = unsafe {
            libc::bind(
                self.fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("binding the AF_PACKET socket");
        }
        Ok(())
    }

    /// Without promiscuous mode we would only see frames addressed to us: a
    /// device with a wrong static IP talking to another would go unnoticed.
    fn set_promiscuous(&self, if_index: u32) -> Result<()> {
        let mut mreq: libc::packet_mreq = unsafe { std::mem::zeroed() };
        mreq.mr_ifindex = if_index as i32;
        mreq.mr_type = libc::PACKET_MR_PROMISC as u16;

        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                libc::PACKET_ADD_MEMBERSHIP,
                &mreq as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("enabling promiscuous mode");
        }
        Ok(())
    }

    /// SO_RCVBUFFORCE ignores the net.core.rmem_max ceiling but needs
    /// CAP_NET_ADMIN; without it we fall back to the ordinary SO_RCVBUF.
    fn set_rcvbuf(&self) {
        let forced = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                &RCVBUF as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if forced < 0 {
            unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &RCVBUF as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }
    }

    /// Without a timeout, recv would block forever and Ctrl-C would go unseen.
    fn set_timeout(&self, ms: i64) -> Result<()> {
        let tv = libc::timeval { tv_sec: ms / 1000, tv_usec: (ms % 1000) * 1000 };
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error()).context("setting the receive timeout");
        }
        Ok(())
    }

    /// The crux: do not receive our own frames back. Available from Linux 4.20
    /// onwards; returns false on older kernels.
    fn set_ignore_outgoing(&self) -> bool {
        let on: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_PACKET,
                PACKET_IGNORE_OUTGOING,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        rc == 0
    }

    /// One frame, or None when the timeout expires.
    pub fn recv(&mut self) -> Option<&[u8]> {
        let n = unsafe {
            libc::recv(self.fd, self.buf.as_mut_ptr() as *mut libc::c_void, self.buf.len(), 0)
        };
        if n <= 0 {
            return None;
        }
        Some(&self.buf[..n as usize])
    }

    /// (received, dropped) since the last call — the kernel resets the counter
    /// when it is read.
    pub fn stats(&self) -> (u32, u32) {
        let mut st = TpacketStats::default();
        let mut len = std::mem::size_of::<TpacketStats>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_PACKET,
                PACKET_STATISTICS,
                &mut st as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 {
            (0, 0)
        } else {
            (st.tp_packets, st.tp_drops)
        }
    }
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}
