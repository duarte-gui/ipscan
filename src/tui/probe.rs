//! One-off probe of a single host (the TUI's `p` action).
//!
//! Sends a single ICMP ping through the system `ping` utility — cheap, needs no
//! extra raw socket, and the Linux `ping` already carries the capability. Good
//! enough to answer "is this host still alive?".

use std::net::Ipv4Addr;
use std::process::Command;

/// Some(true) alive, Some(false) no answer, None if the attempt never happened.
pub fn probe_host(iface: Option<&str>, ip: Ipv4Addr) -> Option<bool> {
    let mut cmd = Command::new("ping");
    cmd.arg("-c").arg("1").arg("-W").arg("1").arg("-n");
    if let Some(i) = iface {
        cmd.arg("-I").arg(i);
    }
    cmd.arg(ip.to_string());
    match cmd.output() {
        Ok(o) => Some(o.status.success()),
        Err(_) => None,
    }
}
