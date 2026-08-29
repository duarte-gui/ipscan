use anyhow::{anyhow, Result};
use ipnet::Ipv4Net;
use pnet::datalink::{self, NetworkInterface};
use pnet::util::MacAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Local facts the rest of the program needs: who we are on the network.
#[derive(Debug, Clone)]
pub struct Local {
    pub iface: NetworkInterface,
    pub mac: MacAddr,
    /// The interface's IPv4. `None` when the machine holds no address on the
    /// network — routine in the field, on a network with no DHCP server. A
    /// sweep with the default `spa` (probe, sender 0.0.0.0) needs no address.
    pub ipv4: Option<Ipv4Addr>,
    /// The interface's subnet, truncated. `None` without IPv4 — and also when
    /// the address is APIPA: 169.254/16 is a symptom of missing DHCP, not the
    /// network's subnet. Using it as a baseline would invent a network.
    pub net: Option<Ipv4Net>,
    pub link_local: Option<Ipv6Addr>,
}

/// 169.254/16 — automatic link-local, assigned by the system when DHCP fails.
/// It is not the network's subnet: no good as a baseline nor as a sweep target.
pub fn is_apipa_net(n: &Ipv4Net) -> bool {
    let o = n.addr().octets();
    o[0] == 169 && o[1] == 254
}

pub fn resolve(name: Option<&str>) -> Result<Local> {
    let all = datalink::interfaces();

    let iface = match name {
        Some(n) => all
            .into_iter()
            .find(|i| i.name == n)
            .ok_or_else(|| anyhow!("interface {:?} not found", n))?,
        None => {
            let up: Vec<NetworkInterface> = all
                .into_iter()
                .filter(|i| i.is_up() && !i.is_loopback() && i.mac.is_some())
                .collect();
            // Prefer an interface that has IPv4, but do not require one: on a
            // network without DHCP the card stays address-less and can still
            // sweep.
            up.iter()
                .find(|i| i.ips.iter().any(|ip| ip.is_ipv4()))
                .cloned()
                .or_else(|| up.into_iter().next())
                .ok_or_else(|| anyhow!("no active interface found"))?
        }
    };

    let mac = iface
        .mac
        .ok_or_else(|| anyhow!("interface {} has no MAC (not ethernet?)", iface.name))?;

    let (ipv4, net) = match iface.ips.iter().find_map(|ip| match ip {
        pnet::ipnetwork::IpNetwork::V4(v4) => {
            let addr = v4.ip();
            Ipv4Net::new(addr, v4.prefix()).ok().map(|n| (addr, n.trunc()))
        }
        _ => None,
    }) {
        Some((addr, net)) if is_apipa_net(&net) => (Some(addr), None),
        Some((addr, net)) => (Some(addr), Some(net)),
        None => (None, None),
    };

    let link_local = iface.ips.iter().find_map(|ip| match ip {
        pnet::ipnetwork::IpNetwork::V6(v6) if is_link_local(&v6.ip()) => Some(v6.ip()),
        _ => None,
    });

    Ok(Local { iface, mac, ipv4, net, link_local })
}

fn is_link_local(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

/// Help text shown when the datalink channel fails for lack of permission.
pub fn permission_hint() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "target/release/ipscan".into());
    format!(
        "Permission denied opening the raw socket.\n\
         ipscan needs CAP_NET_RAW. Grant it once with:\n\n    \
         pkexec setcap cap_net_raw+ep {}\n\n\
         After that it runs as a normal user, without sudo.",
        exe
    )
}

/// Trimmed-down interface for the TUI selector: name + IPv4 subnet, if any.
#[derive(Debug, Clone)]
pub struct Iface {
    pub name: String,
    pub net: Option<Ipv4Net>,
}

/// Lists candidate interfaces (up, non-loopback) with their IPv4 subnet.
pub fn list_ifaces() -> Vec<Iface> {
    let mut out: Vec<Iface> = datalink::interfaces()
        .into_iter()
        .filter(|i| !i.is_loopback() && i.mac.is_some())
        .map(|i| {
            let net = i
                .ips
                .iter()
                .find_map(|ip| match ip {
                    pnet::ipnetwork::IpNetwork::V4(v4) => {
                        Ipv4Net::new(v4.ip(), v4.prefix()).ok().map(|n| n.trunc())
                    }
                    _ => None,
                })
                .filter(|n| !is_apipa_net(n));
            Iface { name: i.name.clone(), net }
        })
        .collect();
    // Interfaces with IPv4 first (more useful to sweep from).
    out.sort_by_key(|i| (i.net.is_none(), i.name.clone()));
    out
}
