use crate::capture::{Event, Source};
use crate::dhcp::{DhcpObservation, Lease, MsgType};
use pnet::util::MacAddr;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct Host {
    pub mac: MacAddr,
    /// Addresses this MAC demonstrably OWNS: it answered ARP for them, sent a
    /// gratuitous/probe frame, or received them over DHCP. Proof of ownership.
    pub ipv4_owned: BTreeSet<Ipv4Addr>,
    /// Addresses merely SEEN as the source of traffic on this MAC. On a router
    /// or gateway this includes everything it forwards — not its own address.
    pub ipv4_routed: BTreeSet<Ipv4Addr>,
    pub ipv6: BTreeSet<Ipv6Addr>,
    pub sources: BTreeSet<Source>,
    pub hostname: Option<String>,
    /// Authoritative lease (from a server DHCPACK or from the lease file).
    pub lease: Option<Lease>,
    /// Asked for DHCP at some point (DISCOVER/REQUEST/INFORM observed).
    pub tried_dhcp: bool,
    pub last_seen: Instant,
}

impl Host {
    fn new(mac: MacAddr) -> Host {
        let now = Instant::now();
        Host {
            mac,
            ipv4_owned: BTreeSet::new(),
            ipv4_routed: BTreeSet::new(),
            ipv6: BTreeSet::new(),
            sources: BTreeSet::new(),
            hostname: None,
            lease: None,
            tried_dhcp: false,
            last_seen: now,
        }
    }

}

pub fn is_apipa(ip: &Ipv4Addr) -> bool {
    ip.octets()[0] == 169 && ip.octets()[1] == 254
}

impl Host {
    /// Every known IPv4 (owned + routed), for display.
    pub fn ipv4_all(&self) -> BTreeSet<Ipv4Addr> {
        self.ipv4_owned.union(&self.ipv4_routed).copied().collect()
    }

    /// The addresses that stand for the device's IDENTITY: the owned ones when
    /// there are any; otherwise the routed ones, which are the only signal left
    /// for a silent static host.
    pub fn identity_ipv4(&self) -> &BTreeSet<Ipv4Addr> {
        if self.ipv4_owned.is_empty() {
            &self.ipv4_routed
        } else {
            &self.ipv4_owned
        }
    }
}

#[derive(Default)]
pub struct Inventory {
    pub hosts: BTreeMap<MacAddr, Host>,
    /// Leases on record whose MAC never showed up any other way.
    pub orphan_leases: BTreeMap<MacAddr, Lease>,
}

impl Inventory {
    pub fn new() -> Inventory {
        Inventory::default()
    }

    pub fn apply(&mut self, ev: Event) {
        match ev {
            Event::V4 { mac, ip, src } => {
                if mac.is_broadcast() || mac == MacAddr::zero() {
                    return;
                }
                let h = self.hosts.entry(mac).or_insert_with(|| Host::new(mac));
                // ArpReply/Gratuitous/ArpRequest(sender)/Dhcp prove ownership;
                // Ipv4Source is merely observed traffic, possibly routed.
                match src {
                    Source::Ipv4Source => {
                        h.ipv4_routed.insert(ip);
                    }
                    _ => {
                        h.ipv4_owned.insert(ip);
                    }
                }
                h.sources.insert(src);
                h.last_seen = Instant::now();
            }
            Event::V6 { mac, ip } => {
                if mac.is_broadcast() || mac == MacAddr::zero() {
                    return;
                }
                let h = self.hosts.entry(mac).or_insert_with(|| Host::new(mac));
                h.ipv6.insert(ip);
                h.sources.insert(Source::Ndp);
                h.last_seen = Instant::now();
            }
            Event::Dhcp(obs) => self.apply_dhcp(*obs),
        }
    }

    fn apply_dhcp(&mut self, obs: DhcpObservation) {
        let mac = obs.client_mac;
        if mac.is_broadcast() || mac == MacAddr::zero() {
            return;
        }
        let h = self.hosts.entry(mac).or_insert_with(|| Host::new(mac));
        h.sources.insert(Source::Dhcp);
        h.last_seen = Instant::now();
        if h.hostname.is_none() {
            h.hostname = obs.hostname.clone();
        }

        match obs.msg_type {
            // Only the server's ACK creates an authoritative lease.
            MsgType::Ack => {
                if let Some(ip) = obs.assigned {
                    h.lease = Some(Lease {
                        ip,
                        hostname: obs.hostname.clone(),
                        lease_secs: obs.lease_secs,
                        server: obs.server,
                    });
                    h.ipv4_owned.insert(ip);
                }
                h.tried_dhcp = true;
            }
            MsgType::Discover | MsgType::Request | MsgType::Inform | MsgType::Decline => {
                h.tried_dhcp = true;
            }
            MsgType::Release => {
                h.tried_dhcp = true;
                h.lease = None;
            }
            _ => {}
        }
    }

    /// Injects leases read from a DHCP server's lease file.
    pub fn merge_lease_file(&mut self, leases: Vec<(MacAddr, Lease)>) {
        for (mac, lease) in leases {
            match self.hosts.get_mut(&mac) {
                Some(h) => {
                    h.tried_dhcp = true;
                    if h.hostname.is_none() {
                        h.hostname = lease.hostname.clone();
                    }
                    h.lease = Some(lease);
                }
                None => {
                    self.orphan_leases.insert(mac, lease);
                }
            }
        }
    }
}
