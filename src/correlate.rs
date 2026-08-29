use crate::capture::Source;
use crate::inventory::{is_apipa, Host, Inventory};
use crate::oui::{is_locally_administered, OuiDb};
use ipnet::Ipv4Net;
use pnet::util::MacAddr;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Severity {
    Info,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Flag {
    /// What we are hunting for: an IP outside every legitimate subnet.
    OutsideSubnet { ips: Vec<Ipv4Addr> },
    /// Present at L2 (answered IPv6 or emitted frames) with no known IPv4.
    L2Only,
    /// Alive on the network with no DHCP lease observed for it.
    NoLease,
    /// DHCP handed out one address and the device uses another.
    LeaseMismatch { lease: Ipv4Addr, in_use: Vec<Ipv4Addr> },
    /// Two distinct MACs claiming the same IPv4.
    DuplicateIp { ip: Ipv4Addr, others: Vec<String> },
    /// DHCP failed and the device fell back to 169.254/16.
    Apipa { ip: Ipv4Addr },
    /// Lease on record, but the MAC no longer shows up on the network.
    OrphanLease { ip: Ipv4Addr },
}

impl Flag {
    pub fn code(&self) -> &'static str {
        match self {
            Flag::OutsideSubnet { .. } => "OUTSIDE_SUBNET",
            Flag::L2Only => "L2_ONLY",
            Flag::NoLease => "NO_LEASE",
            Flag::LeaseMismatch { .. } => "LEASE_MISMATCH",
            Flag::DuplicateIp { .. } => "DUPLICATE_IP",
            Flag::Apipa { .. } => "APIPA",
            Flag::OrphanLease { .. } => "ORPHAN_LEASE",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Flag::OutsideSubnet { .. } | Flag::L2Only => Severity::Critical,
            Flag::NoLease | Flag::LeaseMismatch { .. } | Flag::DuplicateIp { .. } | Flag::Apipa { .. } => {
                Severity::High
            }
            Flag::OrphanLease { .. } => Severity::Info,
        }
    }

    pub fn explain(&self) -> String {
        match self {
            Flag::OutsideSubnet { ips } => format!(
                "uses {} — outside every expected subnet; static IP set on the device itself",
                join(ips)
            ),
            Flag::L2Only => {
                "answers on the link but never revealed an IPv4 — likely a silent static \
                 address; raise --passive-secs or widen --scope"
                    .into()
            }
            Flag::NoLease => {
                "no DHCPACK observed for this MAC — it never took an address from the server"
                    .into()
            }
            Flag::LeaseMismatch { lease, in_use } => {
                format!("DHCP handed out {} but the device uses {}", lease, join(in_use))
            }
            Flag::DuplicateIp { ip, others } => {
                format!("{} is also claimed by {}", ip, others.join(", "))
            }
            Flag::Apipa { ip } => {
                format!("fell back to {} (APIPA): asked for DHCP and got no answer", ip)
            }
            Flag::OrphanLease { ip } => {
                format!("lease for {} on record, but the MAC no longer answers", ip)
            }
        }
    }
}

fn join(ips: &[Ipv4Addr]) -> String {
    ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub mac: String,
    pub vendor: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub hostname: Option<String>,
    pub lease: Option<String>,
    pub lease_secs: Option<u32>,
    pub lease_server: Option<String>,
    pub sources: Vec<String>,
    pub flags: Vec<Flag>,
    pub severity: Severity,
    pub locally_administered: bool,
}

pub fn analyze(inv: &Inventory, expected: &[Ipv4Net], oui: &OuiDb) -> Vec<Finding> {
    let dup = duplicate_ips(inv);
    // "I saw no lease" is only evidence when a lease FILE was loaded, because
    // only the file is a complete picture. Sniffing a single DHCPACK proves a
    // DHCP server exists and says nothing about any other host: leases renew
    // hours apart, so in a few seconds on the wire we see almost none of them.
    // Treating one stray ACK as a baseline flagged every host on the network —
    // missing data dressed up as a finding, drowning the one that mattered.
    let dhcp_baseline = inv.lease_file_loaded;
    let mut out = Vec::new();

    for host in inv.hosts.values() {
        let flags = flags_for(host, expected, dhcp_baseline, &dup);
        let severity = flags.iter().map(|f| f.severity()).max().unwrap_or(Severity::Info);

        out.push(Finding {
            mac: host.mac.to_string(),
            vendor: oui.lookup(host.mac).map(|s| s.to_string()),
            ipv4: host.ipv4_all().iter().map(|i| i.to_string()).collect(),
            ipv6: host.ipv6.iter().map(|i| i.to_string()).collect(),
            hostname: host.hostname.clone(),
            lease: host.lease.as_ref().map(|l| l.ip.to_string()),
            lease_secs: host.lease.as_ref().and_then(|l| l.lease_secs),
            lease_server: host.lease.as_ref().and_then(|l| l.server).map(|s| s.to_string()),
            sources: host.sources.iter().map(|s| s.label().to_string()).collect(),
            flags,
            severity,
            locally_administered: is_locally_administered(host.mac),
        });
    }

    for (mac, lease) in &inv.orphan_leases {
        let flags = vec![Flag::OrphanLease { ip: lease.ip }];
        out.push(Finding {
            mac: mac.to_string(),
            vendor: oui.lookup(*mac).map(|s| s.to_string()),
            ipv4: vec![],
            ipv6: vec![],
            hostname: lease.hostname.clone(),
            lease: Some(lease.ip.to_string()),
            lease_secs: lease.lease_secs,
            lease_server: lease.server.map(|s| s.to_string()),
            sources: vec!["lease-file".into()],
            flags,
            severity: Severity::Info,
            locally_administered: is_locally_administered(*mac),
        });
    }

    // Worst first; within the same severity, a stable order by MAC.
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.mac.cmp(&b.mac)));
    out
}

fn flags_for(
    host: &Host,
    expected: &[Ipv4Net],
    dhcp_baseline: bool,
    dup: &BTreeMap<Ipv4Addr, Vec<MacAddr>>,
) -> Vec<Flag> {
    let mut flags = Vec::new();

    let identity = host.identity_ipv4();
    let apipa: Vec<Ipv4Addr> = identity.iter().copied().filter(is_apipa_ref).collect();
    let routable: Vec<Ipv4Addr> = identity.iter().copied().filter(|i| !is_apipa(i)).collect();

    // "Outside the subnet" only makes sense for a PRIVATE address outside the
    // expected range. A public IP seen on a LAN MAC is not the device's own
    // address: it is routed/NAT traffic crossing the gateway. Flagging it would
    // be a glaring false positive (the gateway "using" 1.1.1.1, 8.8.8.8, ...).
    let foreign: Vec<Ipv4Addr> = routable
        .iter()
        .copied()
        .filter(|ip| is_private(ip) && !expected.iter().any(|n| n.contains(ip)))
        .collect();

    if !foreign.is_empty() {
        flags.push(Flag::OutsideSubnet { ips: foreign });
    }

    if host.ipv4_all().is_empty() {
        flags.push(Flag::L2Only);
    }

    if let Some(ip) = apipa.first() {
        flags.push(Flag::Apipa { ip: *ip });
    }

    match &host.lease {
        Some(lease) => {
            let mismatched: Vec<Ipv4Addr> =
                routable.iter().copied().filter(|ip| *ip != lease.ip).collect();
            if !mismatched.is_empty() {
                flags.push(Flag::LeaseMismatch { lease: lease.ip, in_use: mismatched });
            }
        }
        None => {
            // Only accuse a host of having no lease if it proved to be alive —
            // and only when there is a DHCP baseline to compare against.
            let alive = host.sources.iter().any(|s| {
                matches!(s, Source::ArpReply | Source::Ndp | Source::Ipv4Source | Source::Gratuitous)
            });
            if alive && dhcp_baseline {
                flags.push(Flag::NoLease);
            }
        }
    }

    for ip in &routable {
        if let Some(macs) = dup.get(ip) {
            let others: Vec<String> =
                macs.iter().filter(|m| **m != host.mac).map(|m| m.to_string()).collect();
            if !others.is_empty() {
                flags.push(Flag::DuplicateIp { ip: *ip, others });
            }
        }
    }

    flags
}

fn is_apipa_ref(ip: &Ipv4Addr) -> bool {
    is_apipa(ip)
}

/// Private space (RFC 1918) plus CGNAT (RFC 6598, 100.64/10). Anything outside
/// that, seen on a local MAC, is routed traffic rather than the device's own
/// address.
fn is_private(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
}

fn duplicate_ips(inv: &Inventory) -> BTreeMap<Ipv4Addr, Vec<MacAddr>> {
    let mut map: BTreeMap<Ipv4Addr, Vec<MacAddr>> = BTreeMap::new();
    for host in inv.hosts.values() {
        // A duplicate only means something among OWNED addresses; two routers
        // forwarding the same external IP is not an address conflict.
        for ip in &host.ipv4_owned {
            map.entry(*ip).or_default().push(host.mac);
        }
    }
    map.retain(|_, macs| macs.len() > 1);
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{Event, Source};
    use crate::inventory::Inventory;
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    fn expected() -> Vec<Ipv4Net> {
        vec!["192.168.1.0/24".parse().unwrap()]
    }

    fn find<'a>(fs: &'a [Finding], mac: &str) -> &'a Finding {
        fs.iter().find(|f| f.mac == mac).expect("finding for mac")
    }

    fn has(f: &Finding, code: &str) -> bool {
        f.flags.iter().any(|fl| fl.code() == code)
    }

    #[test]
    fn ip_outside_the_subnet_is_critical() {
        let oui = OuiDb::load();
        let mut inv = Inventory::new();
        let mac = MacAddr::new(0xca, 0x68, 0xac, 0x1a, 0xc7, 0xf7);
        inv.apply(Event::V4 { mac, ip: Ipv4Addr::new(10, 37, 129, 88), src: Source::ArpReply });

        let fs = analyze(&inv, &expected(), &oui);
        let f = find(&fs, &mac.to_string());
        assert!(has(f, "OUTSIDE_SUBNET"));
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn ip_inside_the_subnet_does_not_fire() {
        let oui = OuiDb::load();
        let mut inv = Inventory::new();
        let mac = MacAddr::new(0xf0, 0xda, 0x5e, 0x54, 0xfc, 0xee);
        inv.apply(Event::V4 { mac, ip: Ipv4Addr::new(192, 168, 1, 24), src: Source::ArpReply });

        let fs = analyze(&inv, &expected(), &oui);
        let f = find(&fs, &mac.to_string());
        assert!(!has(f, "OUTSIDE_SUBNET"));
        // With NO lease source in the session, "I saw no lease" proves nothing:
        // it would accuse the whole network on missing data.
        assert!(!has(f, "NO_LEASE"));
    }

    #[test]
    fn no_lease_needs_a_lease_file() {
        let oui = OuiDb::load();
        let mut inv = Inventory::new();
        let silent = MacAddr::new(0xf0, 0xda, 0x5e, 0x54, 0xfc, 0xee);
        let leased = MacAddr::new(0xf0, 0xda, 0x5e, 0x54, 0xfc, 0xef);
        inv.apply(Event::V4 { mac: silent, ip: Ipv4Addr::new(192, 168, 1, 24), src: Source::ArpReply });
        inv.apply(Event::V4 {
            mac: leased,
            ip: Ipv4Addr::new(192, 168, 1, 25),
            src: Source::ArpReply,
        });
        // A loaded lease file is the complete picture, so from here on the
        // absence of a lease genuinely means something.
        inv.merge_lease_file(vec![(
            leased,
            crate::dhcp::Lease {
                ip: Ipv4Addr::new(192, 168, 1, 25),
                hostname: None,
                lease_secs: None,
                server: None,
            },
        )]);

        let fs = analyze(&inv, &expected(), &oui);
        assert!(has(find(&fs, &silent.to_string()), "NO_LEASE"));
        assert!(!has(find(&fs, &leased.to_string()), "NO_LEASE"));
    }

    #[test]
    fn a_sniffed_dhcpack_alone_is_not_a_baseline() {
        // Measured on a live network: exactly one DHCPACK was captured — this
        // machine's own renewal — and it turned NO_LEASE on for all 23 other
        // hosts, about which nothing had been learned. One ACK proves a server
        // exists, not that host X went without a lease.
        let oui = OuiDb::load();
        let mut inv = Inventory::new();
        let silent = MacAddr::new(0xf0, 0xda, 0x5e, 0x54, 0xfc, 0xee);
        let renewing = MacAddr::new(0xf0, 0xda, 0x5e, 0x54, 0xfc, 0xef);
        inv.apply(Event::V4 { mac: silent, ip: Ipv4Addr::new(192, 168, 1, 24), src: Source::ArpReply });
        inv.apply(Event::Dhcp(Box::new(crate::dhcp::DhcpObservation {
            client_mac: renewing,
            msg_type: crate::dhcp::MsgType::Ack,
            assigned: Some(Ipv4Addr::new(192, 168, 1, 25)),
            requested: None,
            hostname: None,
            lease_secs: None,
            server: Some(Ipv4Addr::new(192, 168, 1, 1)),
        })));

        let fs = analyze(&inv, &expected(), &oui);
        // The ACK was recorded as a lease for its own host...
        assert_eq!(find(&fs, &renewing.to_string()).lease.as_deref(), Some("192.168.1.25"));
        // ...but it must not turn every other host into a NO_LEASE finding.
        assert!(!has(find(&fs, &silent.to_string()), "NO_LEASE"));
    }

    #[test]
    fn l2_only_when_there_is_just_ipv6() {
        let oui = OuiDb::load();
        let mut inv = Inventory::new();
        let mac = MacAddr::new(0xfc, 0x52, 0xce, 0x81, 0xba, 0x2d);
        inv.apply(Event::V6 { mac, ip: "fe80::fe52:ceff:fe81:ba2d".parse().unwrap() });

        let fs = analyze(&inv, &expected(), &oui);
        let f = find(&fs, &mac.to_string());
        assert!(has(f, "L2_ONLY"));
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn duplicate_ip_between_two_macs() {
        let oui = OuiDb::load();
        let mut inv = Inventory::new();
        let a = MacAddr::new(1, 1, 1, 1, 1, 1);
        let b = MacAddr::new(2, 2, 2, 2, 2, 2);
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        inv.apply(Event::V4 { mac: a, ip, src: Source::ArpReply });
        inv.apply(Event::V4 { mac: b, ip, src: Source::ArpReply });

        let fs = analyze(&inv, &expected(), &oui);
        assert!(has(find(&fs, &a.to_string()), "DUPLICATE_IP"));
        assert!(has(find(&fs, &b.to_string()), "DUPLICATE_IP"));
    }

    #[test]
    fn public_ip_on_the_gateway_is_not_outside_the_subnet() {
        // The gateway routes traffic: public IPs show up as the source on its
        // MAC. That must NOT be reported as a static IP outside the range.
        let oui = OuiDb::load();
        let mut inv = Inventory::new();
        let gw = MacAddr::new(0xbc, 0x24, 0x11, 0xa8, 0xaf, 0x41);
        inv.apply(Event::V4 { mac: gw, ip: Ipv4Addr::new(192, 168, 1, 1), src: Source::ArpReply });
        inv.apply(Event::V4 { mac: gw, ip: Ipv4Addr::new(1, 1, 1, 1), src: Source::Ipv4Source });
        inv.apply(Event::V4 { mac: gw, ip: Ipv4Addr::new(34, 149, 66, 165), src: Source::Ipv4Source });

        let fs = analyze(&inv, &expected(), &oui);
        let f = find(&fs, &gw.to_string());
        assert!(!has(f, "OUTSIDE_SUBNET"), "routed public IP must not raise an alert");
    }

    #[test]
    fn private_ip_outside_the_range_still_fires() {
        // But a PRIVATE address outside the range is exactly the target.
        let oui = OuiDb::load();
        let mut inv = Inventory::new();
        let mac = MacAddr::new(0xca, 0x68, 0xac, 0x1a, 0xc7, 0xf7);
        inv.apply(Event::V4 { mac, ip: Ipv4Addr::new(10, 37, 129, 88), src: Source::Ipv4Source });
        let fs = analyze(&inv, &expected(), &oui);
        let f = find(&fs, &mac.to_string());
        assert!(has(f, "OUTSIDE_SUBNET"));
    }

    #[test]
    fn apipa_is_flagged_and_not_confused_with_outside_subnet() {
        let oui = OuiDb::load();
        let mut inv = Inventory::new();
        let mac = MacAddr::new(3, 3, 3, 3, 3, 3);
        inv.apply(Event::V4 { mac, ip: Ipv4Addr::new(169, 254, 5, 9), src: Source::ArpReply });

        let fs = analyze(&inv, &expected(), &oui);
        let f = find(&fs, &mac.to_string());
        assert!(has(f, "APIPA"));
        // 169.254 must not be treated as "outside the subnet" — it is a different thing
        assert!(!has(f, "OUTSIDE_SUBNET"));
    }

    #[test]
    fn ordering_puts_critical_before_high() {
        let oui = OuiDb::load();
        let mut inv = Inventory::new();
        let high = MacAddr::new(0xf0, 0xda, 0x5e, 0, 0, 1);
        let critical = MacAddr::new(0xca, 0x68, 0xac, 0, 0, 2);
        inv.apply(Event::V4 { mac: high, ip: Ipv4Addr::new(192, 168, 1, 30), src: Source::ArpReply });
        inv.apply(Event::V4 { mac: critical, ip: Ipv4Addr::new(10, 1, 1, 1), src: Source::ArpReply });

        let fs = analyze(&inv, &expected(), &oui);
        assert_eq!(fs[0].mac, critical.to_string(), "critical must come first");
    }
}
