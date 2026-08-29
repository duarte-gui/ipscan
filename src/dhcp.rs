use pnet::util::MacAddr;
use std::net::Ipv4Addr;

/// BOOTP header offsets (RFC 951 / 2131).
const OP: usize = 0;
const HLEN: usize = 2;
const YIADDR: usize = 16;
const CHADDR: usize = 28;
const MAGIC: usize = 236;
const OPTIONS: usize = 240;

const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum MsgType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Other(u8),
}

impl MsgType {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => MsgType::Discover,
            2 => MsgType::Offer,
            3 => MsgType::Request,
            4 => MsgType::Decline,
            5 => MsgType::Ack,
            6 => MsgType::Nak,
            7 => MsgType::Release,
            8 => MsgType::Inform,
            o => MsgType::Other(o),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhcpObservation {
    /// Client MAC read from chaddr, not from the ethernet frame: relays lie.
    pub client_mac: MacAddr,
    pub msg_type: MsgType,
    /// Address granted by the server (yiaddr) — only meaningful in OFFER/ACK.
    pub assigned: Option<Ipv4Addr>,
    /// Option 50: the address the client asked for.
    pub requested: Option<Ipv4Addr>,
    /// Option 12: hostname advertised by the client.
    pub hostname: Option<String>,
    /// Option 51: lease duration in seconds.
    pub lease_secs: Option<u32>,
    /// Option 54: DHCP server identifier.
    pub server: Option<Ipv4Addr>,
}

/// A lease treated as authoritative: it came from a server ACK.
#[derive(Debug, Clone)]
pub struct Lease {
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub lease_secs: Option<u32>,
    pub server: Option<Ipv4Addr>,
}

/// Parses the UDP payload of port 67/68. Returns None if it is not valid BOOTP.
pub fn parse(payload: &[u8], frame_mac: MacAddr, _src: Ipv4Addr) -> Option<DhcpObservation> {
    if payload.len() < OPTIONS || payload[MAGIC..MAGIC + 4] != MAGIC_COOKIE {
        return None;
    }
    let op = payload[OP];
    if op != 1 && op != 2 {
        return None;
    }

    // chaddr holds 16 bytes but only hlen are valid; for ethernet, hlen == 6.
    let hlen = payload[HLEN] as usize;
    let client_mac = if hlen == 6 {
        MacAddr::new(
            payload[CHADDR],
            payload[CHADDR + 1],
            payload[CHADDR + 2],
            payload[CHADDR + 3],
            payload[CHADDR + 4],
            payload[CHADDR + 5],
        )
    } else {
        frame_mac
    };

    let yiaddr = Ipv4Addr::new(
        payload[YIADDR],
        payload[YIADDR + 1],
        payload[YIADDR + 2],
        payload[YIADDR + 3],
    );

    let mut obs = DhcpObservation {
        client_mac,
        msg_type: MsgType::Other(0),
        assigned: (!yiaddr.is_unspecified()).then_some(yiaddr),
        requested: None,
        hostname: None,
        lease_secs: None,
        server: None,
    };

    for (code, data) in Options::new(&payload[OPTIONS..]) {
        match code {
            53 if data.len() == 1 => obs.msg_type = MsgType::from_u8(data[0]),
            50 if data.len() == 4 => obs.requested = Some(v4(data)),
            54 if data.len() == 4 => obs.server = Some(v4(data)),
            51 if data.len() == 4 => {
                obs.lease_secs = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            12 => obs.hostname = String::from_utf8(data.to_vec()).ok().filter(|s| !s.is_empty()),
            _ => {}
        }
    }
    Some(obs)
}

fn v4(d: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(d[0], d[1], d[2], d[3])
}

/// Iterator over the DHCP options field (TLV format, with 0=pad and 255=end).
struct Options<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Options<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Options { buf, pos: 0 }
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let code = *self.buf.get(self.pos)?;
            match code {
                0 => {
                    self.pos += 1; // pad
                    continue;
                }
                255 => return None, // end
                _ => {}
            }
            let len = *self.buf.get(self.pos + 1)? as usize;
            let start = self.pos + 2;
            let end = start.checked_add(len)?;
            if end > self.buf.len() {
                return None;
            }
            self.pos = end;
            return Some((code, &self.buf[start..end]));
        }
    }
}

/// Reads a DHCP server's lease file (dnsmasq or ISC dhcpd), filling in what
/// sniffing alone would take hours to discover.
pub fn parse_leases_file(path: &str) -> anyhow::Result<Vec<(MacAddr, Lease)>> {
    let text = std::fs::read_to_string(path)?;
    // dnsmasq: "<expiry> <mac> <ip> <hostname> <client-id>" per line
    let looks_dnsmasq = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| l.split_whitespace().count() >= 4 && l.split_whitespace().nth(1).is_some_and(|m| m.contains(':')))
        .unwrap_or(false);

    if looks_dnsmasq {
        return Ok(parse_dnsmasq(&text));
    }
    Ok(parse_isc(&text))
}

fn parse_dnsmasq(text: &str) -> Vec<(MacAddr, Lease)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let (Ok(mac), Ok(ip)) = (f[1].parse::<MacAddr>(), f[2].parse::<Ipv4Addr>()) else {
            continue;
        };
        let hostname = (f[3] != "*").then(|| f[3].to_string());
        out.push((mac, Lease { ip, hostname, lease_secs: None, server: None }));
    }
    out
}

fn parse_isc(text: &str) -> Vec<(MacAddr, Lease)> {
    let mut out = Vec::new();
    let mut ip: Option<Ipv4Addr> = None;
    let mut mac: Option<MacAddr> = None;
    let mut hostname: Option<String> = None;

    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("lease ") {
            ip = rest.split_whitespace().next().and_then(|s| s.parse().ok());
            mac = None;
            hostname = None;
        } else if let Some(rest) = t.strip_prefix("hardware ethernet ") {
            mac = rest.trim_end_matches(';').parse().ok();
        } else if let Some(rest) = t.strip_prefix("client-hostname ") {
            hostname = Some(rest.trim_end_matches(';').trim_matches('"').to_string());
        } else if t == "}" {
            if let (Some(i), Some(m)) = (ip, mac) {
                out.push((m, Lease { ip: i, hostname: hostname.clone(), lease_secs: None, server: None }));
            }
            ip = None;
            mac = None;
            hostname = None;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal DHCP packet: BOOTP header + cookie + the given options.
    fn build(op: u8, chaddr: [u8; 6], yiaddr: [u8; 4], opts: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; OPTIONS];
        p[OP] = op;
        p[HLEN] = 6;
        p[YIADDR..YIADDR + 4].copy_from_slice(&yiaddr);
        p[CHADDR..CHADDR + 6].copy_from_slice(&chaddr);
        p[MAGIC..MAGIC + 4].copy_from_slice(&MAGIC_COOKIE);
        p.extend_from_slice(opts);
        p.push(255); // end
        p
    }

    #[test]
    fn ack_yields_a_lease_with_ip_and_hostname() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x11];
        // opt 53=ACK(5), opt 12=hostname "ha", opt 51=lease 7200s
        let opts = [53, 1, 5, 12, 2, b'h', b'a', 51, 4, 0, 0, 0x1c, 0x20];
        let pkt = build(2, mac, [192, 168, 1, 90], &opts);
        let obs = parse(&pkt, MacAddr::zero(), Ipv4Addr::UNSPECIFIED).expect("parse");
        assert_eq!(obs.msg_type, MsgType::Ack);
        assert_eq!(obs.client_mac, MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x11));
        assert_eq!(obs.assigned, Some(Ipv4Addr::new(192, 168, 1, 90)));
        assert_eq!(obs.hostname.as_deref(), Some("ha"));
        assert_eq!(obs.lease_secs, Some(7200));
    }

    #[test]
    fn uses_chaddr_and_not_the_frame_mac() {
        // A relay rewrites the frame MAC; chaddr preserves the real client.
        let client = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let opts = [53, 1, 3]; // REQUEST
        let pkt = build(1, client, [0, 0, 0, 0], &opts);
        let frame_mac = MacAddr::new(1, 1, 1, 1, 1, 1);
        let obs = parse(&pkt, frame_mac, Ipv4Addr::UNSPECIFIED).unwrap();
        assert_eq!(obs.client_mac, MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
        assert_eq!(obs.msg_type, MsgType::Request);
    }

    #[test]
    fn rejects_a_packet_without_the_magic_cookie() {
        let mut pkt = vec![0u8; OPTIONS + 1];
        pkt[OP] = 2;
        // no valid cookie
        assert!(parse(&pkt, MacAddr::zero(), Ipv4Addr::UNSPECIFIED).is_none());
    }

    #[test]
    fn a_truncated_option_does_not_panic() {
        let mac = [0; 6];
        // opt 51 declares 4 bytes but only 2 are there — the iterator must stop cleanly
        let opts = [51, 4, 0, 0];
        let pkt = build(2, mac, [0, 0, 0, 0], &opts);
        let obs = parse(&pkt, MacAddr::zero(), Ipv4Addr::UNSPECIFIED).unwrap();
        assert_eq!(obs.lease_secs, None);
    }

    #[test]
    fn parse_dnsmasq_reads_mac_and_ip() {
        let text = "1787975363 02:00:00:00:00:11 192.168.1.90 sensor-a *\n\
                    1787975092 02:00:00:00:00:22 192.168.1.4 * 01:02:00";
        let leases = parse_dnsmasq(text);
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].1.ip, Ipv4Addr::new(192, 168, 1, 90));
        assert_eq!(leases[0].1.hostname.as_deref(), Some("sensor-a"));
        assert_eq!(leases[1].1.hostname, None); // "*" becomes None
    }

    #[test]
    fn parse_isc_reads_a_lease_block() {
        let text = "lease 192.168.1.50 {\n  \
                    hardware ethernet 02:00:00:00:00:33;\n  \
                    client-hostname \"web-01\";\n}\n";
        let leases = parse_isc(text);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].0, MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x33));
        assert_eq!(leases[0].1.ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(leases[0].1.hostname.as_deref(), Some("web-01"));
    }
}
