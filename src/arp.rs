use crate::iface::Local;
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use pnet::datalink::DataLinkSender;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::MutablePacket;
use pnet::util::MacAddr;
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const ETH_HDR: usize = 14;
const ARP_LEN: usize = 28;
const FRAME: usize = ETH_HDR + ARP_LEN;

/// Write buffer size for the datalink channel. pnet defaults to 4096 bytes,
/// which would cap every burst at ~97 frames; with 4 MiB a burst of thousands
/// of packets fits comfortably.
pub const WRITE_BUF: usize = 4 * 1024 * 1024;
/// Packets-per-burst ceiling imposed by the buffer above.
const MAX_BURST: usize = WRITE_BUF / FRAME;
/// Packets-per-burst ceiling for *broadcast safety*. Every ARP request goes out
/// as broadcast and is flooded to all switch ports. Large instantaneous bursts
/// trip the "broadcast storm control" on managed switches, which then starts
/// DROPPING broadcasts — including the replies we are after. Measured: during a
/// 100-packet burst, a scan of the same /24 returned noticeably fewer replies
/// than with a small burst. Keeping bursts small smooths the send rate and the
/// switch never reacts.
const SAFE_BURST: usize = 16;

/// Which address to put in the ARP request's "sender protocol address" field.
///
/// This is the most delicate point of the tool. Measured in a lab against a
/// Linux target holding a static address in a subnet the prober is not part of:
///
/// | sender                        | reply    |
/// |-------------------------------|----------|
/// | our own IP (another subnet)   | none     |
/// | the target's own address      | none     |
/// | a neighbour of the target     | answers  |
/// | 0.0.0.0 (ARP probe)           | answers  |
///
/// In short: a sender from another subnet is ignored. The RFC 5227 ARP probe
/// solves that and is also the only option that dirties nobody's ARP cache — a
/// forged neighbour sender would be recorded as a bogus IP->MAC pair for the
/// gateway on every host of the segment, which is ARP poisoning.
#[derive(Debug, Clone, Copy)]
pub enum Spa {
    /// sender 0.0.0.0 (RFC 5227). The default: reaches any subnet and writes
    /// into nobody's ARP cache.
    Probe,
    /// Our own address. Only works inside our own subnet.
    Local,
    /// The target itself: mimics duplicate-address detection.
    Dest,
    /// First host of the target's subnet. Beats stacks that ignore the probe,
    /// but POISONS the neighbours' ARP caches with a bogus pair — use knowingly.
    Neighbor,
    Fixed(Ipv4Addr),
}

impl Spa {
    pub fn parse(s: &str) -> Result<Spa> {
        match s {
            "probe" | "auto" => Ok(Spa::Probe),
            "local" => Ok(Spa::Local),
            "dest" => Ok(Spa::Dest),
            "neighbor" => Ok(Spa::Neighbor),
            other => {
                let ip: Ipv4Addr = other.parse().with_context(|| {
                    format!("invalid --spa: {:?} (use probe, local, dest, neighbor or an IPv4)", other)
                })?;
                Ok(Spa::Fixed(ip))
            }
        }
    }

    fn for_target(&self, target: Ipv4Addr, local: Option<Ipv4Addr>) -> Ipv4Addr {
        match self {
            Spa::Probe => Ipv4Addr::UNSPECIFIED,
            // Without a local IPv4 the `local` mode is rejected before it gets
            // here (`scan::validate_spa`); this fallback is belt and braces.
            Spa::Local => local.unwrap_or(Ipv4Addr::UNSPECIFIED),
            Spa::Dest => target,
            Spa::Neighbor => {
                let [a, b, c, d] = target.octets();
                // Avoid colliding with the target itself when it is the .1
                Ipv4Addr::new(a, b, c, if d == 1 { 2 } else { 1 })
            }
            Spa::Fixed(ip) => *ip,
        }
    }

    /// Neighbor mode forges an address other hosts may end up caching.
    pub fn poisons_arp_cache(&self) -> bool {
        matches!(self, Spa::Neighbor | Spa::Fixed(_))
    }
}

/// Builds a complete Ethernet+ARP request frame inside `buf` (42 bytes).
fn build_request(buf: &mut [u8], local: &Local, spa: Ipv4Addr, target: Ipv4Addr) {
    let mut eth = MutableEthernetPacket::new(buf).expect("42-byte buffer");
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(local.mac);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp = MutableArpPacket::new(eth.payload_mut()).expect("28-byte payload");
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(local.mac);
    arp.set_sender_proto_addr(spa);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target);
}

/// Sweep pacing parameters, grouped so we do not carry six arguments around.
#[derive(Debug, Clone, Copy)]
pub struct Pace {
    /// Packets per second inside one /24 block.
    pub rate: u64,
    /// Silence after each /24, in milliseconds. This is what keeps storm
    /// control at bay: every /24 becomes a short burst followed by quiet, the
    /// pattern in which replies get through and the switch stands down.
    pub settle_ms: u64,
    /// How many times to resend each /24. A reply lost on one pass tends to
    /// arrive on the next; arp-scan uses the same idea with --retry.
    pub passes: u32,
}

impl Default for Pace {
    fn default() -> Self {
        Pace { rate: 2_000, settle_ms: 150, passes: 2 }
    }
}

/// Sends ARP requests to every host of the given networks.
///
/// The sweep runs **one /24 at a time**, with silence between blocks. That was
/// an empirical finding: an isolated /24 finds its hosts reliably, but
/// appending a large broadcast block right behind it collapses the count — the
/// managed switch turns on broadcast storm control and starts dropping frames.
/// Short-burst-then-quiet, per /24, keeps the average broadcast rate under the
/// trigger.
///
/// Networks are expanded into /24s lazily: sweeping 10.0.0.0/8 never
/// materialises 16 million addresses in memory.
/// Do two ranges touch? It is enough for one to contain the other's network.
fn overlaps(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Addresses of a /24 block that survive the ignored ranges. A fully covered
/// block becomes empty; an untouched block never pays for the filter; only a
/// partially covered block is walked address by address — and that only happens
/// when the exclusion is smaller than a /24.
fn block_addrs(block: Ipv4Net, excluded: &[Ipv4Net]) -> Vec<Ipv4Addr> {
    if excluded.iter().any(|x| x.contains(&block)) {
        return Vec::new();
    }
    if !excluded.iter().any(|x| overlaps(&block, x)) {
        return hosts(block).collect();
    }
    hosts(block).filter(|ip| !excluded.iter().any(|x| x.contains(ip))).collect()
}

/// How many addresses the block contributes, without materialising the list.
fn block_count(block: Ipv4Net, excluded: &[Ipv4Net]) -> u64 {
    if excluded.iter().any(|x| x.contains(&block)) {
        return 0;
    }
    if !excluded.iter().any(|x| overlaps(&block, x)) {
        return host_count(&block);
    }
    hosts(block).filter(|ip| !excluded.iter().any(|x| x.contains(ip))).count() as u64
}

pub fn sweep(
    tx: &mut Box<dyn DataLinkSender>,
    local: &Local,
    nets: &[Ipv4Net],
    excluded: &[Ipv4Net],
    spa: Spa,
    pace: Pace,
    stop: &'static AtomicBool,
    progress: &crate::scan::ScanProgress,
    verbose: bool,
) -> Result<u64> {
    let hosts_total: u64 =
        nets.iter().flat_map(|n| slash24_blocks(*n)).map(|b| block_count(b, excluded)).sum();
    if hosts_total == 0 {
        return Ok(0);
    }
    let passes = pace.passes.max(1) as u64;
    // Total work counts the resends, or progress would run past 100%.
    let total = hosts_total * passes;
    let big = hosts_total > 4096;
    progress.sent.store(0, std::sync::atomic::Ordering::Relaxed);
    progress.total.store(total, std::sync::atomic::Ordering::Relaxed);

    let burst = ((pace.rate / 100).clamp(1, SAFE_BURST as u64) as usize).min(MAX_BURST);
    let burst_window = Duration::from_secs_f64(burst as f64 / pace.rate as f64);
    let settle = Duration::from_millis(pace.settle_ms);

    let started = Instant::now();
    let mut sent: u64 = 0;
    let mut last_report = Instant::now();

    for net in nets {
        for slash24 in slash24_blocks(*net) {
            if stop.load(Ordering::Relaxed) {
                return finish(sent, total, big && verbose, started);
            }
            let addrs = block_addrs(slash24, excluded);
            if addrs.is_empty() {
                continue;
            }

            for _pass in 0..pace.passes.max(1) {
                if stop.load(Ordering::Relaxed) {
                    return finish(sent, total, big && verbose, started);
                }
                send_block(tx, local, spa, &addrs, burst, burst_window)?;
                sent += addrs.len() as u64;
                progress.sent.store(sent, std::sync::atomic::Ordering::Relaxed);

                // The quiet window is what lets replies come back without
                // competing against the next broadcast burst.
                if !settle.is_zero() {
                    std::thread::sleep(settle);
                }

                if verbose && big && last_report.elapsed() >= Duration::from_secs(3) {
                    report_progress(sent, total, started);
                    last_report = Instant::now();
                }
            }
        }
    }

    finish(sent, total, big && verbose, started)
}

/// Emits a block of addresses honouring the safe burst size and target rate.
fn send_block(
    tx: &mut Box<dyn DataLinkSender>,
    local: &Local,
    spa: Spa,
    addrs: &[Ipv4Addr],
    burst: usize,
    burst_window: Duration,
) -> Result<()> {
    for group in addrs.chunks(burst) {
        let batch_start = Instant::now();
        let mut idx = 0usize;
        let res = tx.build_and_send(group.len(), FRAME, &mut |buf: &mut [u8]| {
            let target = group[idx];
            idx += 1;
            build_request(buf, local, spa.for_target(target, local.ipv4), target);
        });
        match res {
            Some(Ok(())) => {}
            Some(Err(e)) => return Err(e).context("failed to send ARP request"),
            None => anyhow::bail!("send buffer too small for {} packets", group.len()),
        }
        if let Some(rest) = burst_window.checked_sub(batch_start.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    Ok(())
}

fn finish(sent: u64, total: u64, big: bool, started: Instant) -> Result<u64> {
    if big {
        report_progress(sent, total, started);
        eprintln!();
    }
    Ok(sent)
}

/// Splits a network into aligned /24 blocks, lazily. Networks smaller than a
/// /24 (prefix > 24) are returned whole.
fn slash24_blocks(net: Ipv4Net) -> Box<dyn Iterator<Item = Ipv4Net>> {
    if net.prefix_len() >= 24 {
        return Box::new(std::iter::once(net));
    }
    let base = u32::from(net.network());
    let count = 1u32 << (24 - net.prefix_len() as u32); // how many /24s fit
    Box::new((0..count).map(move |i| {
        let addr = Ipv4Addr::from(base + (i << 8));
        Ipv4Net::new(addr, 24).expect("valid /24")
    }))
}

fn report_progress(sent: u64, total: u64, started: Instant) {
    let sent = sent.min(total);
    let pct = sent as f64 / total as f64 * 100.0;
    let elapsed = started.elapsed().as_secs_f64();
    let pps = if elapsed > 0.0 { sent as f64 / elapsed } else { 0.0 };
    let eta = if pps > 0.0 { total.saturating_sub(sent) as f64 / pps } else { 0.0 };
    eprint!(
        "\r  sweep: {:>5.1}%  {}/{} packets  {:.0} pps  ETA {}   ",
        pct,
        sent,
        total,
        pps,
        fmt_dur(eta)
    );
    let _ = std::io::stderr().flush();
}

fn fmt_dur(secs: f64) -> String {
    let s = secs as u64;
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}s", s)
    }
}

/// Probeable addresses of a network. For /31 and /32 there is no usable-host
/// concept, so we hand back the raw addresses.
pub fn hosts(net: Ipv4Net) -> Box<dyn Iterator<Item = Ipv4Addr>> {
    if net.prefix_len() >= 31 {
        let (a, b) = (net.network(), net.broadcast());
        if a == b {
            Box::new(std::iter::once(a))
        } else {
            Box::new(vec![a, b].into_iter())
        }
    } else {
        Box::new(net.hosts())
    }
}

pub fn host_count(net: &Ipv4Net) -> u64 {
    match net.prefix_len() {
        32 => 1,
        31 => 2,
        p => (1u64 << (32 - p)) - 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_count_per_prefix() {
        assert_eq!(host_count(&"192.168.1.0/24".parse().unwrap()), 254);
        assert_eq!(host_count(&"10.0.0.0/8".parse().unwrap()), (1 << 24) - 2);
        assert_eq!(host_count(&"192.168.1.4/31".parse().unwrap()), 2);
        assert_eq!(host_count(&"192.168.1.4/32".parse().unwrap()), 1);
    }

    #[test]
    fn slash24_expands_a_16_into_256_blocks() {
        let net: Ipv4Net = "192.168.0.0/16".parse().unwrap();
        let blocks: Vec<_> = slash24_blocks(net).collect();
        assert_eq!(blocks.len(), 256);
        assert_eq!(blocks[0], "192.168.0.0/24".parse().unwrap());
        assert_eq!(blocks[1], "192.168.1.0/24".parse().unwrap());
        assert_eq!(blocks[255], "192.168.255.0/24".parse().unwrap());
    }

    #[test]
    fn slash24_devolve_rede_menor_inteira() {
        let net: Ipv4Net = "10.37.129.0/24".parse().unwrap();
        let blocks: Vec<_> = slash24_blocks(net).collect();
        assert_eq!(blocks, vec![net]);
        let small: Ipv4Net = "10.0.0.0/28".parse().unwrap();
        assert_eq!(slash24_blocks(small).collect::<Vec<_>>(), vec![small]);
    }

    #[test]
    fn probe_uses_zero_as_the_sender() {
        let target = Ipv4Addr::new(10, 37, 129, 88);
        let local = Ipv4Addr::new(192, 168, 1, 18);
        assert_eq!(Spa::Probe.for_target(target, Some(local)), Ipv4Addr::UNSPECIFIED);
        assert_eq!(Spa::Local.for_target(target, Some(local)), local);
        assert_eq!(Spa::Dest.for_target(target, Some(local)), target);
        // With no IPv4 on the interface the probe still works: sender 0.0.0.0.
        assert_eq!(Spa::Probe.for_target(target, None), Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn neighbor_does_not_collide_with_a_dot_one_target() {
        let local = Some(Ipv4Addr::new(192, 168, 1, 18));
        // target .1 -> neighbour becomes .2 so we do not probe the target itself
        assert_eq!(
            Spa::Neighbor.for_target(Ipv4Addr::new(10, 0, 0, 1), local),
            Ipv4Addr::new(10, 0, 0, 2)
        );
        // ordinary target -> neighbour .1
        assert_eq!(
            Spa::Neighbor.for_target(Ipv4Addr::new(10, 0, 0, 88), local),
            Ipv4Addr::new(10, 0, 0, 1)
        );
    }

    #[test]
    fn so_neighbor_e_fixed_poluem_cache() {
        assert!(!Spa::Probe.poisons_arp_cache());
        assert!(!Spa::Local.poisons_arp_cache());
        assert!(Spa::Neighbor.poisons_arp_cache());
        assert!(Spa::Fixed(Ipv4Addr::LOCALHOST).poisons_arp_cache());
    }
}
