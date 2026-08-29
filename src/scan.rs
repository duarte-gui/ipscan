//! Reusable scan orchestration, shared by the CLI and the TUI.
//!
//! Both take exactly the same path: `ScanHandle::start` spawns the threads
//! (capture, collector, and the four-layer driver) and returns a handle. The
//! CLI blocks waiting for the driver to finish and then reads the inventory;
//! the TUI holds the handle and reads progress and inventory every frame,
//! without blocking the interface.

use crate::cli::Scope;
use crate::{arp, capture, dhcp, iface, inventory, ndp, oui, correlate};
use anyhow::{Context, Result};
use ipnet::Ipv4Net;
use pnet::datalink::{self, Channel, Config};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Global stop flag. It is a static rather than an Arc because the SIGINT
/// handler must reach it, and only `store` on an AtomicBool is safe to call
/// from inside a signal handler. Shared by every scan in the process — the CLI
/// runs one at a time, and the TUI clears it before each new run.
pub static STOP: AtomicBool = AtomicBool::new(false);

/// Configuration of one scan. Assembled by the CLI from flags, or by the TUI
/// from the form.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Interface to use; None auto-detects the first active one.
    pub iface: Option<String>,
    /// Legitimate subnets: a private address outside all of them is suspect.
    pub expected: Vec<Ipv4Net>,
    /// IGNORED ranges (the form's "!"): subtracted from the targets after the
    /// scope has been assembled — they receive not a single packet. They also
    /// go into `expected`, so nothing coming from them reaches the screen.
    pub excluded: Vec<Ipv4Net>,
    /// Extra ranges to sweep explicitly, beyond what the scope covers.
    pub ranges: Vec<Ipv4Net>,
    pub scope: Scope,
    pub spa: arp::Spa,
    pub pace: arp::Pace,
    pub passive_secs: u64,
    pub passive_only: bool,
    pub no_ipv6: bool,
    pub leases_file: Option<String>,
    /// Print the phase lines and progress bar on stderr (the CLI does).
    pub verbose: bool,
}

/// Current scan phase, for the TUI's label and progress bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Passive,
    Ipv6,
    Sweep,
    Collecting,
    Done,
}

impl Phase {
    fn from_u8(v: u8) -> Phase {
        match v {
            1 => Phase::Passive,
            2 => Phase::Ipv6,
            3 => Phase::Sweep,
            4 => Phase::Collecting,
            5 => Phase::Done,
            _ => Phase::Idle,
        }
    }
    fn as_u8(self) -> u8 {
        match self {
            Phase::Idle => 0,
            Phase::Passive => 1,
            Phase::Ipv6 => 2,
            Phase::Sweep => 3,
            Phase::Collecting => 4,
            Phase::Done => 5,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Passive => "passive listening",
            Phase::Ipv6 => "IPv6 enumeration",
            Phase::Sweep => "ARP sweep",
            Phase::Collecting => "collecting replies",
            Phase::Done => "done",
        }
    }
}

/// Progress observable from outside without a lock. `sweep` updates `sent`/`total`.
#[derive(Debug, Default)]
pub struct ScanProgress {
    phase: AtomicU8,
    pub sent: AtomicU64,
    pub total: AtomicU64,
}

impl ScanProgress {
    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.phase.load(Ordering::Relaxed))
    }
    fn set_phase(&self, p: Phase) {
        self.phase.store(p.as_u8(), Ordering::Relaxed);
    }
    /// (sent, total) for the current sweep.
    pub fn sweep_counts(&self) -> (u64, u64) {
        (self.sent.load(Ordering::Relaxed), self.total.load(Ordering::Relaxed))
    }
    pub fn fraction(&self) -> f64 {
        let (s, t) = self.sweep_counts();
        if t == 0 {
            0.0
        } else {
            (s as f64 / t as f64).min(1.0)
        }
    }
}

/// Handle to a running (or finished) scan. While it lives, the collector keeps
/// the shared inventory updated in real time.
pub struct ScanHandle {
    pub inv: Arc<Mutex<inventory::Inventory>>,
    pub progress: Arc<ScanProgress>,
    driver: Option<JoinHandle<Result<()>>>,
    rx_thread: Option<JoinHandle<()>>,
    collector: Option<JoinHandle<()>>,
    expected: Vec<Ipv4Net>,
}

impl ScanHandle {
    /// Spawns the threads and starts the scan. Does not block.
    pub fn start(cfg: ScanConfig) -> Result<ScanHandle> {
        STOP.store(false, Ordering::Relaxed);
        capture::KERNEL_DROPS.store(0, Ordering::Relaxed);

        let local = iface::resolve(cfg.iface.as_deref())?;
        validate_spa(cfg.spa, &local)?;

        // pnet channel: we only use the sender; receiving goes through rawsock.
        let config = Config {
            read_timeout: Some(Duration::from_millis(200)),
            promiscuous: true,
            write_buffer_size: arp::WRITE_BUF,
            read_buffer_size: 1 << 20,
            ..Default::default()
        };
        let tx = match datalink::channel(&local.iface, config) {
            Ok(Channel::Ethernet(tx, _rx)) => tx,
            Ok(_) => anyhow::bail!("unsupported channel type on {}", local.iface.name),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                anyhow::bail!("{}", iface::permission_hint())
            }
            Err(e) => {
                return Err(e).with_context(|| format!("opening a channel on {}", local.iface.name))
            }
        };

        let sock = crate::rawsock::RawSocket::open(local.iface.index, 200)?;
        if !sock.ignores_outgoing && cfg.verbose {
            eprintln!(
                "warning: kernel without PACKET_IGNORE_OUTGOING (< 4.20); large sweeps \
                 may lose replies."
            );
        }

        let inv = Arc::new(Mutex::new(inventory::Inventory::new()));

        // File leases, if any, are loaded before anything else.
        if let Some(path) = &cfg.leases_file {
            let leases = dhcp::parse_leases_file(path)
                .with_context(|| format!("reading lease file {}", path))?;
            if cfg.verbose {
                eprintln!("lease file: {} entry/entries from {}", leases.len(), path);
            }
            inv.lock().unwrap().merge_lease_file(leases);
        }

        // Capture thread: raw frames -> parsed events on the channel.
        let (evt_tx, evt_rx) = mpsc::channel();
        let local_mac = local.mac;
        let rx_thread = std::thread::spawn(move || capture::rx_loop(sock, evt_tx, &STOP, local_mac));

        // Collector: applies every event to the shared inventory, forever, so
        // the inventory mirrors the live network even during the sweep.
        let inv_collector = Arc::clone(&inv);
        let collector = std::thread::spawn(move || {
            for ev in evt_rx {
                if let Ok(mut g) = inv_collector.lock() {
                    g.apply(ev);
                }
            }
        });

        let expected = cfg.expected.clone();

        // Driver: runs the four layers in the background.
        let progress = Arc::new(ScanProgress::default());
        let driver = {
            let inv = Arc::clone(&inv);
            let progress = Arc::clone(&progress);
            let local = local.clone();
            std::thread::spawn(move || run_layers(cfg, local, tx, inv, progress))
        };

        Ok(ScanHandle {
            inv,
            progress,
            driver: Some(driver),
            rx_thread: Some(rx_thread),
            collector: Some(collector),
            expected,
        })
    }

    /// Has the active sweep (driver) finished? Capture stays alive until `stop`.
    pub fn is_running(&self) -> bool {
        self.driver.as_ref().map(|h| !h.is_finished()).unwrap_or(false)
    }

    /// Computes the findings from the inventory's current state.
    pub fn findings(&self, oui: &oui::OuiDb) -> Vec<correlate::Finding> {
        let g = self.inv.lock().unwrap();
        correlate::analyze(&g, &self.expected, oui)
    }

    /// Access for one-off reads (e.g. the TUI recomputing).
    pub fn expected(&self) -> &[Ipv4Net] {
        &self.expected
    }

    /// Signals a stop and lets the active sweep end, keeping what was found.
    pub fn stop(&self) {
        STOP.store(true, Ordering::Relaxed);
    }

    /// Waits for the driver to finish naturally (used by the CLI).
    pub fn join_driver(&mut self) -> Result<()> {
        if let Some(h) = self.driver.take() {
            return h.join().unwrap_or_else(|_| Ok(()));
        }
        Ok(())
    }
}

impl Drop for ScanHandle {
    fn drop(&mut self) {
        STOP.store(true, Ordering::Relaxed);
        if let Some(h) = self.driver.take() {
            let _ = h.join();
        }
        if let Some(h) = self.rx_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.collector.take() {
            let _ = h.join();
        }
    }
}

/// The four layers, running on the driver thread.
fn run_layers(
    cfg: ScanConfig,
    local: iface::Local,
    mut tx: Box<dyn pnet::datalink::DataLinkSender>,
    inv: Arc<Mutex<inventory::Inventory>>,
    progress: Arc<ScanProgress>,
) -> Result<()> {
    // Layer 1 — passive listening. The collector is already feeding the
    // inventory; here we just give the air some time.
    if cfg.passive_secs > 0 {
        progress.set_phase(Phase::Passive);
        if cfg.verbose {
            eprintln!("[1/4] passive listening for {}s...", cfg.passive_secs);
        }
        sleep_interruptible(Duration::from_secs(cfg.passive_secs));
    }

    if !cfg.passive_only && !STOP.load(Ordering::Relaxed) {
        // Layer 2 — L2 enumeration over ICMPv6.
        if !cfg.no_ipv6 {
            if local.link_local.is_some() {
                progress.set_phase(Phase::Ipv6);
                if cfg.verbose {
                    eprintln!("[2/4] enumerating the link over ICMPv6 ff02::1...");
                }
                ndp::ping_all_nodes(&mut tx, &local, 3)?;
                sleep_interruptible(Duration::from_secs(2));
            } else if cfg.verbose {
                eprintln!("[2/4] skipped: {} has no IPv6 link-local address", local.iface.name);
            }
        }

        // Layers 3 and 4 — ARP sweep driven by the scope.
        let nets = {
            let g = inv.lock().unwrap();
            build_targets(cfg.scope, &cfg.expected, &cfg.ranges, &cfg.excluded, &g)
        };
        if !nets.is_empty() && !STOP.load(Ordering::Relaxed) {
            let total: u64 = nets.iter().map(arp::host_count).sum();
            if cfg.verbose {
                eprintln!(
                    "[3/4] ARP sweep: {} network(s), {} addresses at {} pps (~{})",
                    nets.len(),
                    total,
                    cfg.pace.rate,
                    human_eta(total, cfg.pace.rate)
                );
            }
            progress.set_phase(Phase::Sweep);
            let sweep_start = Instant::now();
            arp::sweep(
                &mut tx,
                &local,
                &nets,
                &cfg.excluded,
                cfg.spa,
                cfg.pace,
                &STOP,
                &progress,
                cfg.verbose,
            )?;
            let collect = collect_window(sweep_start.elapsed());

            progress.set_phase(Phase::Collecting);
            if cfg.verbose {
                eprintln!("[4/4] collecting replies for {:.1}s...", collect.as_secs_f64());
            }
            sleep_interruptible(collect);
        }
    }

    progress.set_phase(Phase::Done);
    Ok(())
}

/// How long to wait for replies once the sweep goes quiet. Proportional to the
/// size of the sweep: a /24 does not deserve the same 3s as a /16. The floor
/// protects congested networks; the ceiling protects the patience of someone
/// testing one hypothesis after another.
fn collect_window(sweep: Duration) -> Duration {
    (sweep / 2).clamp(Duration::from_millis(500), Duration::from_secs(3))
}

/// `spa=local` puts our own address in the sender field — impossible without an
/// IPv4 on the interface. The other modes need no address at all.
fn validate_spa(spa: arp::Spa, local: &iface::Local) -> Result<()> {
    if matches!(spa, arp::Spa::Local) && local.ipv4.is_none() {
        anyhow::bail!(
            "spa=local requires an IPv4 on interface {}, which has no address. \
             Use spa=probe (the default), which sweeps with sender 0.0.0.0.",
            local.iface.name
        );
    }
    Ok(())
}

/// Sleeps for the given duration, waking early if STOP is signalled.
fn sleep_interruptible(dur: Duration) {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        if STOP.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100).min(deadline - Instant::now()));
    }
}

/// Builds the list of networks to sweep according to the requested scope.
pub fn build_targets(
    scope: Scope,
    expected: &[Ipv4Net],
    extra: &[Ipv4Net],
    excluded: &[Ipv4Net],
    inv: &inventory::Inventory,
) -> Vec<Ipv4Net> {
    let mut nets: Vec<Ipv4Net> = extra.to_vec();

    match scope {
        Scope::None => {}
        Scope::Auto => {
            nets.extend(expected.iter().copied());
            // The /24 of every OWNED address seen so far: if listening turned
            // up 10.37.129.88, the whole 10.37.129.0/24 is worth sweeping. Only
            // owned ones — routed addresses would point at public /24s.
            for host in inv.hosts.values() {
                for ip in host.identity_ipv4() {
                    if let Ok(n) = Ipv4Net::new(*ip, 24) {
                        nets.push(n.trunc());
                    }
                }
            }
            for s in crate::cli::FACTORY_DEFAULTS {
                if let Ok(n) = s.parse::<Ipv4Net>() {
                    nets.push(n.trunc());
                }
            }
        }
        Scope::Private16 => {
            nets.push(Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap());
        }
        Scope::Rfc1918 => {
            nets.push(Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap());
            nets.push(Ipv4Net::new(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap());
            nets.push(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
        }
    }

    // Ignored ranges are removed LAST, after the scope has assembled the list:
    // `Scope::Auto` re-injects `expected`, and the ignored range sits in there —
    // subtracting earlier would let it back in through the side door. Ranges
    // smaller than a /24 survive this filter and are discounted address by
    // address inside the sweep itself.
    nets.retain(|n| !excluded.iter().any(|x| x.contains(n)));
    // APIPA is never a target: 169.254/16 is a symptom of missing DHCP, not a
    // network with devices to find. Sweeping it would cost 65k empty addresses.
    nets.retain(|n| !iface::is_apipa_net(n));

    dedup_nets(nets)
}

/// Drops duplicates and networks already contained in another, PRESERVING the
/// priority order. Likely subnets must be swept BEFORE the large exhaustive
/// blocks: sweeping empty /24s ahead of the populated one piles up broadcast and
/// the switch's storm control swallows the replies. That is why we do NOT sort
/// by address — whatever comes first in priority goes first onto the wire.
pub fn dedup_nets(nets: Vec<Ipv4Net>) -> Vec<Ipv4Net> {
    let mut kept: Vec<Ipv4Net> = Vec::new();
    for n in nets {
        if kept.iter().any(|k| k == &n || k.contains(&n)) {
            continue;
        }
        kept.retain(|k| !n.contains(k));
        kept.push(n);
    }
    kept
}

pub fn human_eta(total: u64, rate: u64) -> String {
    let secs = total as f64 / rate.max(1) as f64;
    if secs >= 3600.0 {
        format!("{:.1}h", secs / 3600.0)
    } else if secs >= 60.0 {
        format!("{:.0}min", secs / 60.0)
    } else {
        format!("{:.0}s", secs.max(1.0))
    }
}

/// Installs the SIGINT handler without pulling in a dependency (CLI only).
/// Checks whether we have raw-socket permission without starting a whole scan.
/// The TUI calls this before going full screen, so the hint stays readable.
pub fn preflight_permission() -> Result<()> {
    let local = iface::resolve(None)?;
    crate::rawsock::RawSocket::open(local.iface.index, 50)?;
    Ok(())
}

pub fn install_sigint() {
    const SIGINT: i32 = 2;
    unsafe {
        libc_signal(SIGINT, on_sigint as *const () as usize);
    }
}

extern "C" fn on_sigint(_sig: i32) {
    STOP.store(true, Ordering::Relaxed);
}

extern "C" {
    #[link_name = "signal"]
    fn libc_signal(sig: i32, handler: usize) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> Ipv4Net {
        s.parse::<Ipv4Net>().unwrap().trunc()
    }

    #[test]
    fn an_ignored_range_does_not_come_back_through_the_side_door() {
        // The local network is "expected", and `Scope::Auto` re-injects the
        // expected ones into the target list. Marking it ignored must win.
        let inv = inventory::Inventory::new();
        let expected = vec![net("192.168.1.0/24")];
        let excluded = vec![net("192.168.1.0/24")];
        let targets = build_targets(Scope::Auto, &expected, &[], &excluded, &inv);
        assert!(!targets.contains(&net("192.168.1.0/24")));
        // and the rest of the scope still stands
        assert!(targets.contains(&net("192.168.88.0/24")));
    }

    #[test]
    fn apipa_is_never_a_target() {
        let inv = inventory::Inventory::new();
        let targets = build_targets(Scope::Auto, &[net("169.254.0.0/16")], &[], &[], &inv);
        assert!(!targets.iter().any(|n| iface::is_apipa_net(n)), "169.254/16 became a target: {:?}", targets);
        // Scope `none` with nothing else: APIPA alone leaves nothing to sweep.
        let only_apipa = build_targets(Scope::None, &[], &[net("169.254.0.0/16")], &[], &inv);
        assert!(only_apipa.is_empty(), "{:?}", only_apipa);
    }

    #[test]
    fn targets_come_before_the_scope() {
        // List order is wire order: the user's hypothesis goes first.
        let inv = inventory::Inventory::new();
        let targets =
            build_targets(Scope::Auto, &[net("192.168.1.0/24")], &[net("10.0.0.0/24")], &[], &inv);
        assert_eq!(targets.first(), Some(&net("10.0.0.0/24")));
    }

    #[test]
    fn the_collect_window_tracks_the_sweep() {
        // A short /24: the 0.5s floor instead of the old fixed 3s.
        assert_eq!(collect_window(Duration::from_millis(400)), Duration::from_millis(500));
        // medium sweep: half of it
        assert_eq!(collect_window(Duration::from_secs(2)), Duration::from_secs(1));
        // huge sweep: the 3s ceiling
        assert_eq!(collect_window(Duration::from_secs(600)), Duration::from_secs(3));
    }
}
