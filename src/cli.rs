use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use ipnet::Ipv4Net;

/// Finds devices holding a static IP outside the expected range.
///
/// Combines four layers: passive sniffing, L2 enumeration over ICMPv6, a
/// directed ARP sweep, and an exhaustive ARP sweep of the RFC1918 space.
#[derive(Parser, Debug, Clone)]
#[command(name = "ipscan", version, about, long_about = None)]
pub struct Cli {
    /// Network interface to use (auto-detects the first active one if omitted).
    #[arg(short = 'i', long)]
    pub iface: Option<String>,

    /// Open the interactive interface (TUI) instead of the command line mode.
    #[arg(long)]
    pub tui: bool,

    /// Subnet(s) treated as legitimate. Defaults to the interface's own subnet.
    /// Repeatable: --expected 192.168.1.0/24 --expected 10.10.0.0/16
    #[arg(short = 'e', long = "expected", value_name = "CIDR")]
    pub expected: Vec<String>,

    /// Range(s) to IGNORE (the TUI form's "!"): they receive not a single
    /// packet and nothing coming from them is flagged. Repeatable.
    #[arg(short = 'X', long = "exclude", value_name = "CIDR")]
    pub excluded: Vec<String>,

    /// Scope of the active sweep.
    #[arg(short = 's', long, value_enum, default_value_t = Scope::Auto)]
    pub scope: Scope,

    /// Extra subnets to sweep (repeatable), e.g. --range 10.37.129.0/24
    #[arg(short = 'r', long = "range", value_name = "CIDR")]
    pub ranges: Vec<String>,

    /// Seconds of passive listening before the active sweep.
    #[arg(short = 'p', long, default_value_t = 15)]
    pub passive_secs: u64,

    /// ARP packets per second inside each /24 block. The default is
    /// deliberately conservative: ARP is broadcast, and high rates trip the
    /// storm control on managed switches, which then starts dropping replies.
    #[arg(long, default_value_t = 2_000)]
    pub rate: u64,

    /// Silence after each /24, in ms. This is what keeps storm control from
    /// swallowing replies during large sweeps. Zero disables it (faster, less
    /// reliable on managed switches).
    #[arg(long, default_value_t = 150)]
    pub settle: u64,

    /// How many times to resend each /24. Recovers replies lost on one pass;
    /// 1 turns the retry off.
    #[arg(long, default_value_t = 2)]
    pub passes: u32,

    /// Send nothing at all: passive listening only (stealth mode).
    #[arg(long)]
    pub passive_only: bool,

    /// Skip the ICMPv6 enumeration of ff02::1.
    #[arg(long)]
    pub no_ipv6: bool,

    /// Read leases from a file (dnsmasq.leases or dhcpd.leases) besides sniffing.
    #[arg(long, value_name = "PATH")]
    pub leases_file: Option<String>,

    /// Continuous monitoring: repeats the cycles and reports only what is new.
    #[arg(short = 'w', long)]
    pub watch: bool,

    /// Interval between cycles in --watch mode, in seconds.
    #[arg(long, default_value_t = 60)]
    pub watch_interval: u64,

    /// JSON output instead of a table.
    #[arg(long)]
    pub json: bool,

    /// CSV output instead of a table.
    #[arg(long)]
    pub csv: bool,

    /// Show every host, including those with no flag at all.
    #[arg(short = 'a', long)]
    pub all: bool,

    /// Sender IP of the ARP requests.
    ///
    /// "probe" (default) uses 0.0.0.0 per RFC 5227: the only mode that reaches
    /// foreign subnets without writing into anyone's ARP cache. "local" uses
    /// our own address (works only inside our own subnet), "dest" uses the
    /// target itself, "neighbor" uses the .1 of the target's subnet, and an
    /// explicit IPv4 forces a value. The last two POISON other ARP caches.
    #[arg(long, default_value = "probe")]
    pub spa: String,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// No sweep at all: passive listening only.
    None,
    /// Subnets found while listening + factory defaults (seconds).
    Auto,
    /// The whole of 192.168.0.0/16 (~7s at 10k pps).
    Private16,
    /// All of RFC1918: 10/8 + 172.16/12 + 192.168/16 (~30min at 10k pps).
    Rfc1918,
}

/// Subnets vendors ship as factory defaults. Swept in Auto mode because a
/// device that is "outside the range" is almost always sitting in one of them.
pub const FACTORY_DEFAULTS: &[&str] = &[
    "192.168.0.0/24",
    "192.168.1.0/24",
    "192.168.2.0/24",
    "192.168.8.0/24",
    "192.168.10.0/24",
    "192.168.11.0/24",
    "192.168.15.0/24",
    "192.168.16.0/24",
    "192.168.25.0/24",
    "192.168.50.0/24",
    "192.168.88.0/24",  // Mikrotik
    "192.168.100.0/24", // modems and ONTs
    "192.168.123.0/24",
    "192.168.127.0/24", // Moxa
    "192.168.178.0/24", // AVM Fritz!Box
    "192.168.254.0/24",
    "10.0.0.0/24",
    "10.0.1.0/24",
    "10.1.1.0/24",
    "10.10.10.0/24",
    "172.16.0.0/24",
    "172.20.0.0/24",
];
// Note: 169.254.0.0/16 (APIPA) is deliberately NOT here — sweeping a whole /16
// on every "auto" scan costs tens of seconds, and a host in APIPA gives itself
// away anyway (it ARPs for its own 169.254.x.x), so the passive layer catches it
// and correlation marks it with the APIPA flag. No sweep cost at all.

/// The expected subnets: those given with --expected, or the local subnet when
/// none was. On a network without DHCP the interface may have no subnet — the
/// list comes back empty and there is no legitimacy baseline, which is the
/// truth about that network.
pub fn expected_or_local(cli: &Cli) -> Result<Vec<Ipv4Net>> {
    if !cli.expected.is_empty() {
        return parse_nets(&cli.expected);
    }
    let local = crate::iface::resolve(cli.iface.as_deref())?;
    Ok(local.net.into_iter().collect())
}

pub fn parse_nets(list: &[String]) -> Result<Vec<Ipv4Net>> {
    let mut out = Vec::new();
    for s in list {
        match s.parse::<Ipv4Net>() {
            Ok(n) => out.push(n.trunc()),
            Err(e) => bail!("invalid CIDR {:?}: {}", s, e),
        }
    }
    Ok(out)
}
