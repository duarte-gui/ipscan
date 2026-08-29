mod arp;
mod capture;
mod cli;
mod correlate;
mod dhcp;
mod iface;
mod inventory;
mod ndp;
mod oui;
mod rawsock;
mod report;
mod scan;
mod tui;

use anyhow::Result;
use clap::Parser;
use cli::Cli;
use scan::{ScanConfig, ScanHandle};
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // `--tui`: the interactive interface. Everything else is the usual CLI.
    if cli.tui {
        return tui::run_tui(&cli);
    }

    let mut expected = cli::expected_or_local(&cli)?;
    let excluded = cli::parse_nets(&cli.excluded)?;
    // An ignored range is legitimate too: we never sweep it and nothing from
    // it raises a flag.
    expected.extend(excluded.iter().copied());
    let extra_ranges = cli::parse_nets(&cli.ranges)?;
    let spa = arp::Spa::parse(&cli.spa)?;
    if spa.poisons_arp_cache() {
        eprintln!(
            "warning: --spa {} forges a sender IP that will be written into the ARP cache \
             of every host on the segment. Use it only if probe mode cannot reach the target.",
            cli.spa
        );
    }

    scan::install_sigint();
    let ouidb = oui::OuiDb::load();

    let cfg = ScanConfig {
        iface: cli.iface.clone(),
        expected: expected.clone(),
        excluded: excluded.clone(),
        ranges: extra_ranges,
        scope: cli.scope,
        spa,
        pace: arp::Pace { rate: cli.rate, settle_ms: cli.settle, passes: cli.passes },
        passive_secs: cli.passive_secs,
        passive_only: cli.passive_only,
        no_ipv6: cli.no_ipv6,
        leases_file: cli.leases_file.clone(),
        verbose: true,
    };

    let mut previously_flagged: BTreeSet<String> = BTreeSet::new();

    loop {
        let cycle_start = Instant::now();

        // One full pass of the four layers, blocking until it finishes.
        let mut handle = ScanHandle::start(cfg.clone())?;
        handle.join_driver()?;
        let findings = handle.findings(&ouidb);
        drop(handle); // shuts down this pass's capture and collector

        if cli.watch {
            let fresh: Vec<_> = findings
                .iter()
                .filter(|f| !f.flags.is_empty() && !previously_flagged.contains(&f.mac))
                .cloned()
                .collect();
            for f in &fresh {
                previously_flagged.insert(f.mac.clone());
            }
            if fresh.is_empty() {
                eprintln!(
                    "cycle in {:.0}s · nothing new · {} host(s) known",
                    cycle_start.elapsed().as_secs_f64(),
                    findings.len()
                );
            } else {
                report::table(&fresh, false);
            }
        } else if cli.json {
            report::json(&findings)?;
        } else if cli.csv {
            report::csv(&findings);
        } else {
            report::table(&findings, cli.all);
        }

        report_drops();

        if !cli.watch || scan::STOP.load(Ordering::Relaxed) {
            break;
        }
        // Gap between cycles: a breather before the next pass.
        interruptible_sleep(Duration::from_secs(cli.watch_interval));
        if scan::STOP.load(Ordering::Relaxed) {
            break;
        }
    }

    Ok(())
}

fn report_drops() {
    let drops = capture::KERNEL_DROPS.load(Ordering::Relaxed);
    if drops > 0 {
        eprintln!(
            "warning: the kernel dropped {} frame(s) because the queue was full — the result \
             may be incomplete. Try again with a lower --rate.",
            drops
        );
    }
}

fn interruptible_sleep(dur: Duration) {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        if scan::STOP.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(Duration::from_millis(150).min(deadline - Instant::now()));
    }
}
