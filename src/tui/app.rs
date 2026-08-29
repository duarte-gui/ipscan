//! Central state and logic of the TUI (no drawing — that lives in mod.rs).

use crate::arp;
use crate::cli::Scope;
use crate::correlate::Finding;
use crate::iface;
use crate::oui::OuiDb;
use crate::scan::{ScanConfig, ScanHandle};
use anyhow::Result;
use ipnet::Ipv4Net;
use std::time::{Duration, Instant};

/// A range's role. Two independent questions — do we sweep it? does it count as
/// legitimate? — whose useful combinations are these three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeKind {
    /// `[ ]` The network you are on: swept and legitimate. It is a private
    /// address outside every expected range that counts as suspicious.
    Expected,
    /// `[>]` The range you suspect: swept first and NOT legitimate, so whoever
    /// is in there shows up flagged.
    Target,
    /// `[!]` A range already ruled out: it receives not a single packet and
    /// counts as legitimate, so nothing from it clutters the screen.
    Ignored,
}

impl RangeKind {
    pub fn next(self) -> RangeKind {
        match self {
            RangeKind::Expected => RangeKind::Target,
            RangeKind::Target => RangeKind::Ignored,
            RangeKind::Ignored => RangeKind::Expected,
        }
    }
    pub fn prev(self) -> RangeKind {
        self.next().next()
    }
    /// A one-column marker, shown in brackets in the list.
    pub fn marker(self) -> &'static str {
        match self {
            RangeKind::Expected => " ",
            RangeKind::Target => ">",
            RangeKind::Ignored => "!",
        }
    }
}

/// One row of the range list: a CIDR and its role in the sweep.
#[derive(Debug, Clone)]
pub struct RangeRow {
    pub text: String,
    pub kind: RangeKind,
}

impl RangeRow {
    pub fn new(text: impl Into<String>, kind: RangeKind) -> RangeRow {
        RangeRow { text: text.into(), kind }
    }
    pub fn parsed(&self) -> Option<Ipv4Net> {
        self.text.trim().parse::<Ipv4Net>().ok().map(|n| n.trunc())
    }
    pub fn valid(&self) -> bool {
        self.text.trim().is_empty() || self.parsed().is_some()
    }
}

/// The form's advanced fields.
#[derive(Debug, Clone)]
pub struct Advanced {
    pub spa: String,
    pub rate: u64,
    pub settle: u64,
    pub passes: u32,
    pub no_ipv6: bool,
    pub leases_file: String,
    pub passive_secs: u64,
}

impl Default for Advanced {
    fn default() -> Self {
        Advanced {
            spa: "probe".into(),
            rate: 2_000,
            settle: 150,
            passes: 2,
            no_ipv6: false,
            leases_file: String::new(),
            // Zero by default: capture stays alive during the sweep and after
            // it, so listening never stops — the opening window only slowed the
            // hypothesis loop down. Raise this in the drawer to listen quietly.
            passive_secs: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Form,
    Results,
}

/// Where the cursor sits in the form. The range list occupies several slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormFocus {
    Interface,
    Scope,
    Range(usize),
    AdvancedToggle,
    AdvSpa,
    AdvRate,
    AdvSettle,
    AdvPasses,
    AdvNoIpv6,
    AdvLeases,
    AdvPassive,
}

pub struct App {
    // ---- form ----
    pub ifaces: Vec<iface::Iface>,
    pub iface_idx: usize,
    pub scope: Scope,
    pub ranges: Vec<RangeRow>,
    pub advanced_open: bool,
    pub adv: Advanced,

    // ---- focus and editing ----
    pub pane: Pane,
    pub form_focus: FormFocus,
    pub editing: Option<String>, // edit buffer for the focused field or range

    // ---- results ----
    pub oui: OuiDb,
    pub findings: Vec<Finding>,
    pub result_idx: usize,
    pub only_flagged: bool,
    pub filter: Option<String>,
    pub filtering: bool, // typing in the filter

    // ---- scan ----
    pub scan: Option<ScanHandle>,
    pub last_refresh: Instant,
    pub session_whitelist: Vec<Ipv4Net>,

    // ---- ui ----
    pub help_open: bool,
    pub toast: Option<(String, Instant)>,
    pub should_quit: bool,
    pub perm_error: Option<String>,
}

impl App {
    pub fn new() -> Result<App> {
        let ifaces = iface::list_ifaces();
        // Pre-fill with the local subnet if there is one. On a network without
        // DHCP there is none: the list starts empty rather than inventing a
        // range that would give a false baseline.
        let local = ifaces.first().and_then(|i| i.net);
        let ranges: Vec<RangeRow> = local
            .map(|n| vec![RangeRow::new(n.to_string(), RangeKind::Expected)])
            .unwrap_or_default();
        Ok(App {
            ifaces,
            iface_idx: 0,
            scope: Scope::Auto,
            ranges,
            advanced_open: false,
            adv: Advanced::default(),
            pane: Pane::Form,
            form_focus: FormFocus::Interface,
            editing: None,
            oui: OuiDb::load(),
            findings: Vec::new(),
            result_idx: 0,
            // With no local subnet there is no baseline, hence nothing to call
            // an anomaly: the screen opens showing everything that answered.
            only_flagged: local.is_some(),
            filter: None,
            filtering: false,
            scan: None,
            last_refresh: Instant::now(),
            session_whitelist: Vec::new(),
            help_open: false,
            toast: None,
            should_quit: false,
            perm_error: None,
        })
    }

    pub fn iface_name(&self) -> Option<String> {
        self.ifaces.get(self.iface_idx).map(|i| i.name.clone())
    }

    /// IPv4 subnet of the focused interface, if it has one.
    pub fn local_net(&self) -> Option<Ipv4Net> {
        self.ifaces.get(self.iface_idx).and_then(|i| i.net).map(|n| n.trunc())
    }

    pub fn is_running(&self) -> bool {
        self.scan.as_ref().map(|s| s.is_running()).unwrap_or(false)
    }

    pub fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    /// The toast expires after a few seconds.
    pub fn tick_toast(&mut self) {
        if let Some((_, t)) = &self.toast {
            if t.elapsed() > Duration::from_secs(4) {
                self.toast = None;
            }
        }
    }

    // ------------------------------------------------------------------
    // Building the ScanConfig from the form
    // ------------------------------------------------------------------

    /// The full sweep, assembled from the form. Targets (`[>]`) go ahead of the
    /// ordinary networks: they are the hypothesis under test, and
    /// `scan::build_targets` preserves that order all the way to the wire.
    pub fn build_config(&self) -> Result<ScanConfig> {
        let mut targets = Vec::new();
        let mut normal = Vec::new();
        let mut ignored = Vec::new();
        for r in &self.ranges {
            let Some(net) = r.parsed() else { continue };
            match r.kind {
                RangeKind::Target => targets.push(net),
                RangeKind::Expected => normal.push(net),
                RangeKind::Ignored => ignored.push(net),
            }
        }
        let mut ranges = targets;
        ranges.extend(normal.iter().copied());
        self.finish_config(ranges, normal, ignored, self.scope, self.adv.passive_secs)
    }

    /// "Sweep this range now" (the `s` key): only the focused range, with no
    /// scope and no passive listening. This is the hypothesis loop — type, fire,
    /// read, switch. It applies even to a range marked ignored: the gesture is
    /// explicit.
    pub fn build_config_single(&self, idx: usize) -> Result<ScanConfig> {
        let target = self
            .ranges
            .get(idx)
            .and_then(|r| r.parsed())
            .ok_or_else(|| anyhow::anyhow!("the focused range is empty or has an invalid CIDR"))?;

        let mut normal = Vec::new();
        let mut ignored = Vec::new();
        for (i, r) in self.ranges.iter().enumerate() {
            if i == idx {
                continue;
            }
            let Some(net) = r.parsed() else { continue };
            match r.kind {
                RangeKind::Expected => normal.push(net),
                RangeKind::Ignored => ignored.push(net),
                RangeKind::Target => {}
            }
        }
        self.finish_config(vec![target], normal, ignored, Scope::None, 0)
    }

    /// The part both assemblies share: who judges what, plus advanced fields.
    fn finish_config(
        &self,
        ranges: Vec<Ipv4Net>,
        normal: Vec<Ipv4Net>,
        ignored: Vec<Ipv4Net>,
        scope: Scope,
        passive_secs: u64,
    ) -> Result<ScanConfig> {
        let mut expected = normal;
        // An ignored range is legitimate too: if something from it turns up
        // through passive listening it raises no alert — making it disappear is
        // exactly what was asked for.
        expected.extend(ignored.iter().copied());
        // The session whitelist ('w') counts as expected as well.
        expected.extend(self.session_whitelist.iter().copied());
        // With nothing expected there is no baseline left and every private
        // address would look suspicious. Fall back to the interface subnet —
        // which may not exist, and then having no baseline is the truth.
        if expected.is_empty() {
            expected.extend(self.local_net());
        }

        let spa = arp::Spa::parse(&self.adv.spa)?;
        let leases_file = if self.adv.leases_file.trim().is_empty() {
            None
        } else {
            Some(self.adv.leases_file.trim().to_string())
        };

        Ok(ScanConfig {
            iface: self.iface_name(),
            expected,
            excluded: ignored,
            ranges,
            scope,
            spa,
            pace: arp::Pace {
                rate: self.adv.rate,
                settle_ms: self.adv.settle,
                passes: self.adv.passes,
            },
            passive_secs,
            passive_only: false,
            no_ipv6: self.adv.no_ipv6,
            leases_file,
            verbose: false,
        })
    }

    pub fn any_invalid_range(&self) -> bool {
        self.ranges.iter().any(|r| !r.valid())
    }

    // ------------------------------------------------------------------
    // Firing and refreshing the scan
    // ------------------------------------------------------------------

    pub fn start_scan(&mut self) {
        if self.any_invalid_range() {
            self.toast("some range has an invalid CIDR — fix it before running");
            return;
        }
        let cfg = self.build_config();
        self.launch(cfg, "sweep started");
    }

    /// Fires a sweep of a single range — the form's `s` key.
    pub fn scan_single(&mut self, idx: usize) {
        let label = self
            .ranges
            .get(idx)
            .map(|r| format!("sweeping {}", r.text.trim()))
            .unwrap_or_else(|| "sweep started".into());
        let cfg = self.build_config_single(idx);
        self.launch(cfg, label);
    }

    fn launch(&mut self, cfg: Result<ScanConfig>, notice: impl Into<String>) {
        if self.is_running() {
            return;
        }
        // The old handle goes away BEFORE the new one is born: its `Drop`
        // signals the global STOP, so destroying it afterwards would kill the
        // freshly created sweep — that was the second-scan bug.
        self.scan = None;
        match cfg.and_then(ScanHandle::start) {
            Ok(handle) => {
                self.findings.clear();
                self.result_idx = 0;
                self.scan = Some(handle);
                self.pane = Pane::Results;
                self.toast(notice);
            }
            Err(e) => {
                let msg = format!("{:#}", e);
                if msg.contains("CAP_NET_RAW") {
                    self.perm_error = Some(msg);
                } else {
                    self.toast(format!("failed to start: {}", msg));
                }
            }
        }
    }

    pub fn cancel_scan(&mut self) {
        if let Some(h) = &self.scan {
            h.stop();
            self.toast("sweep cancelled (partial results kept)");
        }
    }

    /// Recomputes the findings from the scan's shared inventory.
    pub fn refresh_findings(&mut self) {
        if let Some(h) = &self.scan {
            self.findings = h.findings(&self.oui);
            let n = self.visible_indices().len();
            if self.result_idx >= n && n > 0 {
                self.result_idx = n - 1;
            }
        }
        self.last_refresh = Instant::now();
    }

    /// Indices of `findings` visible under the filter and only_flagged.
    pub fn visible_indices(&self) -> Vec<usize> {
        let f = self.filter.as_deref().map(|s| s.to_lowercase());
        self.findings
            .iter()
            .enumerate()
            .filter(|(_, x)| !self.only_flagged || !x.flags.is_empty())
            .filter(|(_, x)| match &f {
                None => true,
                Some(q) => {
                    x.mac.to_lowercase().contains(q)
                        || x.ipv4.iter().any(|i| i.contains(q))
                        || x.vendor.as_deref().unwrap_or("").to_lowercase().contains(q)
                        || x.hostname.as_deref().unwrap_or("").to_lowercase().contains(q)
                }
            })
            .map(|(i, _)| i)
            .collect()
    }

    pub fn selected_finding(&self) -> Option<&Finding> {
        let vis = self.visible_indices();
        vis.get(self.result_idx).and_then(|&i| self.findings.get(i))
    }

    // ------------------------------------------------------------------
    // Actions on the selected host
    // ------------------------------------------------------------------

    pub fn whitelist_selected(&mut self) {
        let net = self.selected_finding().and_then(|f| {
            f.ipv4.iter().filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok()).next()
        });
        if let Some(ip) = net {
            if let Ok(n) = Ipv4Net::new(ip, 24) {
                let n = n.trunc();
                if !self.session_whitelist.contains(&n) {
                    self.session_whitelist.push(n);
                }
                self.toast(format!("{} marked as known (this session)", n));
                // reapply over the current findings so it disappears at once
                self.reapply_whitelist();
            }
        } else {
            self.toast("host has no IPv4 to whitelist");
        }
    }

    /// Recomputes findings with the session whitelist added to the expected set.
    fn reapply_whitelist(&mut self) {
        // The whitelist only changes the result on the next read; recompute
        // using the current inventory plus the widened expected set.
        if let Some(h) = &self.scan {
            let g = h.inv.lock().unwrap();
            let mut expected: Vec<Ipv4Net> = h.expected().to_vec();
            expected.extend(self.session_whitelist.iter().copied());
            self.findings = crate::correlate::analyze(&g, &expected, &self.oui);
        }
    }

    pub fn copy_mac_selected(&mut self) {
        if let Some(f) = self.selected_finding() {
            let mac = f.mac.clone();
            super::clipboard::copy(&mac);
            self.toast(format!("MAC {} copied", mac));
        }
    }

    pub fn probe_selected(&mut self) {
        let target = self.selected_finding().and_then(|f| {
            f.ipv4.iter().filter_map(|s| s.parse::<std::net::Ipv4Addr>().ok()).next()
        });
        match target {
            Some(ip) => {
                let alive = crate::tui::probe::probe_host(self.iface_name().as_deref(), ip);
                self.toast(match alive {
                    Some(true) => format!("{} answered (alive)", ip),
                    Some(false) => format!("{} did not answer", ip),
                    None => format!("could not probe {}", ip),
                });
            }
            None => self.toast("host has no IPv4 to probe"),
        }
    }

    pub fn export(&mut self) {
        match crate::tui::export::export(&self.findings) {
            Ok(paths) => self.toast(format!("exported: {}", paths)),
            Err(e) => self.toast(format!("export failed: {:#}", e)),
        }
    }
}
