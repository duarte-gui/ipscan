use crate::correlate::{Finding, Severity};
use std::io::IsTerminal;

struct Style {
    on: bool,
}

impl Style {
    fn new() -> Style {
        // NO_COLOR is the convention terminal tools honour.
        let on = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
        Style { on }
    }
    fn paint(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{}m{}\x1b[0m", code, s)
        } else {
            s.to_string()
        }
    }
    fn sev(&self, s: Severity, text: &str) -> String {
        match s {
            Severity::Critical => self.paint("1;31", text),
            Severity::High => self.paint("1;33", text),
            Severity::Info => self.paint("2", text),
        }
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
}

pub fn table(findings: &[Finding], show_all: bool) {
    let st = Style::new();
    let shown: Vec<&Finding> = findings
        .iter()
        .filter(|f| show_all || !f.flags.is_empty())
        .collect();

    if shown.is_empty() {
        println!(
            "\nNo host looks anomalous. {} device(s) inventoried — use -a to see them all.",
            findings.len()
        );
        return;
    }

    let w_mac = 17;
    let w_ip = shown
        .iter()
        .map(|f| f.ipv4.join(",").len())
        .chain(std::iter::once(4))
        .max()
        .unwrap()
        .min(40);
    let w_vendor = 28;

    println!();
    println!(
        "{}",
        st.bold(&format!(
            "{:<w_mac$}  {:<w_ip$}  {:<w_vendor$}  {}",
            "MAC", "IPv4", "VENDOR", "FLAGS"
        ))
    );
    println!("{}", st.dim(&"-".repeat(w_mac + w_ip + w_vendor + 24)));

    for f in &shown {
        let ips = if f.ipv4.is_empty() { "—".to_string() } else { f.ipv4.join(",") };
        let vendor = f
            .vendor
            .clone()
            .unwrap_or_else(|| if f.locally_administered { "(local/VM MAC)".into() } else { "(unknown)".into() });
        let vendor = truncate(&vendor, w_vendor);
        let codes: Vec<String> = f.flags.iter().map(|fl| fl.code().to_string()).collect();

        println!(
            "{:<w_mac$}  {:<w_ip$}  {:<w_vendor$}  {}",
            f.mac,
            truncate(&ips, w_ip),
            vendor,
            st.sev(f.severity, &codes.join(" "))
        );

        for fl in &f.flags {
            println!("{}", st.dim(&format!("{:>w_mac$}  └─ {}", "", fl.explain())));
        }
        if let Some(l) = &f.lease {
            let mut d = format!("DHCP lease: {}", l);
            if let Some(secs) = f.lease_secs {
                d.push_str(&format!(" for {}", fmt_secs(secs)));
            }
            if let Some(srv) = &f.lease_server {
                d.push_str(&format!(" from server {}", srv));
            }
            println!("{}", st.dim(&format!("{:>w_mac$}  └─ {}", "", d)));
        }
        if let Some(h) = &f.hostname {
            println!("{}", st.dim(&format!("{:>w_mac$}  └─ DHCP hostname: {}", "", h)));
        }
        if !f.sources.is_empty() {
            println!("{}", st.dim(&format!("{:>w_mac$}  └─ seen via: {}", "", f.sources.join(", "))));
        }
    }

    let crit = shown.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = shown.iter().filter(|f| f.severity == Severity::High).count();
    println!();
    println!(
        "{} host(s) inventoried · {} critical · {} high",
        findings.len(),
        crit,
        high
    );
}

fn fmt_secs(s: u32) -> String {
    match s {
        0..=119 => format!("{}s", s),
        120..=7199 => format!("{}min", s / 60),
        _ => format!("{}h", s / 3600),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

pub fn json(findings: &[Finding]) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(findings)?);
    Ok(())
}

pub fn csv(findings: &[Finding]) {
    println!("mac,ipv4,ipv6,vendor,hostname,dhcp_lease,severity,flags,seen_via");
    for f in findings {
        println!(
            "{},{},{},{},{},{},{:?},{},{}",
            f.mac,
            q(&f.ipv4.join(" ")),
            q(&f.ipv6.join(" ")),
            q(f.vendor.as_deref().unwrap_or("")),
            q(f.hostname.as_deref().unwrap_or("")),
            f.lease.as_deref().unwrap_or(""),
            f.severity,
            q(&f.flags.iter().map(|x| x.code()).collect::<Vec<_>>().join(" ")),
            q(&f.sources.join(" ")),
        );
    }
}

fn q(s: &str) -> String {
    if s.contains(',') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
