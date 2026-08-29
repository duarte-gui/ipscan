//! Exports the current findings to timestamped JSON + CSV (the `e` action).

use crate::correlate::Finding;
use anyhow::{Context, Result};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Writes `ipscan-<epoch>.json` and `.csv` in the current directory; returns the names.
pub fn export(findings: &[Finding]) -> Result<String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let base = format!("ipscan-{}", stamp);

    let json_path = format!("{}.json", base);
    let json = serde_json::to_string_pretty(findings)?;
    std::fs::write(&json_path, json).with_context(|| format!("writing {}", json_path))?;

    let csv_path = format!("{}.csv", base);
    let mut f = std::fs::File::create(&csv_path).with_context(|| format!("creating {}", csv_path))?;
    writeln!(f, "mac,ipv4,vendor,hostname,lease,severity,flags")?;
    for x in findings {
        writeln!(
            f,
            "{},{},{},{},{},{:?},{}",
            x.mac,
            csv_q(&x.ipv4.join(" ")),
            csv_q(x.vendor.as_deref().unwrap_or("")),
            csv_q(x.hostname.as_deref().unwrap_or("")),
            x.lease.as_deref().unwrap_or(""),
            x.severity,
            csv_q(&x.flags.iter().map(|fl| fl.code()).collect::<Vec<_>>().join(" ")),
        )?;
    }
    Ok(format!("{} + {}", json_path, csv_path))
}

fn csv_q(s: &str) -> String {
    if s.contains(',') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
