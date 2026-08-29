use pnet::util::MacAddr;
use std::collections::HashMap;

const OUI_PATHS: &[&str] = &[
    "/usr/share/arp-scan/ieee-oui.txt",
    "/usr/local/share/arp-scan/ieee-oui.txt",
    "/etc/ipscan/ieee-oui.txt",
];

/// OUIs missing from, or worth highlighting without, the arp-scan file.
const BUILTIN: &[(&str, &str)] = &[
    ("BC2411", "Proxmox Server Solutions (VM)"),
    ("525400", "QEMU/KVM (VM)"),
    ("020000", "Locally administered (VM/container)"),
    ("0A0027", "VirtualBox host-only"),
    ("080027", "Oracle VirtualBox"),
    ("000C29", "VMware"),
    ("005056", "VMware"),
    ("001C42", "Parallels"),
    ("00155D", "Microsoft Hyper-V"),
    ("B827EB", "Raspberry Pi Foundation"),
    ("DCA632", "Raspberry Pi Trading"),
    ("E45F01", "Raspberry Pi Trading"),
    ("2CCF67", "Raspberry Pi Ltd"),
];

/// Prefix table with longest-prefix lookup, the way arp-scan does it: a vendor
/// may register anywhere from 2 to 12 hex digits.
pub struct OuiDb {
    by_len: HashMap<usize, HashMap<String, String>>,
    lens: Vec<usize>,
}

impl OuiDb {
    pub fn load() -> OuiDb {
        let mut by_len: HashMap<usize, HashMap<String, String>> = HashMap::new();

        let mut insert = |prefix: &str, vendor: &str| {
            let p = prefix.to_ascii_uppercase();
            by_len.entry(p.len()).or_default().insert(p, vendor.to_string());
        };

        for (p, v) in BUILTIN {
            insert(p, v);
        }

        if let Some(text) = OUI_PATHS.iter().find_map(|p| std::fs::read_to_string(p).ok()) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((prefix, vendor)) = line.split_once('\t') else {
                    continue;
                };
                let prefix = prefix.trim();
                let vendor = vendor.trim();
                // Do not overwrite the builtin, which is more specific for VMs.
                let p = prefix.to_ascii_uppercase();
                by_len
                    .entry(p.len())
                    .or_default()
                    .entry(p)
                    .or_insert_with(|| vendor.to_string());
            }
        }

        let mut lens: Vec<usize> = by_len.keys().copied().collect();
        lens.sort_unstable_by(|a, b| b.cmp(a)); // longest to shortest
        OuiDb { by_len, lens }
    }

    pub fn lookup(&self, mac: MacAddr) -> Option<&str> {
        let hex = format!(
            "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            mac.0, mac.1, mac.2, mac.3, mac.4, mac.5
        );
        for &len in &self.lens {
            if len > hex.len() {
                continue;
            }
            if let Some(v) = self.by_len.get(&len).and_then(|m| m.get(&hex[..len])) {
                return Some(v);
            }
        }
        None
    }
}

/// MACs with the "locally administered" bit set are usually a VM, a container
/// or a randomised address — useful context when judging an unknown device.
pub fn is_locally_administered(mac: MacAddr) -> bool {
    mac.0 & 0x02 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_uses_the_builtin_for_vms() {
        let db = OuiDb::load();
        // Proxmox lives in the builtin table (a 6-digit prefix)
        let mac = MacAddr::new(0xbc, 0x24, 0x11, 0xa8, 0xaf, 0x41);
        let v = db.lookup(mac).unwrap_or("");
        assert!(v.contains("Proxmox"), "expected Proxmox, got {:?}", v);
    }

    #[test]
    fn locally_administered_bit() {
        // second least significant bit of the first octet
        assert!(is_locally_administered(MacAddr::new(0x02, 0, 0, 0, 0, 0)));
        assert!(is_locally_administered(MacAddr::new(0xaa, 0, 0, 0, 0, 0)));
        assert!(!is_locally_administered(MacAddr::new(0xf0, 0xda, 0x5e, 0, 0, 0)));
    }
}
