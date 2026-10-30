//! What the namespace backend needs from the host, checked at startup so a
//! relay that cannot build tunnel networks refuses to offer tunnels instead
//! of failing every open.

/// Linux capability numbers (`linux/capability.h`).
#[cfg(target_os = "linux")]
const CAP_NET_ADMIN: u32 = 12;
#[cfg(target_os = "linux")]
const CAP_SYS_ADMIN: u32 = 21;

/// `Ok` when this process can create network namespaces, TUN devices and
/// nftables rules: Linux, `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` (namespaces)
/// in its effective set, `/dev/net/tun`, and the `ip` and `nft` programs.
pub fn check() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status")
            .map_err(|e| format!("cannot read /proc/self/status: {e}"))?;
        let effective = effective_caps(&status)
            .ok_or_else(|| "no CapEff line in /proc/self/status".to_owned())?;
        let mut missing = Vec::new();
        if effective & (1 << CAP_NET_ADMIN) == 0 {
            missing.push("CAP_NET_ADMIN");
        }
        if effective & (1 << CAP_SYS_ADMIN) == 0 {
            missing.push("CAP_SYS_ADMIN (network namespaces)");
        }
        if !missing.is_empty() {
            return Err(format!("missing {}", missing.join(" and ")));
        }
        if !std::path::Path::new("/dev/net/tun").exists() {
            return Err("/dev/net/tun is missing".to_owned());
        }
        for program in ["ip", "nft"] {
            if !on_path(program) {
                return Err(format!("`{program}` is not on PATH"));
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("IP tunnels need Linux (network namespaces, TUN and nftables)".to_owned())
    }
}

/// The `CapEff` bit set of a `/proc/<pid>/status` text.
pub fn effective_caps(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
}

#[cfg(target_os = "linux")]
fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_effective_set() {
        let status = "Name:\twispd\nCapInh:\t0000000000000000\nCapEff:\t0000000000201000\n";
        let caps = effective_caps(status).unwrap();
        assert_eq!(caps, (1 << 12) | (1 << 21));
        assert_eq!(effective_caps("Name: x\n"), None);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn other_systems_are_refused() {
        assert!(check().is_err());
    }
}
