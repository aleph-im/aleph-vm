//! Host IPv4 discovery, ported from the Python daemon.
//!
//! Python sources: conf.py `get_default_interface()` (first default route in
//! /proc/net/route) and network/get_interface_ipv4.py `get_interface_ipv4()`
//! (netifaces/getifaddrs, preferring a global-scope address and falling back
//! to the first one). The Python daemon resolves this once at pool
//! construction and serves the cached value from GetHostInfo; we do the same
//! at startup (see service::HostState).

use std::ffi::CStr;
use std::net::Ipv4Addr;

use crate::error::DaemonError;

/// First interface holding a default route, from /proc/net/route.
/// Mirrors conf.py get_default_interface().
pub fn default_interface() -> Result<Option<String>, DaemonError> {
    let content =
        std::fs::read_to_string("/proc/net/route").map_err(|source| DaemonError::ReadFile {
            path: "/proc/net/route".into(),
            source,
        })?;
    Ok(default_interface_from_route_table(&content))
}

fn default_interface_from_route_table(content: &str) -> Option<String> {
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == "00000000" {
            return Some(parts[0].to_string());
        }
    }
    None
}

/// The main IPv4 address of `interface_name`, preferring global scope.
/// Mirrors get_interface_ipv4(): error when the interface does not exist or
/// carries no IPv4 address (which aborts daemon startup, as in Python where
/// Network.__init__ raises during pool construction).
pub fn get_interface_ipv4(interface_name: &str) -> Result<String, DaemonError> {
    let (found, addresses) = interface_ipv4_addresses(interface_name)?;
    if !found {
        return Err(DaemonError::InterfaceNotFound(interface_name.to_string()));
    }
    let first = addresses
        .first()
        .ok_or_else(|| DaemonError::NoIpv4Address(interface_name.to_string()))?;
    let address = addresses
        .iter()
        .find(|address| is_global_ipv4(**address))
        .unwrap_or(first);
    Ok(address.to_string())
}

/// All IPv4 addresses of an interface via getifaddrs(3), the same primary
/// source netifaces uses, in kernel order. Returns (interface_exists, addrs).
fn interface_ipv4_addresses(interface_name: &str) -> Result<(bool, Vec<Ipv4Addr>), DaemonError> {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a linked list we walk read-only below and free
    // exactly once with freeifaddrs.
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return Err(DaemonError::Io(std::io::Error::last_os_error()));
    }
    let mut found = false;
    let mut result = Vec::new();
    let mut cursor = addrs;
    while !cursor.is_null() {
        // SAFETY: cursor is a valid node of the list returned by getifaddrs.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        if name.to_string_lossy() != interface_name {
            continue;
        }
        found = true;
        if entry.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_addr points at a sockaddr owned by the list; the family
        // check guarantees it is a sockaddr_in.
        let family = unsafe { (*entry.ifa_addr).sa_family };
        if family == libc::AF_INET as libc::sa_family_t {
            let sin = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
            result.push(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
        }
    }
    // SAFETY: addrs came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(addrs) };
    Ok((found, result))
}

/// Python ipaddress.IPv4Address.is_global: not in any IANA special-purpose
/// block that is not globally reachable. Replicates the CPython table
/// (including the 100.64.0.0/10 carve-out that is neither private nor
/// global, and the 192.0.0.9/.10 globally-reachable exceptions).
pub fn is_global_ipv4(address: Ipv4Addr) -> bool {
    let ip = u32::from(address);
    let in_block = |network: [u8; 4], prefix: u32| -> bool {
        let net = u32::from(Ipv4Addr::from(network));
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        (ip & mask) == net
    };
    // Globally reachable exceptions inside 192.0.0.0/24.
    if address == Ipv4Addr::new(192, 0, 0, 9) || address == Ipv4Addr::new(192, 0, 0, 10) {
        return true;
    }
    let not_global = in_block([0, 0, 0, 0], 8)
        || in_block([10, 0, 0, 0], 8)
        || in_block([100, 64, 0, 0], 10)
        || in_block([127, 0, 0, 0], 8)
        || in_block([169, 254, 0, 0], 16)
        || in_block([172, 16, 0, 0], 12)
        || in_block([192, 0, 0, 0], 24)
        || in_block([192, 0, 2, 0], 24)
        || in_block([192, 168, 0, 0], 16)
        || in_block([198, 18, 0, 0], 15)
        || in_block([198, 51, 100, 0], 24)
        || in_block([203, 0, 113, 0], 24)
        || in_block([240, 0, 0, 0], 4)
        || address == Ipv4Addr::BROADCAST;
    !not_global
}

// ── DNS nameserver discovery (conf.py obtain_dns_ips) ───────────────────

/// conf.py `etc_resolv_conf_dns_servers`: `nameserver <ip>` lines. The
/// Python regex is `^nameserver\s+([\w.]+)$`, which misses IPv6 servers
/// (no ':' in the class); ported as-is.
fn resolv_conf_dns_servers(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("nameserver")?;
            let candidate = rest.trim();
            if rest.starts_with([' ', '\t'])
                && !candidate.is_empty()
                && candidate
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
            {
                Some(candidate.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// conf.py `resolvectl_dns_servers`: `resolvectl dns -i <interface>`,
/// splitting the "Link N (iface): a b c" output on the first colon.
fn resolvectl_dns_servers(interface: &str) -> Result<Vec<String>, String> {
    let output = std::process::Command::new("/usr/bin/resolvectl")
        .args(["dns", "-i", interface])
        .output()
        .map_err(|error| format!("cannot run resolvectl: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "resolvectl dns -i {interface} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let (_, servers) = text
        .split_once(':')
        .ok_or_else(|| format!("unexpected resolvectl output: {text:?}"))?;
    Ok(servers.split_whitespace().map(str::to_string).collect())
}

/// conf.py `obtain_dns_ips`, called at startup like `settings.setup()`
/// (only when DNS_NAMESERVERS is unset and an interface was resolved). An
/// unresolvable configuration is a startup error, as in Python.
pub fn obtain_dns_ips(
    resolution: crate::config::DnsResolution,
    interface: &str,
) -> Result<Vec<String>, String> {
    use crate::config::DnsResolution;
    match resolution {
        DnsResolution::Detect => match resolvectl_dns_servers(interface) {
            Ok(servers) => Ok(servers),
            Err(error) => {
                let path = std::path::Path::new("/etc/resolv.conf");
                if path.exists() {
                    let contents = std::fs::read_to_string(path)
                        .map_err(|error| format!("cannot read /etc/resolv.conf: {error}"))?;
                    Ok(resolv_conf_dns_servers(&contents))
                } else {
                    Err(format!("No DNS resolver found ({error})"))
                }
            }
        },
        DnsResolution::ResolvConf => {
            let contents = std::fs::read_to_string("/etc/resolv.conf")
                .map_err(|error| format!("cannot read /etc/resolv.conf: {error}"))?;
            Ok(resolv_conf_dns_servers(&contents))
        }
        DnsResolution::Resolvectl => resolvectl_dns_servers(interface),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolv_conf_parsing_mirrors_the_python_regex() {
        let contents = "# comment\nnameserver 127.0.0.53\nnameserver\t9.9.9.9\n\
                        nameserver fe80::1\nsearch lan\nnameserver 1.1.1.1 trailing\n";
        assert_eq!(
            resolv_conf_dns_servers(contents),
            vec!["127.0.0.53".to_string(), "9.9.9.9".to_string()],
            "the Python [\\w.]+ pattern skips IPv6 and trailing tokens"
        );
    }

    #[test]
    fn default_route_is_detected_in_proc_net_route() {
        // Header + one non-default + one default route, as /proc/net/route
        // formats them.
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
             enp5s0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
             enp5s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(
            default_interface_from_route_table(table),
            Some("enp5s0".to_string())
        );
        assert_eq!(
            default_interface_from_route_table("Iface\tDestination\n"),
            None
        );
    }

    #[test]
    fn global_scope_matches_python_ipaddress() {
        assert!(is_global_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_global_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(is_global_ipv4(Ipv4Addr::new(192, 0, 0, 9)));
        assert!(!is_global_ipv4(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!is_global_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!is_global_ipv4(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn loopback_interface_is_resolvable() {
        // Every Linux host has lo with 127.0.0.1; get_interface_ipv4 must
        // fall back to it as the first (non-global) address.
        assert_eq!(get_interface_ipv4("lo").unwrap(), "127.0.0.1");
    }

    #[test]
    fn missing_interface_is_an_error() {
        let error = get_interface_ipv4("definitely-not-an-iface0").unwrap_err();
        assert!(error.to_string().contains("does not exist"));
    }
}
