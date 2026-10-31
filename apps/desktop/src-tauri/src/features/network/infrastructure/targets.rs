//! Bounded target and CIDR expansion with optional hostname resolution.
//! This adapter may perform DNS resolution; pure port rules remain in domain.
use std::net::{IpAddr, ToSocketAddrs};

pub(super) const MAX_HOSTS: usize = 4096;

/// Expand target spec: single IP, hostname, CIDR (IPv4 /24-/32), comma lists.
pub fn parse_targets(spec: &str) -> Result<Vec<IpAddr>, String> {
    let mut hosts = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((ip_str, mask_str)) = part.split_once('/') {
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|_| format!("bad address in target: {ip_str}"))?;
            let mask: u8 = mask_str
                .parse()
                .map_err(|_| format!("bad mask: {mask_str}"))?;
            match ip {
                IpAddr::V4(v4) => {
                    if mask > 32 {
                        return Err(format!("bad IPv4 mask: /{mask}"));
                    }
                    let bits = u32::from(v4);
                    let suffix = 32u32.saturating_sub(mask as u32);
                    let count = 1u64 << suffix;
                    // The /0 size check must run before shifting by 32 bits.
                    if count > MAX_HOSTS as u64 {
                        return Err(format!(
                            "/{mask} expands to {count} hosts; the cap is {MAX_HOSTS}"
                        ));
                    }
                    let base = bits & u32::MAX.checked_shl(suffix).unwrap_or(0);
                    for i in 0..count {
                        hosts.push(IpAddr::V4(std::net::Ipv4Addr::from(base + i as u32)));
                    }
                }
                IpAddr::V6(_) => return Err("IPv6 CIDR targets arrive in a later arc".to_string()),
            }
        } else if let Ok(ip) = part.parse::<IpAddr>() {
            hosts.push(ip);
        } else {
            let resolved = (part, 0u16)
                .to_socket_addrs()
                .map_err(|e| format!("cannot resolve {part}: {e}"))?
                .map(|a| a.ip())
                .take(4)
                .collect::<Vec<_>>();
            if resolved.is_empty() {
                return Err(format!("cannot resolve {part}"));
            }
            hosts.extend(resolved);
        }
        if hosts.len() > MAX_HOSTS {
            return Err(format!(
                "target expands past {MAX_HOSTS} hosts; narrow the scope"
            ));
        }
    }
    if hosts.is_empty() {
        return Err("no targets parsed".to_string());
    }
    hosts.sort_unstable();
    hosts.dedup();
    Ok(hosts)
}
