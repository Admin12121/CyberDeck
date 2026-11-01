//! Bounded target planning for authorized native scans: literal IPs,
//! IPv4/IPv6 CIDR and explicitly resolved hostnames, with exclusions.
//! No network expansion after the caller's native scope confirmation.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

pub(super) const MAX_HOSTS: usize = 4096;

#[derive(Debug, Clone, Copy)]
enum AddressSelector {
    Single(IpAddr),
    Network(IpAddr, u8),
}

impl AddressSelector {
    fn contains(self, target: IpAddr) -> bool {
        match self {
            Self::Single(ip) => ip == target,
            Self::Network(IpAddr::V4(ip), prefix) => {
                let IpAddr::V4(other) = target else {
                    return false;
                };
                let shift = 32u32 - u32::from(prefix);
                if shift == 32 {
                    return true;
                }
                (u32::from(ip) >> shift) == (u32::from(other) >> shift)
            }
            Self::Network(IpAddr::V6(ip), prefix) => {
                let IpAddr::V6(other) = target else {
                    return false;
                };
                let shift = 128u32 - u32::from(prefix);
                if shift == 128 {
                    return true;
                }
                (u128::from(ip) >> shift) == (u128::from(other) >> shift)
            }
        }
    }

    fn expand(self, into: &mut Vec<IpAddr>) -> Result<(), String> {
        let (address, width, prefix) = match self {
            Self::Single(ip) => {
                if into.len() >= MAX_HOSTS {
                    return Err(format!("scan target cap is {MAX_HOSTS} hosts"));
                }
                into.push(ip);
                return Ok(());
            }
            Self::Network(IpAddr::V4(ip), prefix) => (u128::from(u32::from(ip)), 32u32, prefix),
            Self::Network(IpAddr::V6(ip), prefix) => (u128::from(ip), 128u32, prefix),
        };
        let host_bits = width - u32::from(prefix);
        // Bound *before* any u128 shift (particularly IPv6 /0). An
        // excluded /0 is represented as a matcher, never enumerated.
        if host_bits > 12 {
            return Err(format!(
                "/{prefix} expands past {MAX_HOSTS} hosts; narrow the scope"
            ));
        }
        let count = 1usize << host_bits;
        if count > MAX_HOSTS.saturating_sub(into.len()) {
            return Err(format!(
                "target expands past {MAX_HOSTS} hosts; narrow the scope"
            ));
        }
        let mask = if host_bits == 0 {
            u128::MAX
        } else {
            u128::MAX << host_bits
        };
        let base = address & mask;
        for i in 0..count {
            let value = base + i as u128;
            into.push(if width == 32 {
                IpAddr::V4(Ipv4Addr::from(value as u32))
            } else {
                IpAddr::V6(Ipv6Addr::from(value))
            });
        }
        Ok(())
    }
}

fn parse_selectors(value: &str) -> Result<Vec<AddressSelector>, String> {
    if let Some((addr, prefix)) = value.split_once('/') {
        let address: IpAddr = addr
            .parse()
            .map_err(|_| format!("bad CIDR address: {addr}"))?;
        let bits: u8 = prefix
            .parse()
            .map_err(|_| format!("bad CIDR prefix: {prefix}"))?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        if bits > width {
            return Err(format!("invalid /{bits} prefix for {address}"));
        }
        return Ok(vec![AddressSelector::Network(address, bits)]);
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(vec![AddressSelector::Single(ip)]);
    }
    // Names are resolved once into a small pinned literal-IP set. Hostnames
    // are never retained for later dynamic expansion during a scan.
    if value.is_empty()
        || value
            .chars()
            .any(|c| matches!(c, '/' | '!' | ' ' | '\\' | '@' | ':'))
    {
        return Err(format!("invalid target name: {value}"));
    }
    let ips: Vec<_> = (value, 0u16)
        .to_socket_addrs()
        .map_err(|_| format!("cannot resolve target: {value}"))?
        .take(4)
        .map(|address| AddressSelector::Single(address.ip()))
        .collect();
    if ips.is_empty() {
        return Err(format!("cannot resolve target: {value}"));
    }
    Ok(ips)
}

/// Inline exclusions use `!192.0.2.0/28` or `!2001:db8::1`.
/// Exclusions never add targets; an excluded CIDR may be broader than the
/// expansion cap because it is matched, not enumerated.
pub fn parse_targets(spec: &str) -> Result<Vec<IpAddr>, String> {
    let mut included = Vec::new();
    let mut excluded = Vec::new();
    for part in spec
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (exclude, value) = match part.strip_prefix('!') {
            Some(value) => (true, value.trim()),
            None => (false, part),
        };
        let parsed = parse_selectors(value)?;
        if exclude {
            excluded.extend(parsed);
        } else {
            for selector in parsed {
                selector.expand(&mut included)?;
            }
        }
    }
    included.retain(|ip| !excluded.iter().any(|selector| selector.contains(*ip)));
    included.sort_unstable();
    included.dedup();
    if included.is_empty() {
        return Err("no authorized targets remain after exclusions".to_string());
    }
    Ok(included)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_cidr_expands_normalized_network_without_wrap() {
        let got = parse_targets("2001:db8::5/126").unwrap();
        assert_eq!(got.len(), 4);
        assert_eq!(got[0], "2001:db8::4".parse::<IpAddr>().unwrap());
        assert_eq!(got[3], "2001:db8::7".parse::<IpAddr>().unwrap());
        assert_eq!(parse_targets("2001:db8::/116").unwrap().len(), 4096);
        assert!(parse_targets("2001:db8::/115").is_err());
        assert!(parse_targets("::/0").is_err());
        assert!(parse_targets("::/129").is_err());
    }

    #[test]
    fn exclusions_do_not_add_hosts_or_cross_address_families() {
        let got = parse_targets("192.0.2.4/30,!192.0.2.5,2001:db8::/127,!::/0").unwrap();
        assert_eq!(got.len(), 3);
        assert!(got.iter().all(IpAddr::is_ipv4));
        assert!(!got.contains(&"192.0.2.5".parse().unwrap()));
        let single = parse_targets("2001:db8::/126,!2001:db8::/127").unwrap();
        assert_eq!(single.len(), 2);
        assert_eq!(single[0], "2001:db8::2".parse::<IpAddr>().unwrap());
        assert!(parse_targets("192.0.2.1,!0.0.0.0/0").is_err());
    }

    #[test]
    fn cidr_budgets_reject_overflow_and_keep_original_compatibility() {
        assert_eq!(parse_targets("127.0.0.1").unwrap().len(), 1);
        assert_eq!(parse_targets("192.168.1.0/30").unwrap().len(), 4);
        assert!(parse_targets("192.0.2.1/0").is_err());
        assert!(parse_targets("192.0.2.1/33").is_err());
        assert!(parse_targets("192.0.2.0/20,2001:db8::1").is_err());
        assert_eq!(parse_targets("192.0.2.1,192.0.2.1").unwrap().len(), 1);
        assert!(parse_targets("192.0.2.1,!192.0.2.1").is_err());
    }
}
