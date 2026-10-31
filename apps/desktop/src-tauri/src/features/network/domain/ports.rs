//! Port selection policy: curated presets and bounded explicit port ranges.
//! Pure parsing: no network access or Tauri dependencies.

pub(super) const MAX_PORTS: usize = 1024;

/// Curated CyberDeck TCP port preset, not Nmap's popularity-ranked port list.
pub const TOP_PORTS_100: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900,
    8080, 8443, 67, 69, 123, 161, 389, 636, 1080, 1433, 1521, 2049, 2121, 3128, 3268, 4444, 554,
    5432, 5555, 6379, 8000, 8008, 8081, 8888, 9000, 9090, 9200, 10000, 27017, 50000, 5985, 1, 7, 9,
    13, 17, 19, 20, 26, 37, 42, 43, 49, 70, 79, 81, 88, 102, 106, 109, 113, 119, 137, 138, 179,
    194, 199, 264, 427, 465, 500, 512, 513, 514, 515, 524, 548, 563, 587, 593, 623, 631, 873, 902,
    989, 990, 992, 1194, 1883, 2375, 5060,
];

/// Port spec: "top25", "top100", "1-1024", or explicit "80,443,8000-8100".
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let spec = spec.trim().to_lowercase();
    let mut ports: Vec<u16> = Vec::new();
    let push_range = |ports: &mut Vec<u16>, start: u16, end: u16| {
        for p in start..=end {
            ports.push(p);
        }
    };
    match spec.as_str() {
        "top25" => ports.extend_from_slice(&TOP_PORTS_100[..25]),
        "top100" => ports.extend_from_slice(TOP_PORTS_100),
        "1-1024" | "wellknown" => push_range(&mut ports, 1, 1024),
        _ => {
            for part in spec.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some((a, b)) = part.split_once('-') {
                    let start: u16 = a.trim().parse().map_err(|_| format!("bad port: {a}"))?;
                    let end: u16 = b.trim().parse().map_err(|_| format!("bad port: {b}"))?;
                    if end < start || (end - start) as usize > MAX_PORTS {
                        return Err(format!("port range too large: {part}"));
                    }
                    push_range(&mut ports, start, end);
                } else {
                    let p: u16 = part.parse().map_err(|_| format!("bad port: {part}"))?;
                    ports.push(p);
                }
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err("no ports parsed".to_string());
    }
    if ports.len() > MAX_PORTS {
        return Err(format!(
            "{} ports exceed the cap of {MAX_PORTS}",
            ports.len()
        ));
    }
    Ok(ports)
}
