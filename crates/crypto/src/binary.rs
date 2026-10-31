//! Read-only native PE/ELF/Mach-O header inspection. No execution or loaders.
use serde::Serialize;
pub const MAX_BINARY_BYTES: usize = 16 * 1024 * 1024;
const MAX_SECTIONS: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct BinarySection {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub address: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct BinaryInfo {
    pub format: &'static str,
    pub architecture: String,
    pub bits: u8,
    pub little_endian: bool,
    pub entry_point: Option<u64>,
    pub entry_kind: &'static str,
    pub sections: Vec<BinarySection>,
}
fn read(b: &[u8], off: usize, len: usize) -> Result<&[u8], String> {
    b.get(off..off.checked_add(len).ok_or("offset overflow")?)
        .ok_or_else(|| "truncated executable structure".into())
}
fn integer(b: &[u8], off: usize, width: usize, le: bool) -> Result<u64, String> {
    if !matches!(width, 2 | 4 | 8) {
        return Err("invalid integer width".into());
    }
    let mut arr = [0u8; 8];
    let source = read(b, off, width)?;
    if le {
        arr[..width].copy_from_slice(source);
        Ok(u64::from_le_bytes(arr))
    } else {
        arr[8 - width..].copy_from_slice(source);
        Ok(u64::from_be_bytes(arr))
    }
}
fn name(data: &[u8]) -> String {
    let len = data.iter().position(|&c| c == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..len]).into_owned()
}
fn architecture(fmt: &str, code: u64) -> String {
    match (fmt, code) {
        ("pe", 0x14c) | ("elf", 3) | ("mach-o", 7) => "x86".into(),
        ("pe", 0x8664) | ("elf", 62) | ("mach-o", 0x1000007) => "x86-64".into(),
        ("pe", 0xaa64) | ("elf", 183) | ("mach-o", 0x100000c) => "ARM64".into(),
        ("elf", 40) | ("mach-o", 12) => "ARM".into(),
        ("elf", 243) => "RISC-V".into(),
        _ => format!("machine-0x{code:x}"),
    }
}
fn file_span(b: &[u8], offset: u64, size: u64) -> Result<(), String> {
    if size > 0
        && offset
            .checked_add(size)
            .is_none_or(|end| end > b.len() as u64)
    {
        Err("section exceeds supplied file bounds".into())
    } else {
        Ok(())
    }
}
fn pe(b: &[u8]) -> Result<BinaryInfo, String> {
    if read(b, 0, 2)? != b"MZ" {
        return Err("bad PE DOS header".into());
    }
    let pe = integer(b, 0x3c, 4, true)? as usize;
    if pe > 1024 * 1024 || read(b, pe, 4)? != b"PE\0\0" {
        return Err("bad PE pointer".into());
    }
    let coff = pe + 4;
    read(b, coff, 20)?;
    let arch = integer(b, coff, 2, true)?;
    let count = integer(b, coff + 2, 2, true)? as usize;
    if count > MAX_SECTIONS {
        return Err("PE section limit exceeded".into());
    }
    let opt_len = integer(b, coff + 16, 2, true)? as usize;
    let opt = read(b, coff + 20, opt_len)?;
    let bits = match integer(opt, 0, 2, true)? {
        0x10b => 32,
        0x20b => 64,
        _ => return Err("unknown PE optional header".into()),
    };
    if opt_len < if bits == 32 { 96 } else { 112 } {
        return Err("short PE optional header".into());
    }
    let entry = integer(opt, 16, 4, true)?;
    let table = (coff + 20)
        .checked_add(opt_len)
        .ok_or("PE section table overflow")?;
    read(
        b,
        table,
        count.checked_mul(40).ok_or("PE section table overflow")?,
    )?;
    let mut sections = Vec::with_capacity(count);
    for i in 0..count {
        let off = table + 40 * i;
        let size = integer(b, off + 16, 4, true)?;
        let file_offset = integer(b, off + 20, 4, true)?;
        file_span(b, file_offset, size)?;
        sections.push(BinarySection {
            name: name(read(b, off, 8)?),
            offset: file_offset,
            size,
            address: integer(b, off + 12, 4, true)?,
        });
    }
    Ok(BinaryInfo {
        format: "pe",
        architecture: architecture("pe", arch),
        bits,
        little_endian: true,
        entry_point: Some(entry),
        entry_kind: "rva",
        sections,
    })
}
fn elf(b: &[u8]) -> Result<BinaryInfo, String> {
    let ident = read(b, 0, 16)?;
    if &ident[..4] != b"\x7fELF" || ident[6] != 1 {
        return Err("invalid ELF signature".into());
    }
    let bits = match ident[4] {
        1 => 32,
        2 => 64,
        _ => return Err("unsupported ELF class".into()),
    };
    let le = match ident[5] {
        1 => true,
        2 => false,
        _ => return Err("unsupported ELF byte order".into()),
    };
    read(b, 0, if bits == 32 { 52 } else { 64 })?;
    let arch = integer(b, 18, 2, le)?;
    let entry = integer(b, 24, if bits == 32 { 4 } else { 8 }, le)?;
    let (offset, entsize, count, names) = if bits == 32 {
        (
            integer(b, 32, 4, le)?,
            integer(b, 46, 2, le)? as usize,
            integer(b, 48, 2, le)? as usize,
            integer(b, 50, 2, le)? as usize,
        )
    } else {
        (
            integer(b, 40, 8, le)?,
            integer(b, 58, 2, le)? as usize,
            integer(b, 60, 2, le)? as usize,
            integer(b, 62, 2, le)? as usize,
        )
    };
    if count > MAX_SECTIONS || names == 0xffff {
        return Err("ELF extended sections unsupported".into());
    }
    let mut sections = Vec::new();
    if count > 0 {
        if entsize < if bits == 32 { 40 } else { 64 } || names >= count {
            return Err("invalid ELF section table".into());
        }
        let start = usize::try_from(offset).map_err(|_| "ELF offset overflow")?;
        read(
            b,
            start,
            count.checked_mul(entsize).ok_or("ELF table overflow")?,
        )?;
        let mut raw = Vec::with_capacity(count);
        for i in 0..count {
            let p = start + i * entsize;
            let kind = integer(b, p + 4, 4, le)?;
            let (addr, off, len) = if bits == 32 {
                (
                    integer(b, p + 12, 4, le)?,
                    integer(b, p + 16, 4, le)?,
                    integer(b, p + 20, 4, le)?,
                )
            } else {
                (
                    integer(b, p + 16, 8, le)?,
                    integer(b, p + 24, 8, le)?,
                    integer(b, p + 32, 8, le)?,
                )
            };
            if kind != 8 {
                file_span(b, off, len)?;
            }
            raw.push((integer(b, p, 4, le)? as usize, addr, off, len));
        }
        let (_, _, namesoff, nameslen) = raw[names];
        let table = read(
            b,
            usize::try_from(namesoff).map_err(|_| "ELF names offset overflow")?,
            usize::try_from(nameslen).map_err(|_| "ELF names length overflow")?,
        )?;
        for (index, address, offset, size) in raw {
            let label = if index == 0 {
                String::new()
            } else {
                let tail = table
                    .get(index..)
                    .ok_or("ELF string table index out of range")?;
                let end = tail
                    .iter()
                    .take(257)
                    .position(|&v| v == 0)
                    .ok_or("unterminated ELF section name")?;
                name(&tail[..end])
            };
            sections.push(BinarySection {
                name: label,
                offset,
                size,
                address,
            });
        }
    }
    Ok(BinaryInfo {
        format: "elf",
        architecture: architecture("elf", arch),
        bits,
        little_endian: le,
        entry_point: Some(entry),
        entry_kind: "virtual-address",
        sections,
    })
}
fn macho(b: &[u8]) -> Result<BinaryInfo, String> {
    let (bits, le) = match read(b, 0, 4)? {
        b"\xfe\xed\xfa\xce" => (32, false),
        b"\xce\xfa\xed\xfe" => (32, true),
        b"\xfe\xed\xfa\xcf" => (64, false),
        b"\xcf\xfa\xed\xfe" => (64, true),
        _ => return Err("unsupported Mach-O magic".into()),
    };
    let header = if bits == 32 { 28 } else { 32 };
    read(b, 0, header)?;
    let arch = integer(b, 4, 4, le)?;
    let count = integer(b, 16, 4, le)? as usize;
    let cmd_bytes = integer(b, 20, 4, le)? as usize;
    if count > 1024 || cmd_bytes > MAX_BINARY_BYTES {
        return Err("Mach-O load commands exceed limit".into());
    }
    let end = header
        .checked_add(cmd_bytes)
        .ok_or("Mach-O load commands overflow")?;
    read(b, header, cmd_bytes)?;
    let mut cursor = header;
    let mut sections = Vec::new();
    let mut entry = None;
    for _ in 0..count {
        let kind = integer(b, cursor, 4, le)?;
        let size = integer(b, cursor + 4, 4, le)? as usize;
        if size < 8 || cursor.checked_add(size).is_none_or(|n| n > end) {
            return Err("malformed Mach-O load command".into());
        }
        let cmd = read(b, cursor, size)?;
        if (kind == 1 && bits == 32) || (kind == 0x19 && bits == 64) {
            let (first, stride, count_at) = if bits == 32 {
                (56, 68, 48)
            } else {
                (72, 80, 64)
            };
            if size < first {
                return Err("truncated Mach-O segment".into());
            }
            let n = integer(cmd, count_at, 4, le)? as usize;
            if sections
                .len()
                .checked_add(n)
                .is_none_or(|v| v > MAX_SECTIONS)
            {
                return Err("Mach-O section limit exceeded".into());
            }
            read(
                cmd,
                first,
                n.checked_mul(stride).ok_or("Mach-O section overflow")?,
            )?;
            for j in 0..n {
                let p = first + j * stride;
                let (address, size, off, flags) = if bits == 32 {
                    (
                        integer(cmd, p + 32, 4, le)?,
                        integer(cmd, p + 36, 4, le)?,
                        integer(cmd, p + 40, 4, le)?,
                        integer(cmd, p + 56, 4, le)?,
                    )
                } else {
                    (
                        integer(cmd, p + 32, 8, le)?,
                        integer(cmd, p + 40, 8, le)?,
                        integer(cmd, p + 48, 4, le)?,
                        integer(cmd, p + 64, 4, le)?,
                    )
                };
                if !matches!(flags & 0xff, 1 | 0xc | 0x12) {
                    file_span(b, off, size)?;
                }
                sections.push(BinarySection {
                    name: name(read(cmd, p, 16)?),
                    offset: off,
                    size,
                    address,
                });
            }
        } else if kind == 0x80000028 {
            if size < 24 {
                return Err("short Mach-O LC_MAIN".into());
            }
            entry = Some(integer(cmd, 8, 8, le)?);
        }
        cursor += size;
    }
    if cursor != end {
        return Err("Mach-O load command length mismatch".into());
    }
    Ok(BinaryInfo {
        format: "mach-o",
        architecture: architecture("mach-o", arch),
        bits,
        little_endian: le,
        entry_point: entry,
        entry_kind: "file-offset",
        sections,
    })
}
pub fn inspect_binary(b: &[u8]) -> Result<BinaryInfo, String> {
    if b.len() > MAX_BINARY_BYTES {
        return Err("binary inspection limited to 16 MiB".into());
    }
    if b.starts_with(b"MZ") {
        pe(b)
    } else if b.starts_with(b"\x7fELF") {
        elf(b)
    } else if matches!(
        b.get(..4),
        Some(b"\xfe\xed\xfa\xce" | b"\xce\xfa\xed\xfe" | b"\xfe\xed\xfa\xcf" | b"\xcf\xfa\xed\xfe")
    ) {
        macho(b)
    } else {
        Err("unsupported executable signature".into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pe_sections_and_truncation() {
        let mut b = vec![0u8; 512];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&112u16.to_le_bytes());
        b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        let p = 0x98 + 112;
        b[p..p + 5].copy_from_slice(b".text");
        b[p + 16..p + 20].copy_from_slice(&16u32.to_le_bytes());
        b[p + 20..p + 24].copy_from_slice(&256u32.to_le_bytes());
        assert_eq!(inspect_binary(&b).unwrap().sections[0].name, ".text");
        b[p + 20..p + 24].copy_from_slice(&511u32.to_le_bytes());
        assert!(inspect_binary(&b).is_err());
    }
    #[test]
    fn elf_endianness() {
        for le in [true, false] {
            let mut b = vec![0u8; 64];
            b[..4].copy_from_slice(b"\x7fELF");
            b[4] = 2;
            b[5] = if le { 1 } else { 2 };
            b[6] = 1;
            b[18..20].copy_from_slice(&if le {
                183u16.to_le_bytes()
            } else {
                183u16.to_be_bytes()
            });
            assert_eq!(inspect_binary(&b).unwrap().architecture, "ARM64");
        }
        assert!(inspect_binary(b"\x7fELF").is_err());
    }
    #[test]
    fn macho_entry() {
        let mut b = vec![0u8; 56];
        b[..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
        b[4..8].copy_from_slice(&0x100000cu32.to_le_bytes());
        b[16..20].copy_from_slice(&1u32.to_le_bytes());
        b[20..24].copy_from_slice(&24u32.to_le_bytes());
        b[32..36].copy_from_slice(&0x80000028u32.to_le_bytes());
        b[36..40].copy_from_slice(&24u32.to_le_bytes());
        b[40..48].copy_from_slice(&0x100u64.to_le_bytes());
        assert_eq!(inspect_binary(&b).unwrap().entry_point, Some(0x100));
        b[36..40].copy_from_slice(&999u32.to_le_bytes());
        assert!(inspect_binary(&b).is_err());
    }
}
