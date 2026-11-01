//! Bounded native evidence analysis. Format parsers do not execute embedded files.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

/// All four legacy digest values from one bounded stream, without storing
/// the source in memory. CRC32 retains the existing double-hex wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamDigests {
    pub bytes: u64,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub crc32: String,
}

pub fn digest_stream<R: Read>(mut source: R, max_bytes: u64) -> Result<StreamDigests, String> {
    use md5::Md5;
    use sha1::Sha1;
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut md5 = Md5::new();
    let mut crc = crc32fast::Hasher::new();
    let mut bytes = 0u64;
    let mut block = [0u8; 64 * 1024];
    loop {
        let n = source
            .read(&mut block)
            .map_err(|e| format!("digest read failed: {e}"))?;
        if n == 0 {
            break;
        }
        bytes = bytes.checked_add(n as u64).ok_or("digest input overflow")?;
        if bytes > max_bytes {
            return Err("digest input exceeds byte limit".into());
        }
        sha256.update(&block[..n]);
        sha1.update(&block[..n]);
        md5.update(&block[..n]);
        crc.update(&block[..n]);
    }
    let crc_text = hex::encode(crc.finalize().to_be_bytes());
    Ok(StreamDigests {
        bytes,
        sha256: hex::encode(sha256.finalize()),
        sha1: hex::encode(sha1.finalize()),
        md5: hex::encode(md5.finalize()),
        crc32: hex::encode(crc_text.as_bytes()),
    })
}

pub const MAX_WINDOW: usize = 8 * 1024 * 1024;
pub const MAX_VERIFIED_READ: usize = 16 * 1024 * 1024;
pub const MAX_STRING_HITS: usize = 2000;
pub const MAX_ENTROPY_REGIONS: usize = 2048;
pub const MAX_METADATA_INPUT: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringMatch {
    pub offset: u64,
    pub encoding: &'static str,
    pub text: String,
}
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EntropyRegion {
    pub offset: u64,
    pub length: usize,
    pub entropy: f64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MetadataField {
    pub namespace: &'static str,
    pub key: &'static str,
    pub value: String,
    pub offset: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MetadataReport {
    pub format: &'static str,
    pub fields: Vec<MetadataField>,
    pub parsed_bytes: usize,
    pub complete: bool,
}

/// Fully hash the same open handle that will supply the requested window.
/// No materialization of the rest of the file; reject stale index and short reads.
pub fn verified_window<R: Read + Seek>(
    file: &mut R,
    expected_size: u64,
    expected_sha256: &str,
    offset: u64,
    length: usize,
    limit: usize,
) -> Result<Vec<u8>, String> {
    if length == 0 || length > limit || limit > MAX_VERIFIED_READ {
        return Err("evidence window limit exceeded".into());
    }
    let actual = file
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("evidence seek failed: {e}"))?;
    if actual != expected_size {
        return Err("evidence indexed size mismatch".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut sha = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("cannot verify evidence: {e}"))?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or("evidence size overflow")?;
        if total > expected_size {
            return Err("evidence length changed during verification".into());
        }
        sha.update(&buffer[..n]);
    }
    if total != expected_size || !hex::encode(sha.finalize()).eq_ignore_ascii_case(expected_sha256)
    {
        return Err("evidence SHA256 integrity failure".into());
    }
    let start = offset.min(expected_size);
    let count = (expected_size - start).min(length as u64) as usize;
    file.seek(SeekFrom::Start(start))
        .map_err(|e| e.to_string())?;
    let mut window = vec![0u8; count];
    file.read_exact(&mut window)
        .map_err(|e| format!("cannot read verified window: {e}"))?;
    Ok(window)
}

fn add(
    out: &mut Vec<StringMatch>,
    base: u64,
    from: usize,
    label: &'static str,
    text: &str,
    count: usize,
    min: usize,
    limit: usize,
) {
    if count >= min && out.len() <= limit {
        out.push(StringMatch {
            offset: base + from as u64,
            encoding: label,
            text: text.to_owned(),
        });
    }
}
fn ascii(data: &[u8], base: u64, min: usize, limit: usize, out: &mut Vec<StringMatch>) {
    let mut from = None;
    let mut text = String::new();
    let mut n = 0;
    for (i, c) in data
        .iter()
        .copied()
        .enumerate()
        .chain(std::iter::once((data.len(), 0)))
    {
        if i < data.len() && (32..=126).contains(&c) {
            if from.is_none() {
                from = Some(i);
            }
            n += 1;
            if text.len() < 2048 {
                text.push(c as char);
            }
        } else if let Some(pos) = from.take() {
            add(out, base, pos, "ascii", &text, n, min, limit);
            text.clear();
            n = 0;
        }
    }
}
fn unicode(
    data: &[u8],
    base: u64,
    min: usize,
    limit: usize,
    le: bool,
    parity: usize,
    out: &mut Vec<StringMatch>,
) {
    let label = if le { "utf16le" } else { "utf16be" };
    let mut from = None;
    let mut text = String::new();
    let mut n = 0;
    let mut i = parity;
    while i + 1 < data.len() {
        let v = if le {
            u16::from_le_bytes([data[i], data[i + 1]])
        } else {
            u16::from_be_bytes([data[i], data[i + 1]])
        };
        let (ch, step) = if (0xd800..=0xdbff).contains(&v) && i + 3 < data.len() {
            let next = if le {
                u16::from_le_bytes([data[i + 2], data[i + 3]])
            } else {
                u16::from_be_bytes([data[i + 2], data[i + 3]])
            };
            if (0xdc00..=0xdfff).contains(&next) {
                (
                    char::from_u32(
                        0x10000 + (((v as u32) - 0xd800) << 10) + (next as u32) - 0xdc00,
                    ),
                    4,
                )
            } else {
                (None, 2)
            }
        } else {
            (char::from_u32(v as u32), 2)
        };
        if let Some(c) = ch.filter(|c| !c.is_control() && (!c.is_whitespace() || *c == ' ')) {
            if from.is_none() {
                from = Some(i);
            }
            n += 1;
            if text.len() + c.len_utf8() <= 2048 {
                text.push(c);
            }
        } else if let Some(pos) = from.take() {
            add(out, base, pos, label, &text, n, min, limit);
            text.clear();
            n = 0;
        }
        i += step;
    }
    if let Some(pos) = from {
        add(out, base, pos, label, &text, n, min, limit);
    }
}
pub fn strings(
    data: &[u8],
    base: u64,
    min: usize,
    limit: usize,
) -> Result<(Vec<StringMatch>, bool), String> {
    if data.len() > MAX_WINDOW
        || !(2..=128).contains(&min)
        || !(1..=MAX_STRING_HITS).contains(&limit)
    {
        return Err("invalid forensic string limits".into());
    }
    let mut found = Vec::new();
    ascii(data, base, min, limit, &mut found);
    for le in [true, false] {
        for parity in [0, 1] {
            let mut candidates = Vec::new();
            unicode(data, base, min, limit, le, parity, &mut candidates);
            found.extend(candidates);
        }
    }
    found.sort_by(|a, b| (a.offset, a.encoding).cmp(&(b.offset, b.encoding)));
    let capped = found.len() > limit;
    found.truncate(limit);
    Ok((found, capped))
}
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / len;
            -p * p.log2()
        })
        .sum()
}
pub fn entropy_regions(data: &[u8], base: u64, block: usize) -> Result<Vec<EntropyRegion>, String> {
    if data.len() > MAX_WINDOW
        || !(256..=MAX_WINDOW).contains(&block)
        || data.len().div_ceil(block) > MAX_ENTROPY_REGIONS
    {
        return Err("invalid entropy regions limit".into());
    }
    data.chunks(block)
        .enumerate()
        .map(|(i, b)| {
            Ok(EntropyRegion {
                offset: base
                    .checked_add((i * block) as u64)
                    .ok_or("entropy offset overflow")?,
                length: b.len(),
                entropy: shannon(b),
            })
        })
        .collect()
}
fn b32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().unwrap())
}
fn tiff_u16(data: &[u8], at: usize, le: bool) -> Result<u16, String> {
    let x = data
        .get(at..at.checked_add(2).ok_or("TIFF offset overflow")?)
        .ok_or("truncated TIFF u16")?;
    Ok(if le {
        u16::from_le_bytes(x.try_into().unwrap())
    } else {
        u16::from_be_bytes(x.try_into().unwrap())
    })
}
fn tiff_u32(data: &[u8], at: usize, le: bool) -> Result<u32, String> {
    let x = data
        .get(at..at.checked_add(4).ok_or("TIFF offset overflow")?)
        .ok_or("truncated TIFF u32")?;
    Ok(if le {
        u32::from_le_bytes(x.try_into().unwrap())
    } else {
        u32::from_be_bytes(x.try_into().unwrap())
    })
}
/// Parse the TIFF GPS IFD through checked, nonrecursive offsets. Only bounded
/// hemisphere references and three-component latitude/longitude rationals are
/// supported; unsupported GPS tags are ignored rather than interpreted.
fn gps_ifd(data: &[u8], base: u64, at: usize, le: bool) -> Result<Vec<MetadataField>, String> {
    let count = tiff_u16(data, at, le)? as usize;
    if count > 64 {
        return Err("too many GPS EXIF fields".into());
    }
    let start = at.checked_add(2).ok_or("GPS IFD overflow")?;
    let end = start
        .checked_add(count.checked_mul(12).ok_or("GPS IFD overflow")?)
        .and_then(|e| e.checked_add(4))
        .ok_or("GPS IFD overflow")?;
    if end > data.len() {
        return Err("truncated GPS EXIF IFD".into());
    }
    let mut lat_ref = None;
    let mut lon_ref = None;
    let mut lat = None;
    let mut lon = None;
    for i in 0..count {
        let entry = start + i * 12;
        let tag = tiff_u16(data, entry, le)?;
        let kind = tiff_u16(data, entry + 2, le)?;
        let num = tiff_u32(data, entry + 4, le)?;
        if matches!(tag, 1 | 3) {
            if kind != 2 || num != 2 {
                return Err("invalid GPS hemisphere reference".into());
            }
            let reference = *data.get(entry + 8).ok_or("missing GPS reference")? as char;
            let nul = *data.get(entry + 9).ok_or("missing GPS reference NUL")?;
            if nul != 0
                || (tag == 1 && !matches!(reference, 'N' | 'S'))
                || (tag == 3 && !matches!(reference, 'E' | 'W'))
            {
                return Err("invalid GPS hemisphere".into());
            }
            if tag == 1 {
                lat_ref = Some(reference);
            } else {
                lon_ref = Some(reference);
            }
        } else if matches!(tag, 2 | 4) {
            if kind != 5 || num != 3 {
                return Err("invalid GPS rational vector".into());
            }
            let value_at = tiff_u32(data, entry + 8, le)? as usize;
            if value_at.checked_add(24).ok_or("GPS rational overflow")? > data.len() {
                return Err("truncated GPS rationals".into());
            }
            let mut components = [0.0f64; 3];
            for (component, slot) in components.iter_mut().enumerate() {
                let at = value_at + component * 8;
                let numerator = tiff_u32(data, at, le)?;
                let denominator = tiff_u32(data, at + 4, le)?;
                if denominator == 0 {
                    return Err("zero GPS rational denominator".into());
                }
                *slot = numerator as f64 / denominator as f64;
            }
            let max_degrees = if tag == 2 { 90.0 } else { 180.0 };
            if components[0] > max_degrees || components[1] >= 60.0 || components[2] >= 60.0 {
                return Err("out-of-range GPS coordinate".into());
            }
            let degrees = components[0] + components[1] / 60.0 + components[2] / 3600.0;
            let offset = base
                .checked_add(value_at as u64)
                .ok_or("GPS offset overflow")?;
            if tag == 2 {
                lat = Some((degrees, offset));
            } else {
                lon = Some((degrees, offset));
            }
        }
    }
    let mut fields = Vec::with_capacity(2);
    for (key, coordinate, reference, negative) in [
        ("latitude", lat, lat_ref, 'S'),
        ("longitude", lon, lon_ref, 'W'),
    ] {
        if let Some((value, offset)) = coordinate {
            let direction = reference.ok_or("GPS coordinate lacks hemisphere")?;
            fields.push(MetadataField {
                namespace: "exif.gps",
                key,
                value: format!("{:.6}", if direction == negative { -value } else { value }),
                offset,
            });
        }
    }
    Ok(fields)
}

fn exif(data: &[u8], base: u64) -> Result<Vec<MetadataField>, String> {
    if data.len() < 8 {
        return Err("short Exif TIFF".into());
    }
    let le = match data.get(..2) {
        Some(b"II") => true,
        Some(b"MM") => false,
        _ => return Err("invalid TIFF endian".into()),
    };
    if tiff_u16(data, 2, le)? != 42 {
        return Err("invalid TIFF magic".into());
    }
    let pos = tiff_u32(data, 4, le)? as usize;
    let count = tiff_u16(data, pos, le)? as usize;
    if count > 256 {
        return Err("too many EXIF fields".into());
    }
    let start = pos.checked_add(2).ok_or("EXIF overflow")?;
    let end = start
        .checked_add(count.checked_mul(12).ok_or("EXIF overflow")?)
        .ok_or("EXIF overflow")?;
    if end.checked_add(4).ok_or("EXIF overflow")? > data.len() {
        return Err("truncated EXIF IFD".into());
    }
    let mut fields = Vec::new();
    let mut gps_pointer = None;
    for i in 0..count {
        let at = start + i * 12;
        let tag = tiff_u16(data, at, le)?;
        let typ = tiff_u16(data, at + 2, le)?;
        let n = tiff_u32(data, at + 4, le)? as usize;
        if tag == 0x8825 {
            if typ != 4 || n != 1 || gps_pointer.is_some() {
                return Err("invalid EXIF GPS IFD pointer".into());
            }
            gps_pointer = Some(tiff_u32(data, at + 8, le)? as usize);
            continue;
        }
        let key = match tag {
            0x010f => "make",
            0x0110 => "model",
            0x0131 => "software",
            0x0132 => "datetime",
            0x0112 => "orientation",
            _ => continue,
        };
        let value = if tag == 0x0112 && typ == 3 && n == 1 {
            tiff_u16(data, at + 8, le)?.to_string()
        } else if typ == 2 && (1..=2048).contains(&n) {
            let loc = if n <= 4 {
                at + 8
            } else {
                tiff_u32(data, at + 8, le)? as usize
            };
            let x = data
                .get(loc..loc.checked_add(n).ok_or("EXIF size overflow")?)
                .ok_or("truncated EXIF value")?;
            x.split(|b| *b == 0)
                .next()
                .unwrap_or(x)
                .iter()
                .map(|b| char::from(*b))
                .collect()
        } else {
            continue;
        };
        fields.push(MetadataField {
            namespace: "exif.ifd0",
            key,
            value,
            offset: base + at as u64,
        });
    }
    if let Some(pointer) = gps_pointer {
        fields.extend(gps_ifd(data, base, pointer, le)?);
    }
    Ok(fields)
}
/// Metadata mode preserves partial/metadata-only PNG compatibility.
pub fn metadata(data: &[u8], base: u64) -> Result<MetadataReport, String> {
    metadata_impl(data, base, false)
}

/// Carving mode additionally requires an IDAT before IEND. This validates
/// PNG chunk framing, ordering and CRCs, not compressed pixel contents.
pub fn carving_png_metadata(data: &[u8], base: u64) -> Result<MetadataReport, String> {
    metadata_impl(data, base, true)
}

fn metadata_impl(data: &[u8], base: u64, require_png_idat: bool) -> Result<MetadataReport, String> {
    base.checked_add(data.len() as u64)
        .ok_or("metadata absolute offset overflow")?;
    if data.len() > MAX_METADATA_INPUT {
        return Err("metadata scan window exceeds 4MiB".into());
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        let mut i = 8usize;
        let mut found_ihdr = false;
        let mut seen_idat = false;
        let mut end_found = false;
        let mut fields = Vec::new();
        while i < data.len() {
            if i + 12 > data.len() {
                return Err("truncated PNG chunk".into());
            }
            let n = b32(&data[i..i + 4]) as usize;
            let end = i
                .checked_add(n)
                .and_then(|v| v.checked_add(12))
                .ok_or("PNG chunk overflow")?;
            if end > data.len() {
                return Err("truncated PNG payload".into());
            }
            let tag = &data[i + 4..i + 8];
            let payload = &data[i + 8..i + 8 + n];
            if crc32fast::hash(&data[i + 4..i + 8 + n]) != b32(&data[i + 8 + n..end]) {
                return Err("PNG CRC failure".into());
            }
            if !found_ihdr {
                if tag != b"IHDR" || n != 13 {
                    return Err("invalid PNG IHDR".into());
                }
                found_ihdr = true;
                let width = b32(&payload[0..4]);
                let height = b32(&payload[4..8]);
                if width == 0 || height == 0 {
                    return Err("invalid PNG dimensions".into());
                }
                for (key, value, off) in [
                    ("width", width.to_string(), 8),
                    ("height", height.to_string(), 12),
                    ("bit_depth", payload[8].to_string(), 16),
                    ("color_type", payload[9].to_string(), 17),
                ] {
                    fields.push(MetadataField {
                        namespace: "png",
                        key,
                        value,
                        offset: base + (i + off) as u64,
                    });
                }
            } else if tag == b"tEXt" && fields.len() < 60 {
                if let Some(z) = payload.iter().position(|b| *b == 0) {
                    if z > 0 && z <= 79 && payload.len() - z - 1 <= 2048 {
                        let keyword = payload[..z].iter().map(|b| char::from(*b)).collect();
                        let value = payload[z + 1..].iter().map(|b| char::from(*b)).collect();
                        fields.push(MetadataField {
                            namespace: "png.text",
                            key: "keyword",
                            value: keyword,
                            offset: base + (i + 8) as u64,
                        });
                        fields.push(MetadataField {
                            namespace: "png.text",
                            key: "value",
                            value,
                            offset: base + (i + 9 + z) as u64,
                        });
                    }
                }
            } else if tag == b"IDAT" {
                seen_idat = true;
            } else if tag == b"IEND" {
                if n != 0 {
                    return Err("PNG IEND not empty".into());
                }
                if require_png_idat && !seen_idat {
                    return Err("PNG carving requires image data before IEND".into());
                }
                end_found = true;
                i = end;
                break;
            }
            i = end;
        }
        return Ok(MetadataReport {
            format: "png",
            fields,
            parsed_bytes: i,
            complete: end_found,
        });
    }
    if data.starts_with(b"\xff\xd8") {
        let mut i = 2usize;
        let mut fields = Vec::new();
        let mut done = false;
        while i < data.len() {
            if data[i] != 0xff {
                return Err("invalid JPEG marker".into());
            }
            while i < data.len() && data[i] == 0xff {
                i += 1;
            }
            if i >= data.len() {
                break;
            }
            let tag = data[i];
            i += 1;
            if tag == 0xd9 {
                done = true;
                break;
            }
            if tag == 0xda {
                break;
            } // Do not parse compressed image data as markers.
            if tag == 0x01 || (0xd0..=0xd7).contains(&tag) {
                continue;
            }
            if i + 2 > data.len() {
                return Err("truncated JPEG segment".into());
            }
            let n = u16::from_be_bytes(data[i..i + 2].try_into().unwrap()) as usize;
            if n < 2 || i + n > data.len() {
                return Err("invalid JPEG segment length".into());
            }
            let p = &data[i + 2..i + n];
            let payload_start = i + 2;
            if tag == 0xe1 && p.starts_with(b"Exif\0\0") {
                fields.extend(exif(&p[6..], base + (payload_start + 6) as u64)?);
            }
            if matches!(
                tag,
                0xc0 | 0xc1
                    | 0xc2
                    | 0xc3
                    | 0xc5
                    | 0xc6
                    | 0xc7
                    | 0xc9
                    | 0xca
                    | 0xcb
                    | 0xcd
                    | 0xce
                    | 0xcf
            ) && p.len() >= 5
            {
                let height = u16::from_be_bytes([p[1], p[2]]);
                let width = u16::from_be_bytes([p[3], p[4]]);
                for (key, value, at) in [
                    ("height", height.to_string(), 1),
                    ("width", width.to_string(), 3),
                ] {
                    fields.push(MetadataField {
                        namespace: "jpeg",
                        key,
                        value,
                        offset: base + (payload_start + at) as u64,
                    });
                }
            }
            i += n;
        }
        return Ok(MetadataReport {
            format: "jpeg",
            fields,
            parsed_bytes: i,
            complete: done,
        });
    }
    Err("only PNG and JPEG metadata supported".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn verified_window_rejects_tamper_and_reads_offset() {
        let bytes = b"0123456789ABCDEF".to_vec();
        let hash = hex::encode(Sha256::digest(&bytes));
        let mut c = Cursor::new(bytes.clone());
        assert_eq!(
            verified_window(&mut c, 16, &hash, 5, 4, 1024).unwrap(),
            b"5678"
        );
        let mut changed = Cursor::new(b"0123456789ABCDEx".to_vec());
        assert!(verified_window(&mut changed, 16, &hash, 5, 4, 1024).is_err());
    }
    #[test]
    fn strings_encodings_and_hits() {
        let mut data = b"ABCD\0\0\0\0\0\0".to_vec();
        let at = data.len();
        data.extend("World 世界".encode_utf16().flat_map(|v| v.to_le_bytes()));
        let (hits, _) = strings(&data, 50, 4, 100).unwrap();
        assert!(hits
            .iter()
            .any(|h| h.encoding == "ascii" && h.text == "ABCD" && h.offset == 50));
        assert!(hits.iter().any(|h| h.encoding == "utf16le"
            && h.text == "World 世界"
            && h.offset == 50 + at as u64));
        let (cap, limited) = strings(b"ABCD\0EFGH\0IJKL", 0, 4, 1).unwrap();
        assert!(limited);
        assert_eq!(cap.len(), 1);
    }
    #[test]
    fn entropy_known_vectors() {
        let sample = (0..=255u8).collect::<Vec<_>>();
        let r = entropy_regions(&sample, 128, 256).unwrap();
        assert!((r[0].entropy - 8.0).abs() < 0.0001);
        assert_eq!(r[0].offset, 128);
        assert_eq!(
            entropy_regions(&[1u8; 512], 0, 256).unwrap()[0].entropy,
            0.0
        );
    }
    #[test]
    fn png_real_crc_and_tampered_crc() {
        fn chunk(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
            let mut out = (body.len() as u32).to_be_bytes().to_vec();
            out.extend_from_slice(tag);
            out.extend_from_slice(body);
            out.extend_from_slice(&crc32fast::hash(&out[4..]).to_be_bytes());
            out
        }
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(chunk(b"IHDR", &[0, 0, 0, 5, 0, 0, 0, 7, 8, 2, 0, 0, 0]));
        png.extend(chunk(b"IEND", b""));
        let m = metadata(&png, 0).unwrap();
        assert!(m.complete);
        assert!(m.fields.iter().any(|f| f.key == "width" && f.value == "5"));
        png[18] = 6;
        assert!(metadata(&png, 0).is_err());
    }
    #[test]
    fn jpeg_independent_exif_ifd_fixture() {
        let mut tiff = b"II\x2a\0\x08\0\0\0\x01\0\x0f\x01\x02\0\x04\0\0\0ACME\0\0\0\0".to_vec();
        // IFD0 make string is inline because its declared length is four.
        let mut jpeg = b"\xff\xd8\xff\xe1".to_vec();
        let n = (tiff.len() + 8) as u16;
        jpeg.extend_from_slice(&n.to_be_bytes());
        jpeg.extend_from_slice(b"Exif\0\0");
        jpeg.append(&mut tiff);
        jpeg.extend_from_slice(b"\xff\xd9");
        let m = metadata(&jpeg, 0).unwrap();
        assert!(m
            .fields
            .iter()
            .any(|f| f.key == "make" && f.value == "ACME"));
        assert!(m.complete);
    }

    #[test]
    fn exif_gps_ifd_decodes_both_endiannesses_and_rejects_adversarial_offsets() {
        fn put16(data: &mut [u8], at: usize, value: u16, le: bool) {
            data[at..at + 2].copy_from_slice(&if le {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            });
        }
        fn put32(data: &mut [u8], at: usize, value: u32, le: bool) {
            data[at..at + 4].copy_from_slice(&if le {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            });
        }
        fn tiff(le: bool) -> Vec<u8> {
            let mut data = vec![0u8; 128];
            data[..2].copy_from_slice(if le { b"II" } else { b"MM" });
            put16(&mut data, 2, 42, le);
            put32(&mut data, 4, 8, le);
            put16(&mut data, 8, 1, le); // one IFD0 GPS pointer
            put16(&mut data, 10, 0x8825, le);
            put16(&mut data, 12, 4, le);
            put32(&mut data, 14, 1, le);
            put32(&mut data, 18, 26, le);
            put16(&mut data, 26, 4, le); // four GPS entries
            for (index, tag, kind, count, value) in [
                (0usize, 1u16, 2u16, 2u32, 0u32),
                (1, 2, 5, 3, 80),
                (2, 3, 2, 2, 0),
                (3, 4, 5, 3, 104),
            ] {
                let pos = 28 + index * 12;
                put16(&mut data, pos, tag, le);
                put16(&mut data, pos + 2, kind, le);
                put32(&mut data, pos + 4, count, le);
                if matches!(tag, 1 | 3) {
                    data[pos + 8] = if tag == 1 { b'N' } else { b'E' };
                    data[pos + 9] = 0;
                } else {
                    put32(&mut data, pos + 8, value, le);
                }
            }
            for (i, n) in [27u32, 59, 30, 85, 19, 0].iter().enumerate() {
                let at = 80 + i * 8;
                put32(&mut data, at, *n, le);
                put32(&mut data, at + 4, 1, le);
            }
            data
        }
        fn jpeg(tiff: &[u8]) -> Vec<u8> {
            let mut out = b"\xff\xd8\xff\xe1".to_vec();
            out.extend_from_slice(&((tiff.len() + 8) as u16).to_be_bytes());
            out.extend_from_slice(b"Exif\0\0");
            out.extend_from_slice(tiff);
            out.extend_from_slice(b"\xff\xd9");
            out
        }
        for le in [true, false] {
            let original = tiff(le);
            let report = metadata(&jpeg(&original), 0).unwrap();
            assert!(report.complete);
            assert!(report.fields.iter().any(|f| f.namespace == "exif.gps"
                && f.key == "latitude"
                && f.value == "27.991667"));
            assert!(report.fields.iter().any(|f| f.namespace == "exif.gps"
                && f.key == "longitude"
                && f.value == "85.316667"));

            let mut zero_denominator = original.clone();
            put32(&mut zero_denominator, 84, 0, le);
            assert!(metadata(&jpeg(&zero_denominator), 0).is_err());
            let mut invalid_pointer = original.clone();
            put32(&mut invalid_pointer, 18, 4096, le);
            assert!(metadata(&jpeg(&invalid_pointer), 0).is_err());
            assert!(metadata(&jpeg(&original), u64::MAX).is_err());
        }
    }
}

#[cfg(test)]
mod stream_digest_regression {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn matches_existing_operations_across_multiple_blocks_and_rejects_limit() {
        let input = (0..150_003).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        let digests = digest_stream(Cursor::new(&input), input.len() as u64).unwrap();
        assert_eq!(digests.bytes, input.len() as u64);
        for (name, actual) in [
            ("sha256", &digests.sha256),
            ("sha1", &digests.sha1),
            ("md5", &digests.md5),
            ("crc32", &digests.crc32),
        ] {
            assert_eq!(
                *actual,
                hex::encode(crate::apply_op(name, &input, None).unwrap())
            );
        }
        assert!(digest_stream(Cursor::new(&input), (input.len() - 1) as u64).is_err());
        let empty = digest_stream(Cursor::new(&[] as &[u8]), 0).unwrap();
        assert_eq!(empty.bytes, 0);
    }
}
