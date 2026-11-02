//! Bounded read-only TCP option dissection. Header bytes are immutable evidence.
//! Malformed/ambiguous option lengths never generate a positive fingerprint.
use crate::Layer;

pub(super) fn decode(options: &[u8]) -> Result<Vec<Layer>, &'static str> {
    if options.len() > 40 || options.len() % 4 != 0 {
        return Err("invalid TCP option area length");
    }
    let mut cursor = 0usize;
    let mut layers = Vec::new();
    let mut mss = false;
    let mut window = false;
    let mut sack = false;
    let mut timestamp = false;
    let mut seen_end = false;
    while cursor < options.len() {
        let kind = options[cursor];
        if seen_end {
            if kind != 0 {
                return Err("nonzero data after TCP End of Options");
            }
            cursor += 1;
            continue;
        }
        if kind == 0 {
            seen_end = true;
            cursor += 1;
            continue;
        }
        if kind == 1 {
            cursor += 1;
            continue;
        }
        if cursor + 2 > options.len() {
            return Err("TCP option truncated before length");
        }
        let len = options[cursor + 1] as usize;
        if len < 2
            || cursor
                .checked_add(len)
                .is_none_or(|end| end > options.len())
        {
            return Err("TCP option length exceeds header");
        }
        let data = &options[cursor + 2..cursor + len];
        let value = match kind {
            2 if len == 4 && !mss => {
                mss = true;
                let value = u16::from_be_bytes([data[0], data[1]]);
                if value == 0 {
                    return Err("TCP MSS must not be zero");
                }
                Some(("TCP maximum segment size", value.to_string()))
            }
            3 if len == 3 && !window => {
                window = true;
                if data[0] > 14 {
                    return Err("TCP window scale exceeds supported range");
                }
                Some(("TCP window scale", data[0].to_string()))
            }
            4 if len == 2 && !sack => {
                sack = true;
                Some(("TCP SACK permitted", "yes".to_owned()))
            }
            5 if len >= 10 && (len - 2) % 8 == 0 && len <= 34 => {
                let blocks = (len - 2) / 8;
                let mut summary = String::new();
                for (i, block) in data.chunks_exact(8).enumerate() {
                    let left = u32::from_be_bytes(
                        block[..4]
                            .try_into()
                            .map_err(|_| "TCP SACK block incomplete")?,
                    );
                    let right = u32::from_be_bytes(
                        block[4..8]
                            .try_into()
                            .map_err(|_| "TCP SACK block incomplete")?,
                    );
                    if left == right {
                        return Err("TCP SACK block has empty range");
                    }
                    if i != 0 {
                        summary.push_str(", ");
                    }
                    summary.push_str(&format!("0x{left:08x}..0x{right:08x}"));
                }
                Some((
                    "TCP selective ACK blocks",
                    format!("{blocks} block(s): {summary}"),
                ))
            }
            8 if len == 10 && !timestamp => {
                timestamp = true;
                let val = u32::from_be_bytes(
                    data[..4]
                        .try_into()
                        .map_err(|_| "TCP timestamp truncated")?,
                );
                let echoed = u32::from_be_bytes(
                    data[4..8]
                        .try_into()
                        .map_err(|_| "TCP timestamp truncated")?,
                );
                Some((
                    "TCP timestamps",
                    format!("TSval={val} TSecr={echoed} (peer supplied)"),
                ))
            }
            2 | 3 | 4 | 5 | 8 => {
                return Err("TCP known option has malformed or duplicate encoding")
            }
            _ => None,
        };
        if let Some((label, value)) = value {
            layers.push(Layer {
                label: label.to_owned(),
                value,
            });
        }
        cursor += len;
    }
    Ok(layers)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decoded_syn_options_expose_real_mss_window_sack_and_timestamps() {
        let bytes = [
            2, 4, 0x05, 0xb4, // MSS 1460
            1, 3, 3, 7, // NOP / WS=7
            4, 2, 1, 1, // SACK permitted, padding
            8, 10, 0, 0, 0, 5, 0, 0, 0, 3, // TSval=5, echo=3
            0, 0,
        ];
        let layers = decode(&bytes).unwrap();
        assert_eq!(layers.len(), 4);
        assert_eq!(layers[0].value, "1460");
        assert_eq!(layers[1].value, "7");
        assert_eq!(layers[2].value, "yes");
        assert!(layers[3].value.contains("TSval=5"));
    }
    #[test]
    fn sack_blocks_and_unknown_extensions_are_bounded() {
        let sack = [5, 10, 0, 0, 0, 9, 0, 0, 0, 23, 1, 1];
        assert_eq!(
            decode(&sack).unwrap()[0].value,
            "1 block(s): 0x00000009..0x00000017"
        );
        let unknown = [30, 4, 1, 2];
        assert!(decode(&unknown).unwrap().is_empty());
        assert!(decode(&[5, 10, 0, 0]).is_err());
        assert!(decode(&[5, 10, 0, 0, 0, 9, 0, 0, 0, 9, 1, 1]).is_err());
    }
    #[test]
    fn malformed_and_ambiguous_options_fail_closed_without_panics() {
        for value in [
            &[][..],
            &[0, 0, 0, 2][..],
            &[2, 3, 0, 0][..],
            &[2, 4, 0, 0][..],
            &[3, 3, 15, 1][..],
            &[4, 3, 0, 1][..],
            &[8, 2, 0, 1][..],
            &[2, 4, 5, 180, 2, 4, 5, 180][..],
            &[1, 1, 1, 2][..],
        ] {
            let result = decode(value);
            if value.is_empty() {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err(), "{value:?}");
            }
        }
        assert!(decode(&[1; 44]).is_err());
        assert!(decode(&[1, 1, 1]).is_err());
    }
}
