//! Native text/phonetic recipe parity with the existing TypeScript transforms.
//! No secret persistence, external processes, or unbounded processing.

const LIMIT: usize = 8 * 1024 * 1024;
const LIMIT_ERROR: &str = "recipe output size limit exceeded";

pub(crate) fn supports(id: &str) -> bool {
    matches!(
        id,
        "vigenere" | "nato_encode" | "morse_encode" | "morse_decode"
    )
}

fn push(out: &mut Vec<u8>, piece: &[u8]) -> Result<(), String> {
    if out
        .len()
        .checked_add(piece.len())
        .is_none_or(|len| len > LIMIT)
    {
        return Err(LIMIT_ERROR.to_string());
    }
    out.extend_from_slice(piece);
    Ok(())
}

fn one(out: &mut Vec<u8>, ch: char) -> Result<(), String> {
    let mut buffer = [0_u8; 4];
    push(out, ch.encode_utf8(&mut buffer).as_bytes())
}

fn vigenere(input: &[u8], parameter: Option<&str>) -> Result<Vec<u8>, String> {
    let mut key: Vec<u8> = parameter
        .unwrap_or("")
        .bytes()
        .filter(|v| v.is_ascii_alphabetic())
        .map(|b| b.to_ascii_lowercase())
        .collect();
    if key.is_empty() {
        key = b"key".to_vec();
    }
    let mut index = 0usize;
    let mut out = Vec::new();
    for ch in String::from_utf8_lossy(input).chars() {
        if ch.is_ascii_alphabetic() {
            let base = if ch.is_ascii_uppercase() { b'A' } else { b'a' };
            let shift = key[index % key.len()] - b'a';
            let adjusted = ((ch as u8 - base + 26 - shift) % 26) + base;
            one(&mut out, adjusted as char)?;
            index += 1;
        } else {
            one(&mut out, ch)?;
        }
    }
    Ok(out)
}

const ALPHABET: [&str; 26] = [
    "Alfa", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India", "Juliett",
    "Kilo", "Lima", "Mike", "November", "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango",
    "Uniform", "Victor", "Whiskey", "X-ray", "Yankee", "Zulu",
];
const NUMBERS: [&str; 10] = [
    "Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine",
];

fn nato_encode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let source = String::from_utf8_lossy(input).to_lowercase();
    for (i, ch) in source.chars().enumerate() {
        if i > 0 {
            push(&mut out, b" ")?;
        }
        if ch.is_ascii_lowercase() {
            push(&mut out, ALPHABET[(ch as u8 - b'a') as usize].as_bytes())?;
        } else if ch.is_ascii_digit() {
            push(&mut out, NUMBERS[(ch as u8 - b'0') as usize].as_bytes())?;
        } else if ch == ' ' {
            push(&mut out, b"\n")?;
        } else {
            one(&mut out, ch)?;
        }
    }
    Ok(out)
}

const MORSE: [(&str, &str); 43] = [
    ("a", ".-"),
    ("b", "-..."),
    ("c", "-.-."),
    ("d", "-.."),
    ("e", "."),
    ("f", "..-."),
    ("g", "--."),
    ("h", "...."),
    ("i", ".."),
    ("j", ".---"),
    ("k", "-.-"),
    ("l", ".-.."),
    ("m", "--"),
    ("n", "-."),
    ("o", "---"),
    ("p", ".--."),
    ("q", "--.-"),
    ("r", ".-."),
    ("s", "..."),
    ("t", "-"),
    ("u", "..-"),
    ("v", "...-"),
    ("w", ".--"),
    ("x", "-..-"),
    ("y", "-.--"),
    ("z", "--.."),
    ("0", "-----"),
    ("1", ".----"),
    ("2", "..---"),
    ("3", "...--"),
    ("4", "....-"),
    ("5", "....."),
    ("6", "-...."),
    ("7", "--..."),
    ("8", "---.."),
    ("9", "----."),
    (".", ".-.-.-"),
    (",", "--..--"),
    ("?", "..--.."),
    ("!", "-.-.--"),
    ("/", "-..-."),
    ("@", ".--.-."),
    ("=", "-...-"),
];

fn morse_encode(input: &[u8]) -> Result<Vec<u8>, String> {
    let decoded = String::from_utf8_lossy(input).trim().to_lowercase();
    let mut out = Vec::new();
    for (i, word) in decoded.split_whitespace().enumerate() {
        if i > 0 {
            push(&mut out, b" / ")?;
        }
        for (j, ch) in word.chars().enumerate() {
            if j > 0 {
                push(&mut out, b" ")?;
            }
            let key = ch.to_string();
            let token = MORSE.iter().find(|(name, _)| *name == key);
            let value = token
                .map(|(_, symbol)| *symbol)
                .ok_or_else(|| format!("no Morse mapping for \"{ch}\""))?;
            push(&mut out, value.as_bytes())?;
        }
    }
    Ok(out)
}

fn morse_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = String::from_utf8_lossy(input);
    let mut out = Vec::new();
    for (i, word) in source.trim().split('/').enumerate() {
        if i > 0 {
            push(&mut out, b" ")?;
        }
        for token in word.split_whitespace() {
            let value = MORSE.iter().find(|(_, symbol)| *symbol == token);
            let plain = value
                .map(|(ch, _)| *ch)
                .ok_or_else(|| format!("unknown Morse token \"{token}\""))?;
            push(&mut out, plain.as_bytes())?;
        }
    }
    Ok(out)
}

pub(crate) fn apply(id: &str, input: &[u8], parameter: Option<&str>) -> Result<Vec<u8>, String> {
    match id {
        "vigenere" => vigenere(input, parameter),
        "nato_encode" => nato_encode(input),
        "morse_encode" => morse_encode(input),
        "morse_decode" => morse_decode(input),
        _ => Err("unknown text-parity recipe operation".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vigenere_decode_golden_and_key() {
        assert_eq!(
            vigenere(b"RIJVS UYVJN", Some("KEY")).unwrap(),
            b"HELLO WORLD"
        );
        assert_eq!(
            vigenere("A😀b".as_bytes(), Some("b")).unwrap(),
            "Z😀a".as_bytes()
        );
        assert_eq!(vigenere(b"RIJVS", Some("123")).unwrap(), b"HELLO");
    }
    #[test]
    fn nato_and_morse_golden() {
        assert_eq!(nato_encode(b"Ab 3").unwrap(), b"Alfa Bravo \n Three");
        assert_eq!(
            morse_encode(b"SOS 42!").unwrap(),
            b"... --- ... / ....- ..--- -.-.--"
        );
        assert_eq!(
            morse_decode(b"... --- ... / ....- ..--- -.-.--").unwrap(),
            b"sos 42!"
        );
        assert!(morse_encode("🙂".as_bytes()).is_err());
        assert!(morse_decode(b"... ...-...").is_err());
    }
    #[test]
    fn bounded_growth() {
        assert!(nato_encode(&vec![b'a'; 2_000_000]).is_err());
        assert!(morse_encode(&vec![b'0'; 2_000_000]).is_err());
    }
}
