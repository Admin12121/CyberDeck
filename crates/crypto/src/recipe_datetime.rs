//! Offline text normalization and ISO/Unix timestamp transformations.
//! Bounded input/output. UTC deterministic parsing is deliberate: ambiguous
//! locale-dependent date formats remain in the TypeScript reference engine.
const MAX: usize = 8 * 1024 * 1024;

fn text(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

pub(crate) fn supports(op: &str) -> bool {
    matches!(op, "normalize_unicode" | "unix_to_datetime" | "datetime_to_unix")
}

pub(crate) fn apply(op: &str, input: &[u8], param: Option<&str>) -> Result<Vec<u8>, String> {
    if input.len() > MAX {
        return Err("recipe input size limit exceeded".into());
    }
    let value = text(input);
    match op {
        "normalize_unicode" => {
            // Stream normalized scalars instead of materializing potentially
            // large compatibility expansions before enforcing the output cap.
            let mut result = String::with_capacity(value.len().min(MAX));
            for scalar in icu_normalizer::ComposingNormalizer::new_nfkc()
                .normalize_iter(value.chars())
            {
                if result
                    .len()
                    .checked_add(scalar.len_utf8())
                    .is_none_or(|length| length > MAX)
                {
                    return Err("recipe output size limit exceeded".into());
                }
                result.push(scalar);
            }
            Ok(result.into_bytes())
        }
        "unix_to_datetime" => unix_to_datetime(value.trim()),
        "datetime_to_unix" => datetime_to_unix(value.trim(), param),
        _ => Err("unknown date/normalization operation".into()),
    }
}


/// Gregorian civil date of Unix-day index, valid through both JS TimeClip
/// extrema (proleptic Gregorian, astronomical year numbering).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z / 146_097 } else { (z - 146_096) / 146_097 };
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

fn unix_to_datetime(raw: &str) -> Result<Vec<u8>, String> {
    // Existing JS implementation distinguishes seconds and milliseconds by
    // RAW text length, including sign and leading zeros.
    if raw.is_empty()
        || !raw
            .strip_prefix('-')
            .unwrap_or(raw)
            .bytes()
            .all(|b| b.is_ascii_digit())
        || raw == "-"
    {
        return Err("input must be an integer Unix timestamp".into());
    }
    let value = raw
        .parse::<i128>()
        .map_err(|_| "timestamp out of range")?;
    let milliseconds = if raw.len() >= 13 {
        value
    } else {
        value.checked_mul(1000).ok_or("timestamp out of range")?
    };
    // JS Date TimeClip interval. Keep bounds before any large conversion.
    if !(-8_640_000_000_000_000..=8_640_000_000_000_000).contains(&milliseconds) {
        return Err("timestamp out of range".into());
    }
    // ECMAScript's TimeClip allows +/-100 million days. `time`'s
    // ordinary calendar supports a narrower year interval, so calculate the
    // entire JS interval without narrowing through a timestamp/date library.
    const DAY_MS: i128 = 86_400_000;
    let days = i64::try_from(milliseconds.div_euclid(DAY_MS))
        .map_err(|_| "timestamp out of range")?;
    let within_day = milliseconds.rem_euclid(DAY_MS);
    let (year, month, day) = civil_from_days(days);
    let display_year = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else if year < 0 {
        format!("-{:06}", -year)
    } else {
        format!("+{year:06}")
    };
    let display = format!(
        "{display_year}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z ({} input)",
        within_day / 3_600_000,
        (within_day / 60_000) % 60,
        (within_day / 1000) % 60,
        within_day % 1000,
        if raw.len() >= 13 { "ms" } else { "s" },
    );
    Ok(display.into_bytes())
}

fn datetime_to_unix(raw: &str, param: Option<&str>) -> Result<Vec<u8>, String> {
    use time::{format_description::well_known::Rfc3339, Date, PrimitiveDateTime, Time};
    if raw.is_empty() {
        return Err("unrecognized date; use ISO 8601 like 2026-10-31T12:00:00Z".into());
    }
    // Date-only ISO-8601 dates are UTC per ECMAScript Date.parse.
    let date = if raw.len() == 10 && raw.as_bytes().get(4) == Some(&b'-') && raw.as_bytes().get(7) == Some(&b'-') {
        let mut chunks = raw.split('-');
        let year = chunks.next().and_then(|s| s.parse::<i32>().ok());
        let month = chunks.next().and_then(|s| s.parse::<u8>().ok());
        let day = chunks.next().and_then(|s| s.parse::<u8>().ok());
        // Date.parse normalizes 29..31 across short months for date-only
        // strings, but does not accept days 0 or 32.
        let checked = year.zip(month).zip(day).and_then(|((y, m), d)| {
            if !(1..=31).contains(&d) { return None; }
            let month = time::Month::try_from(m).ok()?;
            Date::from_calendar_date(y, month, 1)
                .ok()?
                .checked_add(time::Duration::days(i64::from(d - 1)))
        });
        checked
            .map(|d| PrimitiveDateTime::new(d, Time::MIDNIGHT).assume_utc())
            .ok_or("unrecognized date; use ISO 8601 like 2026-10-31T12:00:00Z")?
    } else {
        time::OffsetDateTime::parse(raw, &Rfc3339)
            .map_err(|_| "unrecognized date; use ISO 8601 like 2026-10-31T12:00:00Z")?
    };
    // Date.parse serializes to integer milliseconds, discarding sub-ms data.
    let millis = date.unix_timestamp_nanos().div_euclid(1_000_000);
    if !(-8_640_000_000_000_000..=8_640_000_000_000_000).contains(&millis) {
        return Err("timestamp out of range".into());
    }
    let output = if param == Some("ms") {
        millis
    } else {
        millis.div_euclid(1000)
    };
    Ok(output.to_string().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    #[test]
    fn normalization_reference_and_bounded_utf8() {
        for (source, expected) in [
            ("ＡＢＣ１２３", "ABC123"),
            ("① ﬁ ㍑", "1 fi リットル"),
            ("e\u{301}", "é"),
            ("𝔄", "A"),
        ] {
            assert_eq!(apply("normalize_unicode", source.as_bytes(), None).unwrap(), expected.as_bytes());
        }
        assert!(apply("normalize_unicode", &vec![b'A'; MAX + 1], None).is_err());
        let result = crate::recipes::execute_recipe("ＡＢＣ", &[crate::recipes::RecipeStep {
            op_id: "normalize_unicode".into(), enabled: true, param: None,
        }]);
        assert!(result.error.is_none(), "{:?}", result.error);
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(result.output_b64).unwrap(), b"ABC");
    }
    #[test]
    fn unix_timestamp_matches_js_seconds_milliseconds_and_negative() {
        for (raw, expected) in [
            ("0", "1970-01-01T00:00:00.000Z (s input)"),
            ("-1", "1969-12-31T23:59:59.000Z (s input)"),
            ("1700000000", "2023-11-14T22:13:20.000Z (s input)"),
            ("1700000000123", "2023-11-14T22:13:20.123Z (ms input)"),
            ("0000000000000", "1970-01-01T00:00:00.000Z (ms input)"),
            ("8640000000000000", "+275760-09-13T00:00:00.000Z (ms input)"),
            ("-8640000000000000", "-271821-04-20T00:00:00.000Z (ms input)"),
        ] {
            assert_eq!(unix_to_datetime(raw).unwrap(), expected.as_bytes(), "{raw}");
        }
        for bad in ["", "-","1.5", " 5", "++1", "8640000000000001"] {
            assert!(unix_to_datetime(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn parsed_iso_date_timestamps_are_offset_and_millisecond_aware() {
        for (raw, param, expected) in [
            ("1970-01-01", None, "0"),
            ("2026-02-31", None, "1772496000"),
            ("1969-12-31T23:59:59.900Z", None, "-1"),
            ("1969-12-31T23:59:59.900Z", Some("ms"), "-100"),
            ("2026-11-02T12:00:00+05:45", None, "1793600100"),
            ("2026-11-02T12:00:00.123+05:45", Some("ms"), "1793600100123"),
            ("2026-11-02T06:15:00Z", None, "1793600100"),
        ] {
            assert_eq!(datetime_to_unix(raw, param).unwrap(), expected.as_bytes(), "{raw}");
        }
        for bad in ["", "not a date", "2026-02-32", "2026-11-02T12:00:00", "2026-13-01"] {
            assert!(datetime_to_unix(bad, None).is_err(), "{bad}");
        }
    }
}
