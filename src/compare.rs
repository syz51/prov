//! Structural comparison of JSON, JSON Lines and CSV/TSV outputs with numeric tolerance.
//!
//! Two numbers `a` (baseline) and `b` (rerun) are equal when `|a - b| <= atol + rtol * |a|`;
//! integers are differenced exactly, an infinity equals only itself, and NaN equals NaN.
//! Strings, booleans and nulls compare exactly. CSV/TSV cells are text: they compare as
//! numbers only under a nonzero tolerance and only when both are written canonically (no
//! leading zeros or signs), so identifiers such as `00123` and `2.10` never match `123`
//! and `2.1`.

use std::path::Path;

use serde_json::{Number, Value};

/// How many differences are kept with their values; the total is always counted.
pub const KEEP: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tolerance {
    pub rtol: f64,
    pub atol: f64,
}

impl Tolerance {
    pub fn close(&self, a: f64, b: f64) -> bool {
        if a == b || (a.is_nan() && b.is_nan()) {
            return true;
        }
        if a.is_infinite() || b.is_infinite() {
            return false;
        }
        (a - b).abs() <= self.atol + self.rtol * a.abs()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Json,
    Jsonl,
    Delimited(u8),
}

impl Kind {
    pub fn for_path(path: &Path) -> Option<Kind> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "json" => Some(Kind::Json),
            "jsonl" | "ndjson" => Some(Kind::Jsonl),
            "csv" => Some(Kind::Delimited(b',')),
            "tsv" => Some(Kind::Delimited(b'\t')),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Json => "JSON",
            Kind::Jsonl => "JSON Lines",
            Kind::Delimited(b'\t') => "TSV",
            Kind::Delimited(_) => "CSV",
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Diff {
    /// JSON pointer, `line N` plus pointer, or `row R, column C`.
    pub location: String,
    pub baseline: String,
    pub rerun: String,
}

#[derive(Debug, Default)]
pub struct Diffs {
    pub kept: Vec<Diff>,
    pub total: usize,
}

impl Diffs {
    fn push(&mut self, location: String, baseline: String, rerun: String) {
        self.total += 1;
        if self.kept.len() < KEEP {
            self.kept.push(Diff {
                location,
                baseline,
                rerun,
            });
        }
    }
}

/// Compares two files of `kind`. `Err` names which side failed to parse.
pub fn compare(kind: Kind, baseline: &[u8], rerun: &[u8], tol: Tolerance) -> Result<Diffs, String> {
    let mut diffs = Diffs::default();
    match kind {
        Kind::Json => {
            let a: Value = serde_json::from_slice(baseline)
                .map_err(|e| format!("baseline is not valid JSON: {e}"))?;
            let b: Value = serde_json::from_slice(rerun)
                .map_err(|e| format!("rerun output is not valid JSON: {e}"))?;
            json_values(&a, &b, &mut String::new(), tol, &mut diffs);
        }
        Kind::Jsonl => {
            let a = jsonl(baseline).map_err(|e| format!("baseline: {e}"))?;
            let b = jsonl(rerun).map_err(|e| format!("rerun output: {e}"))?;
            if a.len() != b.len() {
                diffs.push(
                    "line count".into(),
                    a.len().to_string(),
                    b.len().to_string(),
                );
            }
            for (i, (x, y)) in a.iter().zip(&b).enumerate() {
                let mut ptr = format!("line {}:", i + 1);
                json_values(x, y, &mut ptr, tol, &mut diffs);
            }
        }
        Kind::Delimited(delim) => {
            let a = table(baseline, delim).map_err(|e| format!("baseline: {e}"))?;
            let b = table(rerun, delim).map_err(|e| format!("rerun output: {e}"))?;
            let header: Option<&Vec<String>> = a.first();
            if a.len() != b.len() {
                diffs.push("row count".into(), a.len().to_string(), b.len().to_string());
            }
            for (r, (ra, rb)) in a.iter().zip(&b).enumerate() {
                if ra.len() != rb.len() {
                    diffs.push(
                        format!("row {}, field count", r + 1),
                        ra.len().to_string(),
                        rb.len().to_string(),
                    );
                }
                for (c, (x, y)) in ra.iter().zip(rb).enumerate() {
                    if x == y || cells_close(x, y, tol) {
                        continue;
                    }
                    let name = header
                        .and_then(|h| h.get(c))
                        .filter(|_| r > 0)
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default();
                    diffs.push(
                        format!("row {}, column {}{name}", r + 1, c + 1),
                        x.clone(),
                        y.clone(),
                    );
                }
            }
        }
    }
    Ok(diffs)
}

fn jsonl(data: &[u8]) -> Result<Vec<Value>, String> {
    let text = std::str::from_utf8(data).map_err(|e| format!("not UTF-8: {e}"))?;
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| {
            serde_json::from_str(l).map_err(|e| format!("line {} is not valid JSON: {e}", i + 1))
        })
        .collect()
}

fn table(data: &[u8], delim: u8) -> Result<Vec<Vec<String>>, String> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .delimiter(delim)
        .from_reader(data);
    rdr.records()
        .map(|r| {
            r.map(|rec| rec.iter().map(str::to_owned).collect())
                .map_err(|e| format!("not valid CSV: {e}"))
        })
        .collect()
}

/// A number written canonically: an optional `-`, an integer part without leading zeros, an
/// optional fraction and an optional exponent. Returns whether it is an integer.
fn canonical_number(s: &str) -> Option<bool> {
    let b = s.strip_prefix('-').unwrap_or(s).as_bytes();
    let int_len = b.iter().take_while(|c| c.is_ascii_digit()).count();
    if int_len == 0 || (int_len > 1 && b[0] == b'0') {
        return None;
    }
    let mut rest = &b[int_len..];
    let mut integer = true;
    if let Some(frac) = rest.strip_prefix(b".") {
        let n = frac.iter().take_while(|c| c.is_ascii_digit()).count();
        if n == 0 {
            return None;
        }
        rest = &frac[n..];
        integer = false;
    }
    if let Some(exp) = rest.strip_prefix(b"e").or_else(|| rest.strip_prefix(b"E")) {
        let exp = exp
            .strip_prefix(b"+")
            .or_else(|| exp.strip_prefix(b"-"))
            .unwrap_or(exp);
        if exp.is_empty() || !exp.iter().all(u8::is_ascii_digit) {
            return None;
        }
        rest = &[];
        integer = false;
    }
    rest.is_empty().then_some(integer)
}

/// Whether two differing CSV cells are numbers within tolerance.
fn cells_close(a: &str, b: &str, tol: Tolerance) -> bool {
    if tol.rtol == 0.0 && tol.atol == 0.0 {
        return false;
    }
    let (a, b) = (a.trim(), b.trim());
    match (canonical_number(a), canonical_number(b)) {
        (Some(true), Some(true)) => match (a.parse::<i128>(), b.parse::<i128>()) {
            (Ok(x), Ok(y)) => ints_close(x, y, tol),
            _ => false,
        },
        (Some(_), Some(_)) => match (a.parse::<f64>(), b.parse::<f64>()) {
            (Ok(x), Ok(y)) => tol.close(x, y),
            _ => false,
        },
        _ => false,
    }
}

fn ints_close(x: i128, y: i128, tol: Tolerance) -> bool {
    x == y || (x.abs_diff(y) as f64) <= tol.atol + tol.rtol * (x as f64).abs()
}

fn numbers_close(a: &Number, b: &Number, tol: Tolerance) -> bool {
    // Integers are differenced exactly, so values beyond 2^53 do not collapse through f64.
    let int = |n: &Number| {
        n.as_i64()
            .map(i128::from)
            .or_else(|| n.as_u64().map(i128::from))
    };
    if let (Some(x), Some(y)) = (int(a), int(b)) {
        return ints_close(x, y, tol);
    }
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => tol.close(x, y),
        _ => false,
    }
}

fn brief(v: &Value) -> String {
    let s = v.to_string();
    if s.chars().count() > 120 {
        let mut t: String = s.chars().take(117).collect();
        t.push_str("...");
        t
    } else {
        s
    }
}

fn json_values(a: &Value, b: &Value, ptr: &mut String, tol: Tolerance, diffs: &mut Diffs) {
    let loc = |p: &str| {
        if p.is_empty() {
            "/".to_owned()
        } else {
            p.to_owned()
        }
    };
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            if !numbers_close(x, y, tol) {
                diffs.push(loc(ptr), x.to_string(), y.to_string());
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            if x.len() != y.len() {
                diffs.push(
                    format!("{} (length)", loc(ptr)),
                    x.len().to_string(),
                    y.len().to_string(),
                );
            }
            for (i, (u, v)) in x.iter().zip(y).enumerate() {
                let len = ptr.len();
                ptr.push_str(&format!("/{i}"));
                json_values(u, v, ptr, tol, diffs);
                ptr.truncate(len);
            }
        }
        (Value::Object(x), Value::Object(y)) => {
            for (k, u) in x {
                let len = ptr.len();
                ptr.push('/');
                ptr.push_str(&k.replace('~', "~0").replace('/', "~1"));
                match y.get(k) {
                    Some(v) => json_values(u, v, ptr, tol, diffs),
                    None => diffs.push(loc(ptr), brief(u), "(absent)".into()),
                }
                ptr.truncate(len);
            }
            for (k, v) in y {
                if !x.contains_key(k) {
                    let p = format!("{ptr}/{}", k.replace('~', "~0").replace('/', "~1"));
                    diffs.push(p, "(absent)".into(), brief(v));
                }
            }
        }
        _ => {
            if a != b {
                diffs.push(loc(ptr), brief(a), brief(b));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXACT: Tolerance = Tolerance {
        rtol: 0.0,
        atol: 0.0,
    };

    #[test]
    fn json_with_tolerance() {
        let a = br#"{"loss": 0.5000, "acc": [0.9, 0.8], "name": "x", "n": 3}"#;
        let b = br#"{"loss": 0.5001, "acc": [0.9, 0.8], "name": "x", "n": 3}"#;
        let d = compare(Kind::Json, a, b, EXACT).unwrap();
        assert_eq!(d.total, 1);
        assert_eq!(d.kept[0].location, "/loss");
        let d = compare(
            Kind::Json,
            a,
            b,
            Tolerance {
                rtol: 1e-3,
                atol: 0.0,
            },
        )
        .unwrap();
        assert_eq!(d.total, 0);
        let d = compare(
            Kind::Json,
            a,
            b,
            Tolerance {
                rtol: 0.0,
                atol: 1e-5,
            },
        )
        .unwrap();
        assert_eq!(d.total, 1);
    }

    #[test]
    fn json_structure_differences() {
        let a = br#"{"a": [1, 2, 3], "b": "x", "gone": 1}"#;
        let b = br#"{"a": [1, 2], "b": "y", "new": 2}"#;
        let d = compare(Kind::Json, a, b, EXACT).unwrap();
        let locs: Vec<_> = d.kept.iter().map(|x| x.location.as_str()).collect();
        assert_eq!(locs, ["/a (length)", "/b", "/gone", "/new"]);
    }

    #[test]
    fn integers_compare_exactly() {
        let a = br#"[9007199254740993]"#;
        let b = br#"[9007199254740992]"#;
        let d = compare(Kind::Json, a, b, EXACT).unwrap();
        assert_eq!(
            d.total, 1,
            "integers beyond 2^53 must not collapse through f64"
        );
        assert_eq!(compare(Kind::Json, b"1.0", b"1", EXACT).unwrap().total, 0);
    }

    #[test]
    fn csv_cells() {
        let a = b"step,loss,tag\n1,0.25,a\n2,0.125,b\n";
        let b = b"step,loss,tag\n1,0.2501,a\n2,0.125,c\n";
        let d = compare(
            Kind::Delimited(b','),
            a,
            b,
            Tolerance {
                rtol: 1e-3,
                atol: 0.0,
            },
        )
        .unwrap();
        assert_eq!(d.total, 1);
        assert_eq!(d.kept[0].location, "row 3, column 3 (tag)");
        let d = compare(
            Kind::Delimited(b','),
            a,
            b"step,loss,tag\n1,0.25,a\n",
            EXACT,
        )
        .unwrap();
        assert_eq!(d.kept[0].location, "row count");
    }

    #[test]
    fn csv_cells_are_text_at_zero_tolerance() {
        let a = b"id,v,big\n00123,2.10,1700000000000000001\n";
        let b = b"id,v,big\n123,2.1,1700000000000000002\n";
        let d = compare(Kind::Delimited(b','), a, b, EXACT).unwrap();
        assert_eq!(d.total, 3);
        let loose = Tolerance {
            rtol: 1e-6,
            atol: 0.0,
        };
        let d = compare(Kind::Delimited(b','), a, b, loose).unwrap();
        let locs: Vec<_> = d.kept.iter().map(|x| x.location.as_str()).collect();
        // `00123` is not a canonical number, so it stays text; 2.10 and 2.1 are close;
        // big integers are differenced exactly: |1| <= 1e-6 * 1.7e18.
        assert_eq!(locs, ["row 2, column 1 (id)"]);
        let tight = Tolerance {
            rtol: 0.0,
            atol: 0.5,
        };
        let d = compare(Kind::Delimited(b','), a, b, tight).unwrap();
        assert_eq!(d.total, 2, "a difference of 1 exceeds atol 0.5");
    }

    #[test]
    fn infinity_equals_only_itself() {
        let loose = Tolerance {
            rtol: 0.5,
            atol: 0.0,
        };
        assert!(!loose.close(f64::INFINITY, 1.0));
        assert!(!loose.close(1.0, f64::INFINITY));
        assert!(!loose.close(f64::INFINITY, f64::NEG_INFINITY));
        assert!(loose.close(f64::INFINITY, f64::INFINITY));
        let d = compare(Kind::Delimited(b','), b"x\ninf\n", b"x\n1e308\n", loose).unwrap();
        assert_eq!(d.total, 1);
    }

    #[test]
    fn canonical_numbers() {
        for s in ["0", "-1", "12", "0.5", "1e5", "-2.5E-3"] {
            assert!(canonical_number(s).is_some(), "{s}");
        }
        for s in [
            "00123", "+1", "1.", ".5", "1e", "1.2.3", "inf", "nan", "0x10", "",
        ] {
            assert!(canonical_number(s).is_none(), "{s}");
        }
    }

    #[test]
    fn parse_failure_is_reported() {
        assert!(
            compare(Kind::Json, b"{", b"{}", EXACT)
                .unwrap_err()
                .contains("baseline")
        );
    }
}
