//! Provenance for research artifacts and experiment runs.
//!
//! `prov` records SHA-256 content manifests of directory trees (`rf.manifest/1`), verifies
//! them and foreign manifests, finds byte-identical files, records command runs with their
//! inputs and outputs (`rf.run/1`), reruns and compares them, and traces lineage. Problems
//! are reported as `rf.finding/1`. See the README for the schemas.

pub mod compare;
pub mod config;
pub mod dupes;
pub mod finding;
pub mod hash;
pub mod import;
pub mod lineage;
pub mod manifest;
pub mod run;
pub mod walk;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The current UTC time in RFC 3339.
pub fn now_rfc3339() -> String {
    jiff::Timestamp::now().to_string()
}

/// Parses a byte count: a plain integer, or one with a `K`, `M`, `G` or `T` suffix
/// (powers of 1000, optionally followed by `B`) or `KiB`, `MiB`, `GiB`, `TiB` (powers of 1024).
pub fn parse_size(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: u64 = num.parse().map_err(|_| format!("invalid size {s:?}"))?;
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "m" | "mb" => 1_000_000,
        "g" | "gb" => 1_000_000_000,
        "t" | "tb" => 1_000_000_000_000,
        "kib" => 1 << 10,
        "mib" => 1 << 20,
        "gib" => 1 << 30,
        "tib" => 1 << 40,
        _ => return Err(format!("invalid size unit in {s:?}")),
    };
    n.checked_mul(mult)
        .ok_or_else(|| format!("size {s:?} is too large"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn sizes() {
        assert_eq!(super::parse_size("1MB"), Ok(1_000_000));
        assert_eq!(super::parse_size("1MiB"), Ok(1 << 20));
        assert_eq!(super::parse_size("42"), Ok(42));
        assert!(super::parse_size("1XB").is_err());
    }
}
