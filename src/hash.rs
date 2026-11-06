//! Streaming SHA-256 of files and byte streams.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

const BUF_SIZE: usize = 256 * 1024;

/// Lower-case hexadecimal encoding.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

pub fn sha256_bytes(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Hashes a reader to its end, returning the number of bytes read and the digest.
pub fn hash_reader(mut reader: impl Read) -> io::Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; BUF_SIZE];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((total, hex(&hasher.finalize())))
}

/// Hashes a file's content. The byte count is what was actually read, not the size `stat` reported.
pub fn hash_file(path: &Path) -> io::Result<(u64, String)> {
    hash_reader(File::open(path)?)
}

/// Normalises a SHA-256 written by another tool: optional `sha256:` prefix, any case.
pub fn normalize_sha256(value: &str) -> Option<String> {
    let v = value.trim();
    let v = v
        .strip_prefix("sha256:")
        .or_else(|| v.strip_prefix("SHA256:"))
        .unwrap_or(v);
    (v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())).then(|| v.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digest() {
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let (n, h) = hash_reader(&b"abc"[..]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(h, sha256_bytes(b"abc"));
    }

    #[test]
    fn normalizes_foreign_hashes() {
        let h = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        assert_eq!(
            normalize_sha256(&format!("sha256:{h}")).as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(normalize_sha256("abc"), None);
    }
}
