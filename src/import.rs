//! Reading foreign JSON manifests as `rf.manifest/1`.
//!
//! A record is any JSON object holding a path field and a SHA-256 field. Without explicit
//! fields, fields are paired by name within each object: a generic hash field (`sha256`,
//! `hash`, …) pairs with a generic path field (`path`, `file`, …), and `<p>_sha256` pairs
//! with `<p>_path`, `<p>_file` or `<p>_artifact`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::finding::{Finding, Report, Severity};
use crate::hash::{normalize_sha256, sha256_bytes};
use crate::manifest::{Expect, Header, Manifest, Record};

pub const PATH_KEYS: &[&str] = &[
    "path",
    "file",
    "local_path",
    "file_path",
    "filepath",
    "relative_path",
    "project_path",
    "retained_file",
    "artifact",
];
pub const HASH_KEYS: &[&str] = &[
    "sha256",
    "sha_256",
    "sha256sum",
    "hash",
    "checksum",
    "digest",
];
const BYTES_KEYS: &[&str] = &["bytes", "size", "size_bytes", "length"];

pub struct ImportOptions {
    pub json: PathBuf,
    /// JSON pointers to records or arrays of records, `*` matching every member; empty means
    /// every object in the document.
    pub records: Vec<String>,
    pub path_field: Option<String>,
    pub hash_field: Option<String>,
    pub bytes_field: Option<String>,
    pub root: Option<PathBuf>,
    /// Choose the root among the JSON file's directory and its ancestors by how many paths exist.
    pub find_root: bool,
}

/// A field name, or a JSON pointer into the record when it starts with `/`.
fn field<'a>(obj: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    match name.strip_prefix('/') {
        Some(_) => {
            let mut v = None;
            for (i, part) in name.split('/').skip(1).enumerate() {
                let part = part.replace("~1", "/").replace("~0", "~");
                v = if i == 0 {
                    obj.get(&part)
                } else {
                    v.and_then(|x: &Value| x.get(&part))
                };
            }
            v
        }
        None => obj.get(name),
    }
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Pair {
    path: String,
    hash: String,
    bytes: Option<String>,
}

/// Field pairs in one object, and hash fields with no path partner.
fn pairs(obj: &Map<String, Value>, opts: &ImportOptions) -> (Vec<Pair>, Vec<String>) {
    let present = |k: &str| field(obj, k).is_some_and(|v| v.is_string() || v.is_null());
    let first = |c: &[String]| c.iter().find(|k| present(k)).cloned();
    let bytes_for = |c: &[String]| c.iter().find(|k| field(obj, k).is_some()).cloned();
    if opts.path_field.is_some() || opts.hash_field.is_some() {
        let own = |o: &Option<String>, d: &[&str]| match o {
            Some(f) => vec![f.clone()],
            None => d.iter().map(|s| (*s).to_owned()).collect(),
        };
        let (Some(path), Some(hash)) = (
            first(&own(&opts.path_field, PATH_KEYS)),
            first(&own(&opts.hash_field, HASH_KEYS)),
        ) else {
            return (Vec::new(), Vec::new());
        };
        let bytes = bytes_for(&own(&opts.bytes_field, BYTES_KEYS));
        return (vec![Pair { path, hash, bytes }], Vec::new());
    }
    let mut hash_keys: Vec<&str> = HASH_KEYS
        .iter()
        .copied()
        .filter(|k| obj.contains_key(*k))
        .collect();
    hash_keys.extend(
        obj.keys()
            .map(String::as_str)
            .filter(|k| k.ends_with("_sha256") && *k != "sha_256"),
    );
    let mut out: Vec<Pair> = Vec::new();
    let mut orphans = Vec::new();
    for h in hash_keys {
        let generic = HASH_KEYS.contains(&h);
        let (paths, sizes): (Vec<String>, Vec<String>) = if generic {
            (
                PATH_KEYS.iter().map(|s| (*s).to_owned()).collect(),
                BYTES_KEYS.iter().map(|s| (*s).to_owned()).collect(),
            )
        } else {
            let p = &h[..h.len() - "sha256".len()];
            (
                ["path", "file", "artifact"]
                    .iter()
                    .map(|s| format!("{p}{s}"))
                    .collect(),
                ["bytes", "size"]
                    .iter()
                    .map(|s| format!("{p}{s}"))
                    .collect(),
            )
        };
        // A generic field that does not hold a SHA-256 (e.g. a SHA-1 `hash`) is not ours.
        if generic
            && !h.contains("sha")
            && !obj[h]
                .as_str()
                .is_some_and(|s| normalize_sha256(s).is_some())
        {
            continue;
        }
        match first(&paths) {
            Some(path) if !out.iter().any(|x| x.path == path) => out.push(Pair {
                path,
                hash: h.to_owned(),
                bytes: bytes_for(&sizes),
            }),
            Some(_) => {}
            None if !obj[h].is_null() => orphans.push(h.to_owned()),
            None => {}
        }
    }
    (out, orphans)
}

/// Resolves a JSON pointer in which `*` matches every element or member.
fn resolve<'a>(v: &'a Value, pointer: &str) -> Vec<(String, &'a Value)> {
    let mut cur = vec![(String::new(), v)];
    for part in pointer.split('/').skip(1) {
        let part = part.replace("~1", "/").replace("~0", "~");
        let mut next = Vec::new();
        for (p, v) in cur {
            match (part.as_str(), v) {
                ("*", Value::Array(a)) => {
                    next.extend(a.iter().enumerate().map(|(i, x)| (format!("{p}/{i}"), x)))
                }
                ("*", Value::Object(o)) => {
                    next.extend(o.iter().map(|(k, x)| (format!("{p}/{}", escape(k)), x)))
                }
                (k, Value::Object(o)) => {
                    next.extend(o.get(k).map(|x| (format!("{p}/{}", escape(k)), x)))
                }
                (k, Value::Array(a)) => next.extend(
                    k.parse::<usize>()
                        .ok()
                        .and_then(|i| a.get(i))
                        .map(|x| (format!("{p}/{k}"), x)),
                ),
                _ => {}
            }
        }
        cur = next;
    }
    cur
}

fn all_objects<'a>(v: &'a Value, ptr: String, out: &mut Vec<(String, &'a Map<String, Value>)>) {
    match v {
        Value::Object(o) => {
            out.push((ptr.clone(), o));
            for (k, x) in o {
                all_objects(x, format!("{ptr}/{}", escape(k)), out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                all_objects(x, format!("{ptr}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// The pointer with array indices replaced by `*`, for grouping.
fn shape(ptr: &str) -> String {
    let s: Vec<&str> = ptr
        .split('/')
        .map(|p| {
            if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
                "*"
            } else {
                p
            }
        })
        .collect();
    if ptr.is_empty() {
        "/".to_owned()
    } else {
        s.join("/")
    }
}

fn parse_document(text: &str, label: &str) -> Result<Value> {
    match serde_json::from_str::<Value>(text) {
        Ok(v) => Ok(v),
        Err(json_err) => {
            // Fall back to JSON Lines: one value per non-empty line.
            let mut items = Vec::new();
            for (i, line) in text.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(line) {
                    Ok(v) => items.push(v),
                    Err(_) => {
                        return Err(json_err).with_context(|| {
                            format!(
                                "{label}: not valid JSON (and line {} is not valid JSON Lines)",
                                i + 1
                            )
                        });
                    }
                }
            }
            Ok(Value::Array(items))
        }
    }
}

#[derive(Default)]
struct Group {
    records: usize,
    without_path: Vec<String>,
}

pub fn import(opts: &ImportOptions) -> Result<(Manifest, Report)> {
    let label = opts.json.display().to_string();
    let bytes = std::fs::read(&opts.json).with_context(|| format!("cannot read {label}"))?;
    let text = std::str::from_utf8(&bytes).with_context(|| format!("{label}: not UTF-8"))?;
    let doc = parse_document(text, &label)?;

    let mut objects: Vec<(String, &Map<String, Value>)> = Vec::new();
    if opts.records.is_empty() {
        all_objects(&doc, String::new(), &mut objects);
    } else {
        for p in &opts.records {
            let found = resolve(&doc, p);
            if found.is_empty() {
                bail!("{label}: JSON pointer {p:?} matches nothing");
            }
            for (ptr, v) in found {
                match v {
                    Value::Object(o) => objects.push((ptr, o)),
                    Value::Array(a) => objects.extend(
                        a.iter()
                            .enumerate()
                            .filter_map(|(i, x)| x.as_object().map(|o| (format!("{ptr}/{i}"), o))),
                    ),
                    _ => bail!("{label}: {ptr:?} is neither an object nor an array"),
                }
            }
        }
    }

    let mut report = Report::default();
    let mut records: Vec<Record> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut groups: BTreeMap<(String, String, String), Group> = BTreeMap::new();
    let mut orphans: BTreeMap<String, usize> = BTreeMap::new();
    for (ptr, obj) in &objects {
        let (found, lone) = pairs(obj, opts);
        for h in lone {
            *orphans
                .entry(format!("{}/{}", shape(ptr), escape(&h)))
                .or_default() += 1;
        }
        for pair in found {
            let origin = format!("{ptr} ({}, {})", pair.path, pair.hash);
            let g = groups
                .entry((shape(ptr), pair.path.clone(), pair.hash.clone()))
                .or_default();
            let Some(path) = field(obj, &pair.path).and_then(Value::as_str) else {
                g.without_path.push(ptr.clone());
                continue;
            };
            g.records += 1;
            let path = path.strip_prefix("./").unwrap_or(path).to_owned();
            let sha256 = match field(obj, &pair.hash) {
                None | Some(Value::Null) => None,
                Some(v) => match v.as_str().and_then(normalize_sha256) {
                    Some(h) => Some(h),
                    None => {
                        report.push(
                            Finding::new(
                                "invalid-hash",
                                Severity::Error,
                                &path,
                                format!("{} value {v} is not a SHA-256 (64 hex digits); content not checked", pair.hash),
                            )
                            .with_evidence(&label, &origin),
                        );
                        None
                    }
                },
            };
            let size = match pair.bytes.as_deref().and_then(|b| field(obj, b)) {
                None | Some(Value::Null) => None,
                Some(v) => {
                    match v.as_u64() {
                        Some(n) => Some(n),
                        None => {
                            report.push(
                            Finding::new(
                                "invalid-bytes",
                                Severity::Warn,
                                &path,
                                format!("byte count {v} is not a non-negative integer; size not checked"),
                            )
                            .with_evidence(&label, &origin),
                        );
                            None
                        }
                    }
                }
            };
            if let Some(&j) = index.get(&path) {
                let prev = &mut records[j];
                let Expect::File {
                    bytes: pb,
                    sha256: ph,
                } = &mut prev.expect
                else {
                    unreachable!("imported records are files")
                };
                let hash_conflict = matches!((&*ph, &sha256), (Some(a), Some(b)) if a != b);
                let size_conflict = matches!((&*pb, &size), (Some(a), Some(b)) if a != b);
                if hash_conflict || size_conflict {
                    report.push(
                        Finding::new(
                            "manifest-conflict",
                            Severity::Error,
                            &path,
                            format!(
                                "listed again with different content; the first entry ({}) is verified",
                                prev.origin.as_deref().unwrap_or("?")
                            ),
                        )
                        .with_evidence(&label, &origin)
                        .with_data(json!({
                            "first": {"origin": prev.origin, "bytes": *pb, "sha256": *ph},
                            "other": {"origin": origin, "bytes": size, "sha256": sha256},
                        })),
                    );
                } else {
                    if ph.is_none() {
                        *ph = sha256;
                    }
                    if pb.is_none() {
                        *pb = size;
                    }
                }
                continue;
            }
            index.insert(path.clone(), records.len());
            records.push(Record {
                path,
                expect: Expect::File {
                    bytes: size,
                    sha256,
                },
                mtime: None,
                origin: Some(origin),
            });
        }
    }
    if groups.is_empty() {
        bail!(
            "{label}: no object pairs a path field ({}) with a SHA-256 field ({}, or <p>_sha256 with <p>_path); pass --records, --path-field and --hash-field",
            PATH_KEYS.join(", "),
            HASH_KEYS.join(", ")
        );
    }

    let mut sources = Vec::new();
    for ((ptr, pf, hf), g) in &groups {
        let m = json!({"records": ptr, "path_field": pf, "hash_field": hf, "with_path": g.records, "without_path": g.without_path.len()});
        report.push(
            Finding::new(
                "import-mapping",
                Severity::Info,
                &label,
                format!("{ptr}: path={pf}, sha256={hf}: {} records", g.records),
            )
            .with_data(m.clone()),
        );
        if !g.without_path.is_empty() {
            report.push(
                Finding::new(
                    "record-without-path",
                    Severity::Info,
                    &label,
                    format!(
                        "{} objects at {ptr} have a {hf:?} field but no string {pf:?}; they name no file and were not checked",
                        g.without_path.len()
                    ),
                )
                .with_evidence(&label, g.without_path.iter().take(5).cloned().collect::<Vec<_>>().join(", "))
                .with_data(json!({"pointers": g.without_path})),
            );
        }
        sources.push(m);
    }
    if !orphans.is_empty() {
        let total: usize = orphans.values().sum();
        report.push(
            Finding::new(
                "hash-without-path",
                Severity::Info,
                &label,
                format!(
                    "{total} SHA-256 values have no path field to pair with ({}); not checked",
                    orphans.keys().cloned().collect::<Vec<_>>().join(", ")
                ),
            )
            .with_data(json!(orphans)),
        );
    }

    let json_dir = opts
        .json
        .canonicalize()
        .with_context(|| format!("cannot resolve {label}"))?
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let root = match &opts.root {
        Some(r) => r.clone(),
        None => choose_root(&json_dir, &records, opts.find_root, &label, &mut report),
    };
    let mut header = Header::new(Some(root.to_string_lossy().into_owned()));
    header.complete = false;
    header.source = Some(json!({
        "path": label,
        "sha256": sha256_bytes(&bytes),
        "arrays": sources,
    }));
    Ok((
        Manifest {
            header,
            records,
            summary: None,
            problems: Vec::new(),
        },
        report,
    ))
}

/// The JSON file's directory, or with `find` the directory among it and its ancestors under
/// which the most listed paths exist (the nearest on ties). Without `find`, a better ancestor
/// is reported as a hint.
fn choose_root(
    dir: &Path,
    records: &[Record],
    find: bool,
    label: &str,
    report: &mut Report,
) -> PathBuf {
    let counts: Vec<(PathBuf, usize)> = dir
        .ancestors()
        .take(8)
        .map(|d| {
            (
                d.to_path_buf(),
                records.iter().filter(|r| d.join(&r.path).exists()).count(),
            )
        })
        .collect();
    let best = counts
        .iter()
        .enumerate()
        .max_by_key(|(i, (_, n))| (*n, std::cmp::Reverse(*i)))
        .map(|(_, c)| c.clone())
        .unwrap_or_else(|| (dir.to_path_buf(), 0));
    let here = counts.first().map_or(0, |c| c.1);
    let data = json!(
        counts
            .iter()
            .map(|(d, n)| json!({"root": d, "existing": n}))
            .collect::<Vec<_>>()
    );
    if find {
        report.push(
            Finding::new(
                "root-chosen",
                Severity::Info,
                label,
                format!(
                    "{} of {} paths exist under {}; using it as the root",
                    best.1,
                    records.len(),
                    best.0.display()
                ),
            )
            .with_data(data),
        );
        return best.0;
    }
    if best.1 > here {
        report.push(
            Finding::new(
                "root-hint",
                Severity::Warn,
                label,
                format!(
                    "{} of {} paths exist under {}, {here} under the manifest's directory; pass --root or --find-root if the paths are relative to it",
                    best.1,
                    records.len(),
                    best.0.display()
                ),
            )
            .with_data(data),
        );
    }
    dir.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ImportOptions {
        ImportOptions {
            json: PathBuf::new(),
            records: Vec::new(),
            path_field: None,
            hash_field: None,
            bytes_field: None,
            root: None,
            find_root: false,
        }
    }

    #[test]
    fn pairs_by_prefix() {
        let h = "a".repeat(64);
        let v = json!({"path": "a.pdf", "sha256": h, "text_path": "a.txt", "text_sha256": h, "raw_line_sha256": h, "bytes": 3});
        let (p, orphans) = pairs(v.as_object().unwrap(), &opts());
        assert_eq!(
            p,
            [
                Pair {
                    path: "path".into(),
                    hash: "sha256".into(),
                    bytes: Some("bytes".into())
                },
                Pair {
                    path: "text_path".into(),
                    hash: "text_sha256".into(),
                    bytes: None
                },
            ]
        );
        assert_eq!(orphans, ["raw_line_sha256"]);
    }

    #[test]
    fn generic_hash_field_must_hold_sha256() {
        let v = json!({"path": "a", "hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709"});
        assert!(pairs(v.as_object().unwrap(), &opts()).0.is_empty());
    }

    #[test]
    fn wildcard_pointers() {
        let v = json!({"sources": [{"artifacts": [{"path": "a"}, {"path": "b"}]}, {"artifacts": [{"path": "c"}]}]});
        let got: Vec<String> = resolve(&v, "/sources/*/artifacts/*")
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert_eq!(
            got,
            [
                "/sources/0/artifacts/0",
                "/sources/0/artifacts/1",
                "/sources/1/artifacts/0"
            ]
        );
        assert_eq!(shape("/sources/1/artifacts/0"), "/sources/*/artifacts/*");
    }
}
