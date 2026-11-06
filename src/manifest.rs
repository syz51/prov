//! `rf.manifest/1`: content manifests of a directory tree, and their verification and diffing.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::finding::{Finding, Report, Severity};
use crate::hash::hash_file;
use crate::walk::{EntryKind, Filter, Skipped, walk};

pub const SCHEMA: &str = "rf.manifest/1";

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub schema: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// Directory the record paths are relative to, or null when unknown.
    pub root: Option<String>,
    pub created_at: String,
    pub tool: String,
    pub tool_version: String,
    pub hash: String,
    #[serde(default)]
    pub includes: Vec<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
    /// True when the records claim to list every file under `root` that the filters admit,
    /// so files not listed are reported as new.
    #[serde(default = "default_true")]
    pub complete: bool,
    /// Special files (sockets, FIFOs, devices) seen and deliberately not recorded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub special: Vec<Skipped>,
    /// For imported manifests: where the records came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,
}

impl Header {
    pub fn new(root: Option<String>) -> Self {
        Header {
            schema: SCHEMA.to_owned(),
            kind: "header".to_owned(),
            root,
            created_at: crate::now_rfc3339(),
            tool: "prov".to_owned(),
            tool_version: crate::VERSION.to_owned(),
            hash: "sha256".to_owned(),
            includes: Vec::new(),
            excludes: Vec::new(),
            complete: true,
            special: Vec::new(),
            source: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expect {
    /// `None` means the manifest does not know the value; it is then reported as unchecked.
    File {
        bytes: Option<u64>,
        sha256: Option<String>,
    },
    Symlink {
        target: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub path: String,
    pub expect: Expect,
    pub mtime: Option<String>,
    /// Where the record came from in a foreign manifest: a JSON pointer to the object.
    pub origin: Option<String>,
    /// The path and hash field names within that object.
    pub origin_fields: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct FileLine {
    schema: String,
    #[serde(rename = "type")]
    kind: String,
    path: String,
    bytes: Option<u64>,
    sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mtime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    origin_fields: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct SymlinkLine {
    schema: String,
    #[serde(rename = "type")]
    kind: String,
    path: String,
    target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub schema: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub files: u64,
    pub symlinks: u64,
    pub bytes: u64,
    /// Paths that exist but could not be recorded (unreadable, non-UTF-8, changed while hashed).
    #[serde(default)]
    pub errors: Vec<Skipped>,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub header: Header,
    pub records: Vec<Record>,
    pub summary: Option<Summary>,
    /// Problems found while reading the manifest itself.
    pub problems: Vec<Finding>,
}

pub fn write_header(out: &mut dyn Write, header: &Header) -> Result<()> {
    serde_json::to_writer(&mut *out, header)?;
    out.write_all(b"\n")?;
    Ok(())
}

pub fn write_record(out: &mut dyn Write, rec: &Record) -> Result<()> {
    match &rec.expect {
        Expect::File { bytes, sha256 } => serde_json::to_writer(
            &mut *out,
            &FileLine {
                schema: SCHEMA.to_owned(),
                kind: "file".to_owned(),
                path: rec.path.clone(),
                bytes: *bytes,
                sha256: sha256.clone(),
                mtime: rec.mtime.clone(),
                origin: rec.origin.clone(),
                origin_fields: rec.origin_fields.clone(),
            },
        )?,
        Expect::Symlink { target } => serde_json::to_writer(
            &mut *out,
            &SymlinkLine {
                schema: SCHEMA.to_owned(),
                kind: "symlink".to_owned(),
                path: rec.path.clone(),
                target: target.clone(),
            },
        )?,
    }
    out.write_all(b"\n")?;
    Ok(())
}

pub fn write_manifest(out: &mut dyn Write, m: &Manifest) -> Result<()> {
    write_header(out, &m.header)?;
    for r in &m.records {
        write_record(out, r)?;
    }
    if let Some(s) = &m.summary {
        serde_json::to_writer(&mut *out, s)?;
        out.write_all(b"\n")?;
    }
    out.flush()?;
    Ok(())
}

/// Checks a record's `schema` field against `family/major`, accepting `family/major.minor`.
pub fn check_schema(v: &Value, family: &str, major: u32, at: &str) -> Result<()> {
    let Some(schema) = v.get("schema").and_then(Value::as_str) else {
        bail!("{at}: record has no \"schema\" field");
    };
    let Some(version) = schema
        .strip_prefix(family)
        .and_then(|s| s.strip_prefix('/'))
    else {
        bail!("{at}: schema {schema:?} is not {family}");
    };
    let got = version.split('.').next().unwrap_or("");
    if got != major.to_string() {
        bail!("{at}: unsupported schema version {schema:?}; this prov reads {family}/{major}");
    }
    Ok(())
}

pub fn read_manifest(path: &Path) -> Result<Manifest> {
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let label = path.display().to_string();
    let mut header: Option<Header> = None;
    let mut records = Vec::new();
    let mut summary: Option<Summary> = None;
    let mut problems = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let lineno = i + 1;
        let at = format!("{label}:{lineno}");
        let line = line.with_context(|| format!("{at}: cannot read line"))?;
        if line.trim().is_empty() {
            continue;
        }
        let v: Value =
            serde_json::from_str(&line).with_context(|| format!("{at}: invalid JSON"))?;
        check_schema(&v, "rf.manifest", 1, &at)?;
        let kind = v.get("type").and_then(Value::as_str).unwrap_or("");
        if header.is_none() && kind != "header" {
            bail!("{at}: the first record must have \"type\": \"header\"");
        }
        if summary.is_some() {
            problems.push(
                Finding::new(
                    "manifest-invalid",
                    Severity::Error,
                    &label,
                    "record after the summary record",
                )
                .with_evidence(&label, format!("line {lineno}")),
            );
        }
        let rec = match kind {
            "header" if header.is_none() => {
                header = Some(
                    serde_json::from_value(v)
                        .with_context(|| format!("{at}: invalid header record"))?,
                );
                continue;
            }
            "header" => bail!("{at}: second header record"),
            "summary" => {
                summary = Some(
                    serde_json::from_value(v)
                        .with_context(|| format!("{at}: invalid summary record"))?,
                );
                continue;
            }
            "file" => {
                let l: FileLine = serde_json::from_value(v)
                    .with_context(|| format!("{at}: invalid file record"))?;
                let sha256 = match l.sha256 {
                    Some(h) => Some(
                        crate::hash::normalize_sha256(&h)
                            .with_context(|| format!("{at}: invalid sha256 {h:?}"))?,
                    ),
                    None => None,
                };
                Record {
                    path: l.path,
                    expect: Expect::File {
                        bytes: l.bytes,
                        sha256,
                    },
                    mtime: l.mtime,
                    origin: l.origin,
                    origin_fields: l.origin_fields,
                }
            }
            "symlink" => {
                let l: SymlinkLine = serde_json::from_value(v)
                    .with_context(|| format!("{at}: invalid symlink record"))?;
                Record {
                    path: l.path,
                    expect: Expect::Symlink { target: l.target },
                    mtime: None,
                    origin: None,
                    origin_fields: Vec::new(),
                }
            }
            other => {
                problems.push(
                    Finding::new(
                        "unknown-record",
                        Severity::Warn,
                        &label,
                        format!("record type {other:?} is not known to this prov; ignored"),
                    )
                    .with_evidence(&label, format!("line {lineno}")),
                );
                continue;
            }
        };
        if let Some(&first) = seen.get(&rec.path) {
            problems.push(
                Finding::new(
                    "manifest-duplicate-path",
                    Severity::Error,
                    &rec.path,
                    format!("path listed twice; the record on line {first} is used"),
                )
                .with_evidence(&label, format!("line {lineno}")),
            );
            continue;
        }
        seen.insert(rec.path.clone(), lineno);
        records.push(rec);
    }
    let Some(header) = header else {
        bail!("{label}: empty manifest");
    };
    // A summary is required of a complete manifest and checked whenever present.
    match &summary {
        None if !header.complete => {}
        None => problems.push(Finding::new(
            "manifest-truncated",
            Severity::Error,
            &label,
            "manifest has no summary record; it may be truncated",
        )),
        Some(s) => {
            let files = records
                .iter()
                .filter(|r| matches!(r.expect, Expect::File { .. }))
                .count() as u64;
            let links = records.len() as u64 - files;
            if s.files != files || s.symlinks != links {
                problems.push(
                    Finding::new(
                        "manifest-truncated",
                        Severity::Error,
                        &label,
                        format!(
                            "summary lists {} files and {} symlinks but the manifest has {files} and {links}",
                            s.files, s.symlinks
                        ),
                    )
                    .with_data(json!({"summary_files": s.files, "summary_symlinks": s.symlinks, "files": files, "symlinks": links})),
                );
            }
        }
    }
    Ok(Manifest {
        header,
        records,
        summary,
        problems,
    })
}

pub struct BuildOptions {
    pub root: PathBuf,
    pub includes: Vec<String>,
    pub excludes: Vec<String>,
    pub mtime: bool,
    /// The output file, excluded from the walk when it lies inside the root.
    pub output: Option<PathBuf>,
}

pub struct BuildStats {
    pub files: u64,
    pub symlinks: u64,
    pub bytes: u64,
    pub errors: Vec<Skipped>,
    pub special: Vec<Skipped>,
}

/// Absolute form of a path whose last component may not exist yet.
pub fn absolute_lenient(path: &Path) -> Result<PathBuf> {
    if let Ok(p) = path.canonicalize() {
        return Ok(p);
    }
    let abs = std::path::absolute(path)?;
    match (abs.parent(), abs.file_name()) {
        (Some(parent), Some(name)) => Ok(parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf())
            .join(name)),
        _ => Ok(abs),
    }
}

/// Where an output file is written before it is renamed into place.
pub fn partial_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".partial");
    path.with_file_name(name)
}

/// Writes `path` through `<path>.partial`, renaming it into place only if `write` succeeds,
/// so a failed write never leaves a truncated or half-written file under the final name.
pub fn write_atomic<T>(path: &Path, write: impl FnOnce(&mut dyn Write) -> Result<T>) -> Result<T> {
    let tmp = partial_path(path);
    let file =
        std::fs::File::create(&tmp).with_context(|| format!("cannot create {}", tmp.display()))?;
    let mut w = std::io::BufWriter::new(file);
    let result = write(&mut w).and_then(|v| {
        w.flush()?;
        Ok(v)
    });
    drop(w);
    match result {
        Ok(v) => {
            std::fs::rename(&tmp, path)
                .with_context(|| format!("cannot rename {} into place", tmp.display()))?;
            Ok(v)
        }
        Err(e) => {
            // The partial file is ours and incomplete; the original error is what matters.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub fn build(opts: &BuildOptions, out: &mut dyn Write) -> Result<BuildStats> {
    let root = opts
        .root
        .canonicalize()
        .with_context(|| format!("cannot open {}", opts.root.display()))?;
    let mut excludes = opts.excludes.clone();
    if let Some(output) = &opts.output {
        for p in [output.clone(), partial_path(output)] {
            let abs = absolute_lenient(&p)?;
            if let Ok(rel) = abs.strip_prefix(&root) {
                let rel = rel.to_string_lossy().replace('\\', "/");
                excludes.push(format!("/{}", globset::escape(&rel)));
            }
        }
    }
    let filter = Filter::new(&opts.includes, &excludes, 0)?;
    let walked = walk(&root, &filter, opts.mtime)?;
    let hashed: Vec<Result<Record, Skipped>> = walked
        .entries
        .par_iter()
        .map(|e| match &e.kind {
            EntryKind::Symlink { target } => Ok(Record {
                path: e.rel.clone(),
                expect: Expect::Symlink {
                    target: target.clone(),
                },
                mtime: None,
                origin: None,
                origin_fields: Vec::new(),
            }),
            EntryKind::File { bytes, mtime } => match hash_file(&e.abs) {
                Ok((n, sha)) if n == *bytes => Ok(Record {
                    path: e.rel.clone(),
                    expect: Expect::File {
                        bytes: Some(n),
                        sha256: Some(sha),
                    },
                    mtime: mtime.clone(),
                    origin: None,
                    origin_fields: Vec::new(),
                }),
                Ok((n, _)) => Err(Skipped {
                    path: e.rel.clone(),
                    reason: format!("file changed while hashing ({bytes} bytes listed, {n} read)"),
                }),
                Err(err) => Err(Skipped {
                    path: e.rel.clone(),
                    reason: err.to_string(),
                }),
            },
        })
        .collect();
    let mut header = Header::new(Some(root.to_string_lossy().into_owned()));
    header.includes = opts.includes.clone();
    header.excludes = excludes;
    header.special = walked.special.clone();
    write_header(out, &header)?;
    let mut stats = BuildStats {
        files: 0,
        symlinks: 0,
        bytes: 0,
        errors: walked.errors,
        special: walked.special,
    };
    for r in hashed {
        match r {
            Ok(rec) => {
                match &rec.expect {
                    Expect::File { bytes, .. } => {
                        stats.files += 1;
                        stats.bytes += bytes.unwrap_or(0);
                    }
                    Expect::Symlink { .. } => stats.symlinks += 1,
                }
                write_record(out, &rec)?;
            }
            Err(s) => stats.errors.push(s),
        }
    }
    stats.errors.sort_by(|a, b| a.path.cmp(&b.path));
    let summary = Summary {
        schema: SCHEMA.to_owned(),
        kind: "summary".to_owned(),
        files: stats.files,
        symlinks: stats.symlinks,
        bytes: stats.bytes,
        errors: stats.errors.clone(),
    };
    serde_json::to_writer(&mut *out, &summary)?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(stats)
}

#[derive(Debug)]
enum Outcome {
    Ok,
    Missing,
    Changed {
        bytes: u64,
        sha256: Option<String>,
    },
    /// Exists with the listed size (or unknown size), but the manifest has no hash.
    Unchecked {
        bytes: u64,
    },
    LinkChanged {
        target: Option<String>,
    },
    /// Content matches the listed SHA-256 but the listed size does not.
    SizeMismatch {
        bytes: u64,
    },
    Unreadable(String),
}

fn check_record(root: &Path, rec: &Record) -> Outcome {
    let path = root.join(&rec.path);
    match &rec.expect {
        Expect::Symlink { target } => match std::fs::read_link(&path) {
            Ok(t) if t.to_str() == Some(target.as_str()) => Outcome::Ok,
            Ok(t) => Outcome::LinkChanged {
                target: Some(t.to_string_lossy().into_owned()),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Outcome::Missing,
            Err(_) if path.symlink_metadata().is_ok() => Outcome::LinkChanged { target: None },
            Err(e) => Outcome::Unreadable(e.to_string()),
        },
        Expect::File { bytes, sha256 } => {
            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Outcome::Missing,
                Err(e) => return Outcome::Unreadable(e.to_string()),
            };
            if !meta.is_file() {
                return Outcome::Unreadable("not a regular file".to_owned());
            }
            let Some(expected) = sha256 else {
                // Without a hash, a size difference is the only evidence available.
                return match bytes {
                    Some(b) if meta.len() != *b => Outcome::Changed {
                        bytes: meta.len(),
                        sha256: None,
                    },
                    _ => Outcome::Unchecked { bytes: meta.len() },
                };
            };
            // With a hash, content decides; a listed size never overrides it.
            match hash_file(&path) {
                Ok((n, got)) if &got == expected && bytes.is_none_or(|b| b == n) => Outcome::Ok,
                Ok((n, got)) if &got == expected => Outcome::SizeMismatch { bytes: n },
                Ok((n, got)) => Outcome::Changed {
                    bytes: n,
                    sha256: Some(got),
                },
                Err(e) => Outcome::Unreadable(e.to_string()),
            }
        }
    }
}

/// The evidence locator for an imported record: its JSON pointer and field names.
pub fn origin_locator(origin: &str, fields: &[String]) -> String {
    if fields.is_empty() {
        origin.to_owned()
    } else {
        format!("{origin} ({})", fields.join(", "))
    }
}

fn locate(f: Finding, label: &str, rec: &Record) -> Finding {
    match &rec.origin {
        Some(o) => f.with_evidence(label, origin_locator(o, &rec.origin_fields)),
        None => f,
    }
}

/// Verifies `m` against the files under `root`. `label` names the manifest in evidence.
pub fn verify(m: &Manifest, root: &Path, label: &str) -> Result<Report> {
    let mut report = Report::default();
    report.extend(m.problems.iter().cloned());
    if let Some(s) = &m.summary {
        for e in &s.errors {
            report.push(Finding::new(
                "unrecorded-at-build",
                Severity::Warn,
                &e.path,
                format!(
                    "not recorded when the manifest was built ({}); not checked",
                    e.reason
                ),
            ));
        }
    }
    if !root.is_dir() {
        bail!("root {} is not a directory", root.display());
    }
    let outcomes: Vec<Outcome> = m
        .records
        .par_iter()
        .map(|r| check_record(root, r))
        .collect();

    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for k in [
        "ok",
        "changed",
        "missing",
        "moved",
        "unchecked",
        "unreadable",
        "new",
    ] {
        counts.insert(k, 0);
    }
    // Missing files with a known hash, for move detection: sha256 -> record indices.
    let mut missing_by_hash: HashMap<String, Vec<usize>> = HashMap::new();
    let mut missing_sizes: HashSet<Option<u64>> = HashSet::new();
    let mut missing: Vec<usize> = Vec::new();
    for (i, (rec, out)) in m.records.iter().zip(&outcomes).enumerate() {
        match out {
            Outcome::Ok => *counts.get_mut("ok").unwrap() += 1,
            Outcome::Missing => {
                if let Expect::File {
                    sha256: Some(h),
                    bytes,
                } = &rec.expect
                {
                    missing_by_hash.entry(h.clone()).or_default().push(i);
                    missing_sizes.insert(*bytes);
                }
                missing.push(i);
            }
            Outcome::Changed { bytes, sha256 } => {
                *counts.get_mut("changed").unwrap() += 1;
                let (eb, eh) = match &rec.expect {
                    Expect::File { bytes, sha256 } => (*bytes, sha256.clone()),
                    Expect::Symlink { .. } => (None, None),
                };
                let msg = match (eb, sha256) {
                    (Some(e), None) => format!("size changed: {e} bytes listed, {bytes} on disk"),
                    _ => format!(
                        "content changed: sha256 {} listed, {} on disk ({bytes} bytes)",
                        short(eh.as_deref()),
                        short(sha256.as_deref())
                    ),
                };
                report.push(locate(
                    Finding::new("file-changed", Severity::Error, &rec.path, msg).with_data(
                        json!({
                            "expected": {"bytes": eb, "sha256": eh},
                            "actual": {"bytes": bytes, "sha256": sha256},
                        }),
                    ),
                    label,
                    rec,
                ));
            }
            Outcome::SizeMismatch { bytes } => {
                *counts.get_mut("ok").unwrap() += 1;
                let listed = match &rec.expect {
                    Expect::File { bytes, .. } => *bytes,
                    Expect::Symlink { .. } => None,
                };
                report.push(locate(
                    Finding::new(
                        "bytes-mismatch",
                        Severity::Warn,
                        &rec.path,
                        format!(
                            "content matches the listed sha256, but the listed size ({}) differs from the file ({bytes} bytes); the size field may mean something else",
                            listed.map_or("?".to_owned(), |b| format!("{b} bytes"))
                        ),
                    )
                    .with_data(json!({"listed_bytes": listed, "bytes": bytes})),
                    label,
                    rec,
                ));
            }
            Outcome::Unchecked { bytes } => {
                *counts.get_mut("unchecked").unwrap() += 1;
                report.push(locate(
                    Finding::new(
                        "hash-unchecked",
                        Severity::Warn,
                        &rec.path,
                        format!(
                            "file exists ({bytes} bytes) but the manifest lists no sha256; content not checked"
                        ),
                    ),
                    label,
                    rec,
                ));
            }
            Outcome::LinkChanged { target } => {
                *counts.get_mut("changed").unwrap() += 1;
                let expected = match &rec.expect {
                    Expect::Symlink { target } => target.as_str(),
                    Expect::File { .. } => "",
                };
                report.push(Finding::new(
                    "symlink-changed",
                    Severity::Error,
                    &rec.path,
                    match target {
                        Some(t) => format!("symlink points to {t:?}, manifest lists {expected:?}"),
                        None => format!("no longer a symlink; manifest lists one to {expected:?}"),
                    },
                ));
            }
            Outcome::Unreadable(e) => {
                *counts.get_mut("unreadable").unwrap() += 1;
                report.push(locate(
                    Finding::new(
                        "file-unreadable",
                        Severity::Error,
                        &rec.path,
                        format!("cannot verify: {e}"),
                    ),
                    label,
                    rec,
                ));
            }
        }
    }

    let mut moved_from: HashSet<usize> = HashSet::new();
    if m.header.complete {
        let filter = Filter::new(&m.header.includes, &m.header.excludes, 0)?;
        let walked = walk(root, &filter, false)?;
        for e in &walked.errors {
            report.push(Finding::new(
                "walk-error",
                Severity::Warn,
                &e.path,
                format!("cannot check for new files here: {}", e.reason),
            ));
        }
        let listed: HashSet<&str> = m.records.iter().map(|r| r.path.as_str()).collect();
        let new: Vec<_> = walked
            .entries
            .iter()
            .filter(|e| !listed.contains(e.rel.as_str()))
            .collect();
        // Hash only new files that could be a moved copy of a missing one.
        let candidates: Vec<Option<String>> = new
            .par_iter()
            .map(|e| match &e.kind {
                EntryKind::File { bytes, .. }
                    if !missing_by_hash.is_empty()
                        && (missing_sizes.contains(&Some(*bytes))
                            || missing_sizes.contains(&None)) =>
                {
                    hash_file(&e.abs).ok().map(|(_, h)| h)
                }
                _ => None,
            })
            .collect();
        for (e, h) in new.iter().zip(candidates) {
            let from = h.as_ref().and_then(|h| {
                missing_by_hash
                    .get_mut(h)
                    .and_then(|v| (!v.is_empty()).then(|| v.remove(0)))
            });
            if let Some(i) = from {
                moved_from.insert(i);
                *counts.get_mut("moved").unwrap() += 1;
                let old = &m.records[i].path;
                report.push(
                    Finding::new(
                        "file-moved",
                        Severity::Error,
                        old,
                        format!("missing here; identical content found at {}", e.rel),
                    )
                    .with_data(json!({"from": old, "to": e.rel, "sha256": h})),
                );
            } else {
                *counts.get_mut("new").unwrap() += 1;
                let what = match &e.kind {
                    EntryKind::File { bytes, .. } => format!("file ({bytes} bytes)"),
                    EntryKind::Symlink { target } => format!("symlink to {target:?}"),
                };
                report.push(Finding::new(
                    "file-new",
                    Severity::Warn,
                    &e.rel,
                    format!("{what} not listed in the manifest"),
                ));
            }
        }
    } else {
        report.push(Finding::new(
            "new-files-unchecked",
            Severity::Info,
            label,
            "manifest does not claim to list every file under its root; files it does not list were not checked",
        ));
    }
    for i in missing {
        if moved_from.contains(&i) {
            continue;
        }
        *counts.get_mut("missing").unwrap() += 1;
        let rec = &m.records[i];
        report.push(locate(
            Finding::new(
                "file-missing",
                Severity::Error,
                &rec.path,
                "listed in the manifest but not found",
            ),
            label,
            rec,
        ));
    }
    let records = m.records.len();
    let msg = format!(
        "{records} records under {}: {} ok, {} changed, {} missing, {} moved, {} unchecked, {} unreadable; {} new",
        root.display(),
        counts["ok"],
        counts["changed"],
        counts["missing"],
        counts["moved"],
        counts["unchecked"],
        counts["unreadable"],
        counts["new"],
    );
    let mut data = serde_json::to_value(&counts)?;
    data["records"] = json!(records);
    data["root"] = json!(root.display().to_string());
    data["new_files_checked"] = json!(m.header.complete);
    report.push(Finding::new("verify-summary", Severity::Info, label, msg).with_data(data));
    Ok(report)
}

fn short(h: Option<&str>) -> String {
    match h {
        Some(h) => h.chars().take(12).collect(),
        None => "unknown".to_owned(),
    }
}

/// Compares two manifests record by record. Differences are `info`; unknown hashes are `warn`.
pub fn diff(a: &Manifest, b: &Manifest) -> Report {
    let mut report = Report::default();
    let am: BTreeMap<&str, &Record> = a.records.iter().map(|r| (r.path.as_str(), r)).collect();
    let bm: BTreeMap<&str, &Record> = b.records.iter().map(|r| (r.path.as_str(), r)).collect();
    let mut removed: Vec<&Record> = am
        .iter()
        .filter(|(p, _)| !bm.contains_key(*p))
        .map(|(_, r)| *r)
        .collect();
    let mut added: Vec<&Record> = bm
        .iter()
        .filter(|(p, _)| !am.contains_key(*p))
        .map(|(_, r)| *r)
        .collect();
    let (mut changed, mut unchecked, mut same, mut moved) = (0u64, 0u64, 0u64, 0u64);
    // A path the other build could not record is not evidence of removal or addition.
    let unrecorded = |m: &Manifest| -> HashMap<String, String> {
        m.summary
            .iter()
            .flat_map(|s| &s.errors)
            .map(|e| (e.path.clone(), e.reason.clone()))
            .collect()
    };
    let (a_err, b_err) = (unrecorded(a), unrecorded(b));
    let mut not_compared = |r: &Record, errs: &HashMap<String, String>, which: &str| -> bool {
        let Some(reason) = errs.get(&r.path) else {
            return false;
        };
        unchecked += 1;
        report.push(Finding::new(
            "diff-unchecked",
            Severity::Warn,
            &r.path,
            format!("the {which} manifest could not record this path ({reason}); not compared"),
        ));
        true
    };
    removed.retain(|r| !not_compared(r, &b_err, "second"));
    added.retain(|r| !not_compared(r, &a_err, "first"));
    for (p, ra) in &am {
        let Some(rb) = bm.get(p) else { continue };
        match (&ra.expect, &rb.expect) {
            (
                Expect::File {
                    sha256: Some(ha),
                    bytes: ba,
                },
                Expect::File {
                    sha256: Some(hb),
                    bytes: bb,
                },
            ) => {
                if ha == hb {
                    same += 1;
                } else {
                    changed += 1;
                    report.push(
                        Finding::new(
                            "diff-changed",
                            Severity::Info,
                            *p,
                            format!("content differs: {} ({} bytes) -> {} ({} bytes)", short(Some(ha)), fmt_opt(*ba), short(Some(hb)), fmt_opt(*bb)),
                        )
                        .with_data(json!({"a": {"bytes": ba, "sha256": ha}, "b": {"bytes": bb, "sha256": hb}})),
                    );
                }
            }
            (
                Expect::File {
                    bytes: Some(ba), ..
                },
                Expect::File {
                    bytes: Some(bb), ..
                },
            ) if ba != bb => {
                changed += 1;
                report.push(Finding::new(
                    "diff-changed",
                    Severity::Info,
                    *p,
                    format!("size differs: {ba} -> {bb} bytes"),
                ));
            }
            (Expect::File { .. }, Expect::File { .. }) => {
                unchecked += 1;
                report.push(Finding::new(
                    "diff-unchecked",
                    Severity::Warn,
                    *p,
                    "a manifest lists no sha256 for this path; content not compared",
                ));
            }
            (x, y) if x == y => same += 1,
            _ => {
                changed += 1;
                report.push(Finding::new(
                    "diff-changed",
                    Severity::Info,
                    *p,
                    "entry type or symlink target differs",
                ));
            }
        }
    }
    // Pair removed and added files with identical content as moves.
    let mut added_by_hash: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, r) in added.iter().enumerate() {
        if let Expect::File {
            sha256: Some(h), ..
        } = &r.expect
        {
            added_by_hash.entry(h.as_str()).or_default().push(i);
        }
    }
    let mut used: HashSet<usize> = HashSet::new();
    removed.retain(|r| {
        let Expect::File {
            sha256: Some(h), ..
        } = &r.expect
        else {
            return true;
        };
        let Some(v) = added_by_hash.get_mut(h.as_str()) else {
            return true;
        };
        let Some(pos) = v.iter().position(|i| !used.contains(i)) else {
            return true;
        };
        let i = v[pos];
        used.insert(i);
        moved += 1;
        report.push(
            Finding::new(
                "diff-moved",
                Severity::Info,
                &r.path,
                format!("moved to {}", added[i].path),
            )
            .with_data(json!({"from": r.path, "to": added[i].path, "sha256": h})),
        );
        false
    });
    let mut idx = 0usize;
    added.retain(|_| {
        let keep = !used.contains(&idx);
        idx += 1;
        keep
    });
    for r in &removed {
        report.push(Finding::new(
            "diff-removed",
            Severity::Info,
            &r.path,
            "only in the first manifest",
        ));
    }
    for r in &added {
        report.push(Finding::new(
            "diff-added",
            Severity::Info,
            &r.path,
            "only in the second manifest",
        ));
    }
    report.push(
        Finding::new(
            "diff-summary",
            Severity::Info,
            "manifest diff",
            format!(
                "{same} same, {changed} changed, {moved} moved, {} removed, {} added, {unchecked} unchecked",
                removed.len(),
                added.len()
            ),
        )
        .with_data(json!({"same": same, "changed": changed, "moved": moved, "removed": removed.len(), "added": added.len(), "unchecked": unchecked})),
    );
    report
}

fn fmt_opt(v: Option<u64>) -> String {
    v.map_or_else(|| "unknown".to_owned(), |v| v.to_string())
}
