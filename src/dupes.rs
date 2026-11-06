//! Groups of byte-identical files: size prefilter, then SHA-256. Read-only.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use rayon::prelude::*;
use serde::Serialize;
use serde_json::json;

use crate::finding::{Finding, Report, Severity};
use crate::hash::hash_file;
use crate::walk::{Entry, EntryKind, Filter, walk};

#[derive(Debug, Clone, Serialize)]
pub struct Group {
    pub sha256: String,
    pub bytes: u64,
    /// Relative paths, sorted.
    pub paths: Vec<String>,
    /// Number of distinct files on disk; hard links to one file count once.
    pub distinct: usize,
    /// Bytes freed by keeping one copy: `bytes * (distinct - 1)`.
    pub reclaimable_bytes: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct Dupes {
    pub scanned_files: u64,
    pub scanned_bytes: u64,
    pub hashed_files: u64,
    pub groups: Vec<Group>,
    pub duplicate_files: u64,
    pub reclaimable_bytes: u64,
}

pub fn find(root: &Path, filter: &Filter) -> Result<(Dupes, Report)> {
    let walked = walk(root, filter, false)?;
    let mut report = Report::default();
    for e in &walked.errors {
        report.push(Finding::new(
            "walk-error",
            Severity::Warn,
            &e.path,
            format!("not scanned: {}", e.reason),
        ));
    }
    let mut by_size: HashMap<u64, Vec<&Entry>> = HashMap::new();
    let mut out = Dupes::default();
    for e in &walked.entries {
        if let EntryKind::File { bytes, .. } = e.kind {
            out.scanned_files += 1;
            out.scanned_bytes += bytes;
            by_size.entry(bytes).or_default().push(e);
        }
    }
    let candidates: Vec<&Entry> = by_size
        .values()
        .filter(|v| v.len() > 1)
        .flatten()
        .copied()
        .collect();
    out.hashed_files = candidates.len() as u64;
    let hashed: Vec<(&Entry, std::io::Result<(u64, String)>)> = candidates
        .par_iter()
        .map(|e| (*e, hash_file(&e.abs)))
        .collect();
    let mut by_hash: BTreeMap<(u64, String), Vec<&Entry>> = BTreeMap::new();
    for (e, r) in hashed {
        let EntryKind::File { bytes, .. } = e.kind else {
            continue;
        };
        match r {
            Ok((n, h)) if n == bytes => by_hash.entry((n, h)).or_default().push(e),
            Ok((n, _)) => report.push(Finding::new(
                "file-unreadable",
                Severity::Warn,
                &e.rel,
                format!("changed while hashing ({bytes} bytes listed, {n} read); not grouped"),
            )),
            Err(err) => report.push(Finding::new(
                "file-unreadable",
                Severity::Warn,
                &e.rel,
                format!("not hashed: {err}"),
            )),
        }
    }
    for ((bytes, sha256), mut entries) in by_hash {
        if entries.len() < 2 {
            continue;
        }
        entries.sort_by(|a, b| a.rel.cmp(&b.rel));
        let mut ids = HashSet::new();
        let mut distinct = 0;
        for e in &entries {
            match e.file_id {
                Some(id) => {
                    if ids.insert(id) {
                        distinct += 1;
                    }
                }
                None => distinct += 1,
            }
        }
        let reclaimable = bytes * (distinct as u64 - 1);
        out.duplicate_files += entries.len() as u64 - 1;
        out.reclaimable_bytes += reclaimable;
        out.groups.push(Group {
            sha256,
            bytes,
            paths: entries.iter().map(|e| e.rel.clone()).collect(),
            distinct,
            reclaimable_bytes: reclaimable,
        });
    }
    out.groups.sort_by(|a, b| {
        b.reclaimable_bytes
            .cmp(&a.reclaimable_bytes)
            .then_with(|| a.paths[0].cmp(&b.paths[0]))
    });
    for g in &out.groups {
        let hard = if g.distinct < g.paths.len() {
            format!(" ({} are hard links)", g.paths.len() - g.distinct)
        } else {
            String::new()
        };
        report.push(
            Finding::new(
                "duplicate-group",
                Severity::Info,
                &g.paths[0],
                format!(
                    "{} identical copies of {} bytes{hard}; {} bytes reclaimable",
                    g.paths.len(),
                    g.bytes,
                    g.reclaimable_bytes
                ),
            )
            .with_data(serde_json::to_value(g)?),
        );
    }
    report.push(
        Finding::new(
            "dupes-summary",
            Severity::Info,
            root.display().to_string(),
            format!(
                "{} files ({} bytes) scanned, {} hashed; {} groups, {} redundant copies, {} bytes reclaimable",
                out.scanned_files,
                out.scanned_bytes,
                out.hashed_files,
                out.groups.len(),
                out.duplicate_files,
                out.reclaimable_bytes
            ),
        )
        .with_data(json!({
            "scanned_files": out.scanned_files,
            "scanned_bytes": out.scanned_bytes,
            "hashed_files": out.hashed_files,
            "groups": out.groups.len(),
            "duplicate_files": out.duplicate_files,
            "reclaimable_bytes": out.reclaimable_bytes,
        })),
    );
    Ok((out, report))
}
