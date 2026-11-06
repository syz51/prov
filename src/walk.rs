//! Deterministic directory walking with include/exclude globs.
//!
//! A pattern without `/` matches a file or directory name at any depth; a pattern with `/`
//! matches the path relative to the walk root, where `*` also crosses `/`. A leading `/`
//! anchors a pattern to the root. Excluded
//! directories are not descended into. Symbolic links are reported, never followed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

fn glob(pattern: &str, original: &str) -> Result<Glob> {
    Glob::new(pattern).with_context(|| format!("invalid glob pattern {original:?}"))
}

#[derive(Debug, Default, Clone)]
pub struct Patterns {
    names: GlobSet,
    paths: GlobSet,
}

impl Patterns {
    pub fn new(patterns: &[String]) -> Result<Self> {
        let mut names = GlobSetBuilder::new();
        let mut paths = GlobSetBuilder::new();
        for p in patterns {
            if let Some(anchored) = p.strip_prefix('/') {
                paths.add(glob(anchored, p)?);
            } else if p.contains('/') {
                paths.add(glob(p, p)?);
            } else {
                names.add(glob(p, p)?);
            }
        }
        Ok(Patterns {
            names: names.build()?,
            paths: paths.build()?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.paths.is_empty()
    }

    pub fn matches(&self, rel: &str) -> bool {
        let name = rel.rsplit('/').next().unwrap_or(rel);
        self.names.is_match(name) || self.paths.is_match(rel)
    }
}

#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub include: Patterns,
    pub exclude: Patterns,
    /// Files smaller than this many bytes are left out.
    pub min_size: u64,
}

impl Filter {
    pub fn new(include: &[String], exclude: &[String], min_size: u64) -> Result<Self> {
        Ok(Filter {
            include: Patterns::new(include)?,
            exclude: Patterns::new(exclude)?,
            min_size,
        })
    }
}

#[derive(Debug, Clone)]
pub enum EntryKind {
    File { bytes: u64, mtime: Option<String> },
    Symlink { target: String },
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// Path relative to the walk root, `/`-separated.
    pub rel: String,
    pub abs: PathBuf,
    pub kind: EntryKind,
    /// `(device, inode)` where the platform has them; used to spot hard links.
    pub file_id: Option<(u64, u64)>,
}

/// A path the walk could not record, with the reason.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct Walk {
    pub entries: Vec<Entry>,
    /// Paths that exist but could not be read or represented; these make a walk incomplete.
    pub errors: Vec<Skipped>,
    /// Special files (sockets, FIFOs, devices) that are deliberately not recorded.
    pub special: Vec<Skipped>,
}

#[cfg(unix)]
fn file_id(meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn file_id(_meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

pub fn mtime_of(meta: &std::fs::Metadata) -> Option<String> {
    let t = meta.modified().ok()?;
    jiff::Timestamp::try_from(t).ok().map(|ts| ts.to_string())
}

fn rel_string(root: &Path, path: &Path) -> Result<String, String> {
    let rel = path.strip_prefix(root).map_err(|e| e.to_string())?;
    let mut parts = Vec::new();
    for c in rel.components() {
        match c.as_os_str().to_str() {
            Some(s) => parts.push(s),
            None => return Err("path is not valid UTF-8".to_owned()),
        }
    }
    Ok(parts.join("/"))
}

/// Walks `root`, returning entries sorted by relative path (byte order).
pub fn walk(root: &Path, filter: &Filter, want_mtime: bool) -> Result<Walk> {
    let meta =
        std::fs::metadata(root).with_context(|| format!("cannot read {}", root.display()))?;
    if !meta.is_dir() {
        bail!("{} is not a directory", root.display());
    }
    let mut out = Walk::default();
    let it = walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            match rel_string(root, e.path()) {
                Ok(rel) => !filter.exclude.matches(&rel),
                Err(_) => true,
            }
        });
    for item in it {
        let entry = match item {
            Ok(e) => e,
            Err(err) => {
                let path = err
                    .path()
                    .map(|p| rel_string(root, p).unwrap_or_else(|_| p.display().to_string()))
                    .unwrap_or_default();
                out.errors.push(Skipped {
                    path,
                    reason: err.to_string(),
                });
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let rel = match rel_string(root, entry.path()) {
            Ok(r) => r,
            Err(reason) => {
                out.errors.push(Skipped {
                    path: entry.path().display().to_string(),
                    reason,
                });
                continue;
            }
        };
        let ft = entry.file_type();
        if ft.is_dir() {
            continue;
        }
        if !filter.include.is_empty() && !filter.include.matches(&rel) {
            continue;
        }
        if ft.is_symlink() {
            match std::fs::read_link(entry.path()) {
                Ok(target) => match target.to_str() {
                    Some(t) => out.entries.push(Entry {
                        rel,
                        abs: entry.path().to_path_buf(),
                        kind: EntryKind::Symlink {
                            target: t.to_owned(),
                        },
                        file_id: None,
                    }),
                    None => out.errors.push(Skipped {
                        path: rel,
                        reason: "symlink target is not valid UTF-8".to_owned(),
                    }),
                },
                Err(e) => out.errors.push(Skipped {
                    path: rel,
                    reason: format!("cannot read symlink: {e}"),
                }),
            }
            continue;
        }
        if !ft.is_file() {
            out.special.push(Skipped {
                path: rel,
                reason: "not a regular file, directory or symlink".to_owned(),
            });
            continue;
        }
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                out.errors.push(Skipped {
                    path: rel,
                    reason: e.to_string(),
                });
                continue;
            }
        };
        if meta.len() < filter.min_size {
            continue;
        }
        out.entries.push(Entry {
            rel,
            abs: entry.path().to_path_buf(),
            kind: EntryKind::File {
                bytes: meta.len(),
                mtime: if want_mtime { mtime_of(&meta) } else { None },
            },
            file_id: file_id(&meta),
        });
    }
    out.entries.sort_by(|a, b| a.rel.cmp(&b.rel));
    out.errors.sort_by(|a, b| a.path.cmp(&b.path));
    out.special.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_filter_admits_everything() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("a"), b"a").unwrap();
        let w = walk(t.path(), &Filter::default(), false).unwrap();
        assert_eq!(w.entries.len(), 1);
    }

    #[test]
    fn name_and_path_patterns() {
        let p = Patterns::new(&[
            "*.pdf".into(),
            "build".into(),
            "docs/tmp/*".into(),
            "/top.txt".into(),
        ])
        .unwrap();
        assert!(p.matches("top.txt"));
        assert!(!p.matches("a/top.txt"));
        assert!(p.matches("a/b/c.pdf"));
        assert!(p.matches("x/build"));
        assert!(p.matches("docs/tmp/a/b.txt"));
        assert!(!p.matches("docs/tmpx/a"));
        assert!(!p.matches("a/builder"));
    }
}
