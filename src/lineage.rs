//! Which runs produced which files, and which runs consumed them.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

use crate::hash::short;
use crate::run::{RunRecord, Snapshot, read_record};

/// Lexically normalises a path (`.` and `..` resolved without touching the file system).
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub struct Lineage {
    pub runs: Vec<RunRecord>,
    /// Files in the directory that are not readable rf.run/1 records.
    pub skipped: Vec<String>,
}

pub fn load(dir: &Path) -> Result<Lineage> {
    let mut runs = Vec::new();
    let mut skipped = Vec::new();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    for p in paths {
        match read_record(&p) {
            Ok(r) => runs.push(r),
            Err(e) => skipped.push(format!("{}: {e:#}", p.display())),
        }
    }
    runs.sort_by(|a, b| {
        a.started_at
            .cmp(&b.started_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(Lineage { runs, skipped })
}

#[derive(Default)]
struct FileUse {
    /// sha256 -> run ids
    produced: BTreeMap<String, Vec<String>>,
    consumed: BTreeMap<String, Vec<String>>,
}

fn key(run: &RunRecord, path: &str) -> PathBuf {
    normalize(&Path::new(&run.cwd).join(path))
}

fn index(runs: &[RunRecord]) -> BTreeMap<PathBuf, FileUse> {
    let mut files: BTreeMap<PathBuf, FileUse> = BTreeMap::new();
    for r in runs {
        for i in &r.inputs {
            if let Some(h) = i.state.sha256() {
                files
                    .entry(key(r, &i.path))
                    .or_default()
                    .consumed
                    .entry(h.to_owned())
                    .or_default()
                    .push(r.id.clone());
            }
        }
        for o in &r.outputs {
            if let Some(h) = o.state.sha256() {
                files
                    .entry(key(r, &o.path))
                    .or_default()
                    .produced
                    .entry(h.to_owned())
                    .or_default()
                    .push(r.id.clone());
            }
        }
    }
    files
}

fn display(p: &Path, base: &Path) -> String {
    p.strip_prefix(base)
        .map(|r| r.display().to_string())
        .unwrap_or_else(|_| p.display().to_string())
}

fn exit_label(r: &RunRecord) -> String {
    match (r.exit.code, r.exit.signal) {
        (Some(c), _) => format!("exit {c}"),
        (None, Some(s)) => format!("signal {s}"),
        _ => "exit unknown".to_owned(),
    }
}

pub fn text(l: &Lineage, base: &Path) -> String {
    let files = index(&l.runs);
    let mut s = String::new();
    for r in &l.runs {
        let rerun = r
            .rerun_of
            .as_ref()
            .map(|x| format!("  (rerun of {x})"))
            .unwrap_or_default();
        let _ = writeln!(
            s,
            "run {}  {}  {}{rerun}",
            r.id,
            r.started_at,
            exit_label(r)
        );
        let _ = writeln!(s, "  $ {}", r.argv.join(" "));
        for i in &r.inputs {
            let k = key(r, &i.path);
            let Some(h) = i.state.sha256() else { continue };
            let u = &files[&k];
            let from = match u.produced.get(h) {
                Some(ids) => format!("<- produced by {}", ids.join(", ")),
                None if u.produced.is_empty() => "(no recorded producer)".to_owned(),
                None => format!(
                    "(no recorded producer of this content; other versions from {})",
                    u.produced
                        .iter()
                        .map(|(h, ids)| format!("{} [{}]", ids.join(", "), short(h)))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            };
            let modified = if i.modified_by_run {
                "  MODIFIED BY RUN"
            } else {
                ""
            };
            let _ = writeln!(
                s,
                "  in   {}  {}  {from}{modified}",
                display(&k, base),
                short(h)
            );
        }
        for o in &r.outputs {
            let k = key(r, &o.path);
            let Some(h) = o.state.sha256() else {
                let what = match o.state {
                    Snapshot::Missing => "missing",
                    _ => "unreadable",
                };
                let _ = writeln!(s, "  out  {}  ({what} after the run)", display(&k, base));
                continue;
            };
            let to = match files[&k].consumed.get(h) {
                Some(ids) => format!("-> consumed by {}", ids.join(", ")),
                None => "(not consumed by a recorded run)".to_owned(),
            };
            let _ = writeln!(s, "  out  {}  {}  {to}", display(&k, base), short(h));
        }
    }
    let _ = writeln!(s, "files");
    for (k, u) in &files {
        let _ = writeln!(s, "  {}", display(k, base));
        let mut hashes: Vec<&String> = u.produced.keys().chain(u.consumed.keys()).collect();
        hashes.sort();
        hashes.dedup();
        for h in hashes {
            let p = u
                .produced
                .get(h)
                .map(|v| v.join(", "))
                .unwrap_or_else(|| "-".into());
            let c = u
                .consumed
                .get(h)
                .map(|v| v.join(", "))
                .unwrap_or_else(|| "-".into());
            let _ = writeln!(s, "    {}  produced by {p}; consumed by {c}", short(h));
        }
    }
    s
}

fn q(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn dot(l: &Lineage, base: &Path) -> String {
    let mut s =
        String::from("digraph lineage {\n  rankdir=LR;\n  node [fontname=\"Helvetica\"];\n");
    let mut nodes = BTreeMap::new();
    let mut file_node = |k: &Path, h: &str, s: &mut String| {
        let id = format!("file:{}@{h}", k.display());
        nodes.entry(id.clone()).or_insert_with(|| {
            let _ = writeln!(
                s,
                "  {} [shape=ellipse, label={}];",
                q(&id),
                q(&format!("{}\n{}", display(k, base), short(h)))
            );
        });
        id
    };
    for r in &l.runs {
        let rid = format!("run:{}", r.id);
        let _ = writeln!(
            s,
            "  {} [shape=box, label={}];",
            q(&rid),
            q(&format!("{}\n{}", r.id, exit_label(r)))
        );
        for i in &r.inputs {
            if let Some(h) = i.state.sha256() {
                let f = file_node(&key(r, &i.path), h, &mut s);
                let _ = writeln!(s, "  {} -> {};", q(&f), q(&rid));
            }
        }
        for o in &r.outputs {
            if let Some(h) = o.state.sha256() {
                let f = file_node(&key(r, &o.path), h, &mut s);
                let _ = writeln!(s, "  {} -> {};", q(&rid), q(&f));
            }
        }
        if let Some(orig) = &r.rerun_of {
            let _ = writeln!(
                s,
                "  {} -> {} [style=dashed, label=\"rerun of\"];",
                q(&rid),
                q(&format!("run:{orig}"))
            );
        }
    }
    s.push_str("}\n");
    s
}
