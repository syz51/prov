//! `rf.run/1`: recording a command's run, verifying a record, and rerunning it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::compare::{self, Kind, Tolerance};
use crate::finding::{Finding, Report, Severity};
use crate::hash::{hash_file, hex, sha256_bytes};
use crate::manifest::check_schema;
use crate::walk::{EntryKind, Filter, walk};

pub const SCHEMA: &str = "rf.run/1";

/// Environment variables recorded by default; a trailing `*` matches a prefix.
pub const DEFAULT_ENV: &[&str] = &[
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_NUMERIC",
    "TZ",
    "SOURCE_DATE_EPOCH",
    "PYTHONHASHSEED",
    "PYTHONPATH",
    "PYTHONUTF8",
    "PYTHONDONTWRITEBYTECODE",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "UV_*",
    "CUDA_VISIBLE_DEVICES",
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "RAYON_NUM_THREADS",
    "HF_HUB_OFFLINE",
    "HF_DATASETS_OFFLINE",
    "TRANSFORMERS_OFFLINE",
];

/// A variable whose upper-cased name contains one of these is never recorded.
pub const SECRET_MARKERS: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "AUTH",
    "COOKIE",
    "CREDENTIAL",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TreeEntry {
    File {
        path: String,
        bytes: u64,
        sha256: String,
    },
    Symlink {
        path: String,
        target: String,
    },
}

impl TreeEntry {
    fn path(&self) -> &str {
        match self {
            TreeEntry::File { path, .. } | TreeEntry::Symlink { path, .. } => path,
        }
    }
}

/// The state of a declared input or output path at one moment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Snapshot {
    File {
        bytes: u64,
        sha256: String,
    },
    /// `sha256` is the tree digest: SHA-256 of one line per entry, in path order,
    /// `F <sha256> <bytes> <path>\n` or `L <target> <path>\n`.
    Dir {
        bytes: u64,
        sha256: String,
        files: Vec<TreeEntry>,
    },
    Missing,
    Unreadable {
        error: String,
    },
}

impl Snapshot {
    pub fn sha256(&self) -> Option<&str> {
        match self {
            Snapshot::File { sha256, .. } | Snapshot::Dir { sha256, .. } => Some(sha256),
            _ => None,
        }
    }

    fn describe(&self) -> String {
        match self {
            Snapshot::File { bytes, sha256 } => format!("file {} ({bytes} bytes)", &sha256[..12]),
            Snapshot::Dir { files, sha256, .. } => {
                format!("directory {} ({} entries)", &sha256[..12], files.len())
            }
            Snapshot::Missing => "missing".to_owned(),
            Snapshot::Unreadable { error } => format!("unreadable ({error})"),
        }
    }
}

/// Snapshots a path, following a symlink at the path itself but not inside directories.
pub fn snapshot(path: &Path) -> Snapshot {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Snapshot::Missing,
        Err(e) => {
            return Snapshot::Unreadable {
                error: e.to_string(),
            };
        }
    };
    if meta.is_file() {
        return match hash_file(path) {
            Ok((bytes, sha256)) => Snapshot::File { bytes, sha256 },
            Err(e) => Snapshot::Unreadable {
                error: e.to_string(),
            },
        };
    }
    if !meta.is_dir() {
        return Snapshot::Unreadable {
            error: "not a regular file or directory".to_owned(),
        };
    }
    let walked = match walk(path, &Filter::default(), false) {
        Ok(w) => w,
        Err(e) => {
            return Snapshot::Unreadable {
                error: format!("{e:#}"),
            };
        }
    };
    if let Some(e) = walked.errors.first() {
        return Snapshot::Unreadable {
            error: format!("{}: {}", e.path, e.reason),
        };
    }
    use rayon::prelude::*;
    let entries: Result<Vec<TreeEntry>, String> = walked
        .entries
        .par_iter()
        .map(|e| match &e.kind {
            EntryKind::Symlink { target } => Ok(TreeEntry::Symlink {
                path: e.rel.clone(),
                target: target.clone(),
            }),
            EntryKind::File { .. } => hash_file(&e.abs)
                .map(|(bytes, sha256)| TreeEntry::File {
                    path: e.rel.clone(),
                    bytes,
                    sha256,
                })
                .map_err(|err| format!("{}: {err}", e.rel)),
        })
        .collect();
    let files = match entries {
        Ok(f) => f,
        Err(error) => return Snapshot::Unreadable { error },
    };
    let mut h = Sha256::new();
    let mut bytes = 0;
    for f in &files {
        match f {
            TreeEntry::File {
                path,
                bytes: b,
                sha256,
            } => {
                bytes += b;
                h.update(format!("F {sha256} {b} {path}\n"));
            }
            TreeEntry::Symlink { path, target } => h.update(format!("L {target} {path}\n")),
        }
    }
    Snapshot::Dir {
        bytes,
        sha256: hex(&h.finalize()),
        files,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputEntry {
    /// As declared; relative paths resolve against the record's `cwd`.
    pub path: String,
    /// State before the run.
    pub state: Snapshot,
    pub modified_by_run: bool,
    /// State after the run, when it differs from `state`.
    #[serde(default)]
    pub after: Option<Snapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputEntry {
    pub path: String,
    /// State before the run (`missing` when the run created it).
    pub before: Snapshot,
    /// State after the run.
    pub state: Snapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitInfo {
    pub success: bool,
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfo {
    pub bytes: u64,
    pub sha256: String,
    /// File holding the stream, relative to the record's directory; null when not stored.
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramInfo {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRecord {
    pub schema: String,
    pub id: String,
    pub name: String,
    pub tool: String,
    pub tool_version: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub started_at: String,
    pub ended_at: String,
    pub duration_ms: u64,
    pub exit: ExitInfo,
    pub env: BTreeMap<String, String>,
    /// Names of variables the allowlist matched but that were dropped as possible secrets.
    pub env_redacted: Vec<String>,
    pub env_allowlist: Vec<String>,
    pub git: Value,
    /// Tool name to the first line of its version output; null when it could not be run.
    pub tools: BTreeMap<String, Option<String>>,
    pub program: Option<ProgramInfo>,
    pub inputs: Vec<InputEntry>,
    pub outputs: Vec<OutputEntry>,
    pub stdout: StreamInfo,
    pub stderr: StreamInfo,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub rerun_of: Option<String>,
}

pub fn is_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    SECRET_MARKERS.iter().any(|m| upper.contains(m))
}

/// True for values such as `https://user:pass@host/` that embed credentials in a URL.
fn has_url_credentials(value: &str) -> bool {
    value.split("://").skip(1).any(|rest| {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        authority.contains('@')
    })
}

fn allowed(name: &str, allow: &[String]) -> bool {
    allow.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == p,
    })
}

/// Applies the allowlist, then drops anything that looks like a secret.
pub fn select_env(
    vars: impl IntoIterator<Item = (String, String)>,
    allow: &[String],
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut kept = BTreeMap::new();
    let mut redacted = Vec::new();
    for (k, v) in vars {
        if !allowed(&k, allow) {
            continue;
        }
        if is_secret_name(&k) || has_url_credentials(&v) {
            redacted.push(k);
        } else {
            kept.insert(k, v);
        }
    }
    redacted.sort();
    (kept, redacted)
}

fn first_line(cmd: &mut Command) -> Option<String> {
    let out = cmd.stdin(Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = if out.stdout.iter().any(|b| !b.is_ascii_whitespace()) {
        out.stdout
    } else {
        out.stderr
    };
    String::from_utf8_lossy(&text)
        .lines()
        .next()
        .map(|l| l.trim().to_owned())
}

fn git_output(cwd: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

fn git_line(cwd: &Path, args: &[&str]) -> Option<String> {
    git_output(cwd, args).map(|o| String::from_utf8_lossy(&o).trim().to_owned())
}

/// Git state of the work tree containing `cwd`. Paths inside `exclude` (prov's state
/// directory) are left out of the dirty list.
pub fn git_state(cwd: &Path, exclude: &Path) -> Value {
    if Command::new("git")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .is_err()
    {
        return json!({"status": "unavailable", "reason": "git is not installed or not on PATH"});
    }
    let Some(top) = git_line(cwd, &["rev-parse", "--show-toplevel"]) else {
        return json!({"status": "none", "reason": "not inside a git work tree"});
    };
    let top = PathBuf::from(top);
    let head = git_line(&top, &["rev-parse", "--verify", "-q", "HEAD"]);
    let branch = git_line(&top, &["symbolic-ref", "-q", "--short", "HEAD"]);
    let Some(status) = git_output(
        &top,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    ) else {
        return json!({"status": "error", "toplevel": top, "head": head, "reason": "git status failed"});
    };
    let exclude_rel = exclude.canonicalize().ok().and_then(|e| {
        e.strip_prefix(top.canonicalize().ok()?)
            .ok()
            .map(Path::to_path_buf)
    });
    let mut fields = status.split(|b| *b == 0).filter(|f| !f.is_empty());
    let mut dirty: Vec<(String, String)> = Vec::new();
    while let Some(f) = fields.next() {
        let s = String::from_utf8_lossy(f);
        if s.len() < 4 {
            continue;
        }
        let (xy, path) = (s[..2].to_owned(), s[3..].to_owned());
        if xy.starts_with('R') || xy.starts_with('C') {
            fields.next(); // the original path
        }
        if exclude_rel
            .as_ref()
            .is_some_and(|e| !e.as_os_str().is_empty() && Path::new(&path).starts_with(e))
        {
            continue;
        }
        dirty.push((xy, path));
    }
    dirty.sort_by(|a, b| a.1.cmp(&b.1));
    let mut h = Sha256::new();
    for (xy, path) in &dirty {
        let p = top.join(path);
        let content = match fs::symlink_metadata(&p) {
            Ok(m) if m.is_symlink() => fs::read_link(&p)
                .map(|t| format!("symlink:{}", t.to_string_lossy()))
                .unwrap_or_else(|e| format!("unreadable:{e}")),
            Ok(m) if m.is_file() => hash_file(&p)
                .map(|(_, h)| h)
                .unwrap_or_else(|e| format!("unreadable:{e}")),
            Ok(_) => "dir".to_owned(),
            Err(_) => "absent".to_owned(),
        };
        h.update(format!("{xy} {path} {content}\n"));
    }
    json!({
        "status": "ok",
        "toplevel": top,
        "head": head,
        "branch": branch,
        "dirty": !dirty.is_empty(),
        "dirty_paths": dirty.iter().map(|(xy, p)| json!({"status": xy, "path": p})).collect::<Vec<_>>(),
        "dirty_sha256": hex(&h.finalize()),
        "state_dir_excluded": exclude_rel.is_some(),
    })
}

fn find_program(argv0: &str, cwd: &Path) -> Option<PathBuf> {
    if argv0.contains('/') {
        let p = cwd.join(argv0);
        return p.is_file().then_some(p);
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(argv0))
        .find(|p| is_executable(p))
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

fn program_info(argv0: &str, cwd: &Path) -> Option<ProgramInfo> {
    let path = find_program(argv0, cwd)?;
    let path = path.canonicalize().unwrap_or(path);
    let (bytes, sha256) = hash_file(&path).ok()?;
    Some(ProgramInfo {
        path: path.to_string_lossy().into_owned(),
        bytes,
        sha256,
    })
}

fn sanitize_name(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim_matches('.').to_owned();
    if s.is_empty() { "run".to_owned() } else { s }
}

struct Tee {
    bytes: u64,
    sha256: String,
    echo_failed: bool,
    write_error: Option<String>,
}

fn tee(
    mut src: impl Read,
    mut echo: Option<Box<dyn Write + Send>>,
    file: Option<File>,
) -> io::Result<Tee> {
    let mut file = file.map(BufWriter::new);
    let mut buf = vec![0u8; 64 * 1024];
    let mut h = Sha256::new();
    let mut total = 0u64;
    let mut echo_failed = false;
    let mut write_error = None;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let chunk = &buf[..n];
        h.update(chunk);
        total += n as u64;
        if let Some(f) = &mut file
            && write_error.is_none()
            && let Err(e) = f.write_all(chunk)
        {
            write_error = Some(e.to_string());
        }
        if let Some(out) = &mut echo
            && (out.write_all(chunk).is_err() || out.flush().is_err())
        {
            echo = None;
            echo_failed = true;
        }
    }
    if let Some(mut f) = file
        && write_error.is_none()
        && let Err(e) = f.flush()
    {
        write_error = Some(e.to_string());
    }
    Ok(Tee {
        bytes: total,
        sha256: hex(&h.finalize()),
        echo_failed,
        write_error,
    })
}

pub struct RunSpec {
    pub argv: Vec<String>,
    /// Absolute working directory for the command.
    pub cwd: PathBuf,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub name: Option<String>,
    /// Absolute state directory; records go to `<state_dir>/runs/`.
    pub state_dir: PathBuf,
    pub extra_env: Vec<String>,
    pub store_streams: bool,
    pub git: bool,
    pub python: bool,
    pub rerun_of: Option<String>,
    pub echo: bool,
}

pub struct RunOutcome {
    pub record: RunRecord,
    pub path: PathBuf,
}

impl RunOutcome {
    /// Exit status for `prov run`: the command's own failure first, then prov's findings.
    pub fn exit_code(&self) -> u8 {
        let e = &self.record.exit;
        if !e.success {
            return match (e.code, e.signal) {
                (Some(c), _) => u8::try_from(c & 0xff).ok().filter(|c| *c != 0).unwrap_or(1),
                (None, Some(s)) => u8::try_from(128 + s).unwrap_or(1),
                _ => 1,
            };
        }
        u8::from(
            self.record
                .findings
                .iter()
                .any(|f| f.severity == Severity::Error),
        )
    }
}

pub fn execute(spec: &RunSpec) -> Result<RunOutcome> {
    let Some(argv0) = spec.argv.first() else {
        bail!("no command given; put it after `--`");
    };
    let resolve = |p: &str| spec.cwd.join(p);
    let mut inputs = Vec::new();
    for p in &spec.inputs {
        let snap = snapshot(&resolve(p));
        match &snap {
            Snapshot::Missing => bail!("input {p} not found (relative to {})", spec.cwd.display()),
            Snapshot::Unreadable { error } => bail!("input {p} cannot be read: {error}"),
            _ => {}
        }
        inputs.push(InputEntry {
            path: p.clone(),
            state: snap,
            modified_by_run: false,
            after: None,
        });
    }
    let outputs_before: Vec<Snapshot> =
        spec.outputs.iter().map(|p| snapshot(&resolve(p))).collect();

    let mut allow: Vec<String> = DEFAULT_ENV.iter().map(|s| (*s).to_owned()).collect();
    allow.extend(spec.extra_env.iter().cloned());
    let vars = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)));
    let (env, env_redacted) = select_env(vars, &allow);
    let git = if spec.git {
        git_state(&spec.cwd, &spec.state_dir)
    } else {
        json!({"status": "skipped", "reason": "--no-git"})
    };
    let mut tools = BTreeMap::new();
    tools.insert(
        "uv".to_owned(),
        first_line(Command::new("uv").arg("--version")),
    );
    tools.insert(
        "git".to_owned(),
        first_line(Command::new("git").arg("--version")),
    );
    if spec.python {
        tools.insert(
            "python".to_owned(),
            first_line(
                Command::new("uv")
                    .args(["run", "--no-project", "python", "--version"])
                    .current_dir(&spec.cwd),
            ),
        );
    }
    let program = program_info(argv0, &spec.cwd);

    let runs = spec.state_dir.join("runs");
    fs::create_dir_all(&runs).with_context(|| format!("cannot create {}", runs.display()))?;
    let name = sanitize_name(spec.name.as_deref().unwrap_or_else(|| {
        Path::new(argv0)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("run")
    }));
    let started = jiff::Timestamp::now();
    let stamp = format!(
        "{}.{:03}Z",
        started.strftime("%Y%m%dT%H%M%S"),
        started.subsec_millisecond()
    );
    let mut id = format!("{stamp}-{name}");
    let mut n = 1;
    let record_path = loop {
        let p = runs.join(format!("{id}.json"));
        match OpenOptions::new().write(true).create_new(true).open(&p) {
            Ok(_) => break p,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                n += 1;
                id = format!("{stamp}-{name}-{n}");
            }
            Err(e) => return Err(e).with_context(|| format!("cannot create {}", p.display())),
        }
    };
    let stream_file = |ext: &str| -> Result<(Option<File>, Option<String>)> {
        if !spec.store_streams {
            return Ok((None, None));
        }
        let rel = format!("{id}.{ext}");
        let f = File::create(runs.join(&rel))
            .with_context(|| format!("cannot create {}", runs.join(&rel).display()))?;
        Ok((Some(f), Some(rel)))
    };
    let (out_file, out_rel) = stream_file("stdout")?;
    let (err_file, err_rel) = stream_file("stderr")?;

    let clock = Instant::now();
    let child = Command::new(argv0)
        .args(&spec.argv[1..])
        .current_dir(&spec.cwd)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            for p in [Some(format!("{id}.json")), out_rel, err_rel]
                .into_iter()
                .flatten()
            {
                let _ = fs::remove_file(runs.join(p));
            }
            bail!("cannot start {argv0}: {e}");
        }
    };
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let echo = spec.echo;
    let t_out = std::thread::spawn(move || {
        tee(
            stdout,
            echo.then(|| Box::new(io::stdout()) as Box<dyn Write + Send>),
            out_file,
        )
    });
    let t_err = std::thread::spawn(move || {
        tee(
            stderr,
            echo.then(|| Box::new(io::stderr()) as Box<dyn Write + Send>),
            err_file,
        )
    });
    let status = child.wait().context("waiting for the command")?;
    let out_tee = t_out
        .join()
        .expect("stdout thread panicked")
        .context("reading stdout")?;
    let err_tee = t_err
        .join()
        .expect("stderr thread panicked")
        .context("reading stderr")?;
    let duration_ms = clock.elapsed().as_millis() as u64;
    let ended = jiff::Timestamp::now();

    #[cfg(unix)]
    let signal = std::os::unix::process::ExitStatusExt::signal(&status);
    #[cfg(not(unix))]
    let signal: Option<i32> = None;

    let mut findings = Vec::new();
    if !status.success() {
        findings.push(Finding::new(
            "command-failed",
            Severity::Warn,
            &id,
            match (status.code(), signal) {
                (Some(c), _) => format!("command exited with status {c}"),
                (None, Some(s)) => format!("command was killed by signal {s}"),
                _ => "command failed".to_owned(),
            },
        ));
    }
    for (label, t) in [("stdout", &out_tee), ("stderr", &err_tee)] {
        if t.echo_failed {
            findings.push(Finding::new(
                "echo-failed",
                Severity::Warn,
                &id,
                format!(
                    "could not pass {label} through to the terminal; it was still hashed and stored"
                ),
            ));
        }
        if let Some(e) = &t.write_error {
            findings.push(Finding::new(
                "stream-not-stored",
                Severity::Error,
                &id,
                format!("could not store {label}: {e}; its hash and size are still recorded"),
            ));
        }
    }
    for input in &mut inputs {
        let now = snapshot(&resolve(&input.path));
        if now != input.state {
            findings.push(
                Finding::new(
                    "input-modified",
                    Severity::Error,
                    &input.path,
                    format!(
                        "input changed during the run: {} before, {} after",
                        input.state.describe(),
                        now.describe()
                    ),
                )
                .with_data(json!({"run": id})),
            );
            input.modified_by_run = true;
            input.after = Some(now);
        }
    }
    let mut outputs = Vec::new();
    for (p, before) in spec.outputs.iter().zip(outputs_before) {
        let state = snapshot(&resolve(p));
        match &state {
            Snapshot::Missing => findings.push(Finding::new(
                "output-missing",
                Severity::Error,
                p,
                "declared output does not exist after the run",
            )),
            Snapshot::Unreadable { error } => findings.push(Finding::new(
                "output-unreadable",
                Severity::Error,
                p,
                format!("declared output cannot be read: {error}"),
            )),
            _ if state == before => findings.push(Finding::new(
                "output-unchanged",
                Severity::Warn,
                p,
                "output has the same content as before the run; the run may not have written it",
            )),
            _ => {}
        }
        outputs.push(OutputEntry {
            path: p.clone(),
            before,
            state,
        });
    }

    let record = RunRecord {
        schema: SCHEMA.to_owned(),
        id: id.clone(),
        name,
        tool: "prov".to_owned(),
        tool_version: crate::VERSION.to_owned(),
        argv: spec.argv.clone(),
        cwd: spec.cwd.to_string_lossy().into_owned(),
        started_at: started.to_string(),
        ended_at: ended.to_string(),
        duration_ms,
        exit: ExitInfo {
            success: status.success(),
            code: status.code(),
            signal,
        },
        env,
        env_redacted,
        env_allowlist: allow,
        git,
        tools,
        program,
        inputs,
        outputs,
        stdout: StreamInfo {
            bytes: out_tee.bytes,
            sha256: out_tee.sha256,
            path: out_rel,
        },
        stderr: StreamInfo {
            bytes: err_tee.bytes,
            sha256: err_tee.sha256,
            path: err_rel,
        },
        findings,
        rerun_of: spec.rerun_of.clone(),
    };
    let partial = runs.join(format!("{id}.json.partial"));
    let mut data = serde_json::to_vec_pretty(&record)?;
    data.push(b'\n');
    fs::write(&partial, &data).with_context(|| format!("cannot write {}", partial.display()))?;
    fs::rename(&partial, &record_path)
        .with_context(|| format!("cannot write {}", record_path.display()))?;
    Ok(RunOutcome {
        record,
        path: record_path,
    })
}

pub fn read_record(path: &Path) -> Result<RunRecord> {
    let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let v: Value = serde_json::from_slice(&data)
        .with_context(|| format!("{}: invalid JSON", path.display()))?;
    check_schema(&v, "rf.run", 1, &path.display().to_string())?;
    serde_json::from_value(v)
        .with_context(|| format!("{}: invalid rf.run/1 record", path.display()))
}

fn tree_changes(a: &[TreeEntry], b: &[TreeEntry]) -> Value {
    let am: BTreeMap<&str, &TreeEntry> = a.iter().map(|e| (e.path(), e)).collect();
    let bm: BTreeMap<&str, &TreeEntry> = b.iter().map(|e| (e.path(), e)).collect();
    let removed: Vec<&str> = am
        .keys()
        .filter(|k| !bm.contains_key(*k))
        .copied()
        .collect();
    let added: Vec<&str> = bm
        .keys()
        .filter(|k| !am.contains_key(*k))
        .copied()
        .collect();
    let changed: Vec<&str> = am
        .iter()
        .filter(|(k, v)| bm.get(*k).is_some_and(|w| w != *v))
        .map(|(k, _)| *k)
        .collect();
    json!({"added": added, "removed": removed, "changed": changed})
}

fn drift(rule: &str, subject: &str, expected: &Snapshot, now: &Snapshot) -> Finding {
    let mut data = json!({"expected": expected.sha256(), "actual": now.sha256()});
    if let (Snapshot::Dir { files: a, .. }, Snapshot::Dir { files: b, .. }) = (expected, now) {
        data["files"] = tree_changes(a, b);
    }
    Finding::new(
        rule,
        Severity::Error,
        subject,
        format!("recorded {}, now {}", expected.describe(), now.describe()),
    )
    .with_data(data)
}

/// Re-hashes a record's inputs, outputs, stored streams and program.
pub fn verify_record(path: &Path, root: Option<&Path>) -> Result<Report> {
    let rec = read_record(path)?;
    let base = root
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(&rec.cwd));
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut report = Report::default();
    let (mut ok, mut bad, mut skipped) = (0u64, 0u64, 0u64);
    for i in &rec.inputs {
        let expected = i.after.as_ref().unwrap_or(&i.state);
        let now = snapshot(&base.join(&i.path));
        if &now == expected {
            ok += 1;
        } else {
            bad += 1;
            let rule = if now == Snapshot::Missing {
                "input-missing"
            } else {
                "input-drift"
            };
            report.push(drift(rule, &i.path, expected, &now));
        }
    }
    for o in &rec.outputs {
        if matches!(o.state, Snapshot::Missing | Snapshot::Unreadable { .. }) {
            skipped += 1;
            report.push(Finding::new(
                "output-unchecked",
                Severity::Warn,
                &o.path,
                format!(
                    "the run left no readable output ({}); nothing to verify",
                    o.state.describe()
                ),
            ));
            continue;
        }
        let now = snapshot(&base.join(&o.path));
        if now == o.state {
            ok += 1;
        } else {
            bad += 1;
            let rule = if now == Snapshot::Missing {
                "output-missing"
            } else {
                "output-drift"
            };
            report.push(drift(rule, &o.path, &o.state, &now));
        }
    }
    for (label, s) in [("stdout", &rec.stdout), ("stderr", &rec.stderr)] {
        let Some(p) = &s.path else {
            skipped += 1;
            report.push(Finding::new(
                "stream-unchecked",
                Severity::Info,
                &rec.id,
                format!("{label} was not stored; only its recorded hash is known"),
            ));
            continue;
        };
        match hash_file(&dir.join(p)) {
            Ok((n, h)) if h == s.sha256 && n == s.bytes => ok += 1,
            Ok((n, h)) => {
                bad += 1;
                report.push(Finding::new("stream-drift", Severity::Error, p, format!("stored {label} differs from the record: {n} bytes, sha256 {} (recorded {} bytes, {})", &h[..12], s.bytes, &s.sha256[..12.min(s.sha256.len())])));
            }
            Err(e) => {
                bad += 1;
                report.push(Finding::new(
                    "stream-missing",
                    Severity::Error,
                    p,
                    format!("stored {label} cannot be read: {e}"),
                ));
            }
        }
    }
    if let Some(prog) = &rec.program {
        match hash_file(Path::new(&prog.path)) {
            Ok((_, h)) if h == prog.sha256 => ok += 1,
            Ok(_) => report.push(Finding::new(
                "program-changed",
                Severity::Warn,
                &prog.path,
                "the executable differs from the one recorded",
            )),
            Err(e) => report.push(Finding::new(
                "program-changed",
                Severity::Warn,
                &prog.path,
                format!("the recorded executable cannot be read: {e}"),
            )),
        }
    }
    report.push(
        Finding::new(
            "run-verify-summary",
            Severity::Info,
            &rec.id,
            format!("{ok} ok, {bad} drifted or missing, {skipped} unchecked (inputs, outputs, streams and program, against {})", base.display()),
        )
        .with_data(json!({"ok": ok, "drifted": bad, "unchecked": skipped, "root": base})),
    );
    Ok(report)
}

/// Whether a declared path stays inside the run directory.
fn contained(p: &str) -> bool {
    let path = Path::new(p);
    if path.is_absolute() {
        return false;
    }
    let mut depth = 0i32;
    for c in path.components() {
        match c {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::CurDir => {}
            _ => return false,
        }
    }
    true
}

/// Copies a file or directory tree, recreating symlinks rather than following them.
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    let meta = fs::metadata(from).with_context(|| format!("cannot read {}", from.display()))?;
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    if meta.is_file() {
        fs::copy(from, to)
            .with_context(|| format!("cannot copy {} to {}", from.display(), to.display()))?;
        return Ok(());
    }
    for e in walkdir::WalkDir::new(from).follow_links(false) {
        let e = e?;
        let rel = e.path().strip_prefix(from)?;
        let dest = to.join(rel);
        let ft = e.file_type();
        if ft.is_dir() {
            fs::create_dir_all(&dest)?;
        } else if ft.is_symlink() {
            let target = fs::read_link(e.path())?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &dest)?;
            #[cfg(not(unix))]
            bail!(
                "cannot recreate symlink {} on this platform",
                e.path().display()
            );
        } else if ft.is_file() {
            fs::copy(e.path(), &dest)
                .with_context(|| format!("cannot copy {}", e.path().display()))?;
        }
    }
    Ok(())
}

pub struct RerunOptions {
    pub record: PathBuf,
    pub in_place: bool,
    pub scratch: Option<PathBuf>,
    pub compare: bool,
    pub tol: Tolerance,
    pub state_dir: PathBuf,
    pub echo: bool,
    pub store_streams: bool,
    pub git: bool,
}

/// Reruns a recorded command and compares its outputs with the recorded ones.
pub fn rerun(opts: &RerunOptions) -> Result<(Report, RunOutcome)> {
    let rec = read_record(&opts.record)?;
    let base = PathBuf::from(&rec.cwd);
    let mut report = Report::default();
    let now = jiff::Timestamp::now();
    let stamp = format!(
        "{}.{:03}Z",
        now.strftime("%Y%m%dT%H%M%S"),
        now.subsec_millisecond()
    );
    let work = opts.scratch.clone().unwrap_or_else(|| {
        opts.state_dir
            .join("reruns")
            .join(format!("{}-{stamp}", rec.id))
    });
    if work.exists() && fs::read_dir(&work)?.next().is_some() {
        bail!("{} exists and is not empty", work.display());
    }
    fs::create_dir_all(&work).with_context(|| format!("cannot create {}", work.display()))?;
    let work = work.canonicalize()?;

    let (cwd, baselines): (PathBuf, Vec<PathBuf>) = if opts.in_place {
        let dir = work.join("baseline");
        let mut paths = Vec::new();
        for (i, o) in rec.outputs.iter().enumerate() {
            let src = base.join(&o.path);
            let name = Path::new(&o.path)
                .file_name()
                .map(|n| n.to_owned())
                .unwrap_or_else(|| "output".into());
            let dest = dir.join(i.to_string()).join(name);
            if src.exists() {
                copy_tree(&src, &dest)?;
            }
            paths.push(dest);
        }
        (base.clone(), paths)
    } else {
        if let Some(o) = rec.outputs.iter().find(|o| !contained(&o.path)) {
            bail!(
                "output {} lies outside the run directory, so a scratch rerun would write the original; use --in-place",
                o.path
            );
        }
        for i in &rec.inputs {
            if contained(&i.path) {
                copy_tree(&base.join(&i.path), &work.join(&i.path))?;
            } else {
                report.push(Finding::new(
                    "input-not-isolated",
                    Severity::Warn,
                    &i.path,
                    "input lies outside the run directory; the rerun reads the original",
                ));
            }
        }
        for o in &rec.outputs {
            if let Some(parent) = work.join(&o.path).parent() {
                fs::create_dir_all(parent)?;
            }
        }
        (
            work.clone(),
            rec.outputs.iter().map(|o| base.join(&o.path)).collect(),
        )
    };
    let base_str = base.to_string_lossy();
    for a in rec.argv.iter().skip(1) {
        if !opts.in_place && Path::new(a).is_absolute() && a.starts_with(base_str.as_ref()) {
            report.push(Finding::new("argv-absolute-path", Severity::Warn, a, "argument is an absolute path into the original run directory; the rerun may read or write the original"));
        }
    }
    for i in &rec.inputs {
        let at = if contained(&i.path) {
            cwd.join(&i.path)
        } else {
            base.join(&i.path)
        };
        let now = snapshot(&at);
        if now != i.state {
            let mut f = drift("input-drift", &i.path, &i.state, &now);
            f.message = format!(
                "rerun input differs from what the recorded run read ({}); the rerun is not a faithful reproduction",
                f.message
            );
            report.push(f);
            if i.modified_by_run {
                report.push(Finding::new(
                    "input-modified-by-original-run",
                    Severity::Warn,
                    &i.path,
                    "the recorded run changed this input, so its pre-run content is not available",
                ));
            }
        }
    }
    let spec = RunSpec {
        argv: rec.argv.clone(),
        cwd: cwd.clone(),
        inputs: rec.inputs.iter().map(|i| i.path.clone()).collect(),
        outputs: rec.outputs.iter().map(|o| o.path.clone()).collect(),
        name: Some(format!("{}-rerun", rec.name)),
        state_dir: opts.state_dir.clone(),
        extra_env: rec
            .env_allowlist
            .iter()
            .filter(|p| !DEFAULT_ENV.contains(&p.as_str()))
            .cloned()
            .collect(),
        store_streams: opts.store_streams,
        git: opts.git,
        python: rec.tools.contains_key("python"),
        rerun_of: Some(rec.id.clone()),
        echo: opts.echo,
    };
    let outcome = execute(&spec)?;
    if outcome.record.exit.success != rec.exit.success || outcome.record.exit.code != rec.exit.code
    {
        report.push(Finding::new(
            "exit-status-differs",
            Severity::Error,
            &outcome.record.id,
            format!(
                "recorded exit {:?}, rerun exit {:?}",
                rec.exit.code, outcome.record.exit.code
            ),
        ));
    }
    let (mut same, mut close, mut differ) = (0u64, 0u64, 0u64);
    for ((o, new), baseline) in rec
        .outputs
        .iter()
        .zip(&outcome.record.outputs)
        .zip(&baselines)
    {
        let baseline_ok = snapshot(baseline) == o.state;
        let fs = compare_output(
            &o.path,
            &o.state,
            &new.state,
            baseline,
            &cwd.join(&new.path),
            baseline_ok,
            opts.compare,
            opts.tol,
        );
        for f in &fs {
            match f.rule.as_str() {
                "output-identical" => same += 1,
                "output-equal-within-tolerance" => close += 1,
                _ if f.severity == Severity::Error => differ += 1,
                _ => {}
            }
        }
        report.extend(fs);
    }
    report.push(
        Finding::new(
            "rerun-summary",
            Severity::Info,
            &outcome.record.id,
            format!(
                "rerun of {} in {}: {same} outputs identical, {close} equal within tolerance (rtol {}, atol {}), {differ} differ; record {}",
                rec.id,
                cwd.display(),
                opts.tol.rtol,
                opts.tol.atol,
                outcome.path.display()
            ),
        )
        .with_data(json!({"rerun_of": rec.id, "cwd": cwd, "record": outcome.path, "identical": same, "within_tolerance": close, "differ": differ, "rtol": opts.tol.rtol, "atol": opts.tol.atol})),
    );
    Ok((report, outcome))
}

#[allow(clippy::too_many_arguments)]
fn compare_output(
    path: &str,
    recorded: &Snapshot,
    new: &Snapshot,
    baseline: &Path,
    produced: &Path,
    baseline_ok: bool,
    structural: bool,
    tol: Tolerance,
) -> Vec<Finding> {
    match (recorded, new) {
        (Snapshot::Missing, Snapshot::Missing) => vec![Finding::new(
            "output-not-produced",
            Severity::Info,
            path,
            "neither the recorded run nor the rerun produced this output",
        )],
        (Snapshot::Missing | Snapshot::Unreadable { .. }, _) => vec![Finding::new(
            "output-new",
            Severity::Warn,
            path,
            format!(
                "the recorded run left {}, the rerun produced {}",
                recorded.describe(),
                new.describe()
            ),
        )],
        (_, Snapshot::Missing) => vec![Finding::new(
            "output-missing",
            Severity::Error,
            path,
            "the rerun did not produce this output",
        )],
        (_, Snapshot::Unreadable { error }) => vec![Finding::new(
            "output-unreadable",
            Severity::Error,
            path,
            format!("rerun output cannot be read: {error}"),
        )],
        (Snapshot::File { sha256: a, .. }, Snapshot::File { sha256: b, .. }) => {
            vec![compare_file(
                path,
                a,
                b,
                baseline,
                produced,
                baseline_ok,
                structural,
                tol,
            )]
        }
        (Snapshot::Dir { files: a, .. }, Snapshot::Dir { files: b, .. }) => {
            let am: BTreeMap<&str, &TreeEntry> = a.iter().map(|e| (e.path(), e)).collect();
            let bm: BTreeMap<&str, &TreeEntry> = b.iter().map(|e| (e.path(), e)).collect();
            let keys: BTreeSet<&str> = am.keys().chain(bm.keys()).copied().collect();
            let mut out = Vec::new();
            for k in keys {
                let subject = format!("{path}/{k}");
                match (am.get(k), bm.get(k)) {
                    (Some(_), None) => out.push(Finding::new(
                        "output-missing",
                        Severity::Error,
                        &subject,
                        "the rerun did not produce this file",
                    )),
                    (None, Some(_)) => out.push(Finding::new(
                        "output-new",
                        Severity::Warn,
                        &subject,
                        "the rerun produced a file the recorded run did not",
                    )),
                    (
                        Some(TreeEntry::File { sha256: x, .. }),
                        Some(TreeEntry::File { sha256: y, .. }),
                    ) => {
                        out.push(compare_file(
                            &subject,
                            x,
                            y,
                            &baseline.join(k),
                            &produced.join(k),
                            baseline_ok,
                            structural,
                            tol,
                        ));
                    }
                    (Some(x), Some(y)) if x == y => out.push(Finding::new(
                        "output-identical",
                        Severity::Info,
                        &subject,
                        "identical symlink",
                    )),
                    _ => out.push(Finding::new(
                        "output-kind-changed",
                        Severity::Error,
                        &subject,
                        "entry type or symlink target differs",
                    )),
                }
            }
            out
        }
        _ => vec![Finding::new(
            "output-kind-changed",
            Severity::Error,
            path,
            format!(
                "recorded {}, rerun produced {}",
                recorded.describe(),
                new.describe()
            ),
        )],
    }
}

#[allow(clippy::too_many_arguments)]
fn compare_file(
    subject: &str,
    recorded: &str,
    new: &str,
    baseline: &Path,
    produced: &Path,
    baseline_ok: bool,
    structural: bool,
    tol: Tolerance,
) -> Finding {
    if recorded == new {
        return Finding::new(
            "output-identical",
            Severity::Info,
            subject,
            format!("byte-identical (sha256 {})", &new[..12]),
        );
    }
    let bytes_differ = || {
        Finding::new(
            "output-bytes-differ",
            Severity::Error,
            subject,
            format!(
                "bytes differ: recorded sha256 {}, rerun {}",
                &recorded[..12],
                &new[..12]
            ),
        )
    };
    let Some(kind) = Kind::for_path(Path::new(subject)).filter(|_| structural) else {
        return bytes_differ();
    };
    if !baseline_ok {
        let mut f = bytes_differ();
        f.message.push_str(&format!(
            "; the recorded {} output no longer exists unchanged, so values were not compared",
            kind.name()
        ));
        return f;
    }
    let (a, b) = match (fs::read(baseline), fs::read(produced)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            let mut f = bytes_differ();
            f.message.push_str(&format!("; values not compared: {e}"));
            return f;
        }
    };
    // The baseline file was matched against the record as a whole; recheck this file's bytes.
    if sha256_bytes(&a) != recorded {
        let mut f = bytes_differ();
        f.message
            .push_str("; the baseline file does not match the record, so values were not compared");
        return f;
    }
    match compare::compare(kind, &a, &b, tol) {
        Ok(d) if d.total == 0 => Finding::new(
            "output-equal-within-tolerance",
            Severity::Info,
            subject,
            format!(
                "bytes differ but every {} value matches within rtol {}, atol {}",
                kind.name(),
                tol.rtol,
                tol.atol
            ),
        ),
        Ok(d) => {
            let first = d
                .kept
                .first()
                .map(|x| format!("; first at {}: {} vs {}", x.location, x.baseline, x.rerun))
                .unwrap_or_default();
            Finding::new(
                "output-values-differ",
                Severity::Error,
                subject,
                format!(
                    "{} {} values differ beyond rtol {}, atol {}{first}",
                    d.total,
                    kind.name(),
                    tol.rtol,
                    tol.atol
                ),
            )
            .with_data(json!({"total": d.total, "differences": d.kept}))
        }
        Err(e) => {
            let mut f = bytes_differ();
            f.message.push_str(&format!("; values not compared: {e}"));
            f
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_filter() {
        let vars = [
            ("PATH", "/bin"),
            ("UV_INDEX_URL", "https://user:pw@example.invalid/simple"),
            ("UV_CACHE_DIR", "/cache"),
            ("UV_PUBLISH_TOKEN", "t"),
            ("OPENAI_API_KEY", "k"),
            ("MY_SETTING", "x"),
            ("GH_AUTH", "x"),
        ]
        .map(|(k, v)| (k.to_owned(), v.to_owned()));
        let allow: Vec<String> = ["PATH", "UV_*", "OPENAI_API_KEY", "GH_*"]
            .map(String::from)
            .to_vec();
        let (kept, redacted) = select_env(vars, &allow);
        assert_eq!(kept.keys().collect::<Vec<_>>(), ["PATH", "UV_CACHE_DIR"]);
        assert_eq!(
            redacted,
            [
                "GH_AUTH",
                "OPENAI_API_KEY",
                "UV_INDEX_URL",
                "UV_PUBLISH_TOKEN"
            ]
        );
    }

    #[test]
    fn containment() {
        assert!(contained("a/b"));
        assert!(contained("a/../b"));
        assert!(!contained("../b"));
        assert!(!contained("a/../../b"));
        assert!(!contained("/etc/passwd"));
    }

    #[test]
    fn url_credentials() {
        assert!(has_url_credentials("https://u:p@host/x"));
        assert!(!has_url_credentials("https://host/x?a=b@c"));
        assert!(!has_url_credentials("/usr/bin"));
    }
}
