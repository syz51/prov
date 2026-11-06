use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use prov::compare::Tolerance;
use prov::finding::{Finding, Format, Report, Severity, write_text};
use prov::{config, dupes, import, lineage, manifest, run, walk};

/// Provenance for research artifacts and experiment runs.
#[derive(Parser)]
#[command(name = "prov", version, about, long_about = None)]
struct Cli {
    /// research.toml to use instead of searching upward from the current directory.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build, verify, diff and import content manifests (rf.manifest/1).
    Manifest {
        #[command(subcommand)]
        cmd: ManifestCmd,
    },
    /// Find groups of byte-identical files. Never deletes or links anything.
    Dupes(DupesArgs),
    /// Run a command and record it (rf.run/1); or verify or rerun a record.
    Run(RunArgs),
    /// Show which runs produced and consumed which files.
    Lineage(LineageArgs),
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Hash every file under a directory into an rf.manifest/1 JSON Lines file.
    Build {
        dir: PathBuf,
        /// Leave out matching paths (repeatable). A pattern without `/` matches a name at any
        /// depth; with `/` it matches the path relative to DIR; a leading `/` anchors it.
        #[arg(long, value_name = "GLOB")]
        exclude: Vec<String>,
        /// Record only matching files (repeatable).
        #[arg(long, value_name = "GLOB")]
        include: Vec<String>,
        /// Do not record modification times.
        #[arg(long)]
        no_mtime: bool,
        /// Output file; standard output when omitted.
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    /// Check files against a manifest: missing, changed, moved and new files.
    Verify {
        manifest: PathBuf,
        /// Directory the manifest's paths are relative to (default: the header's root).
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t)]
        format: Format,
    },
    /// Compare two manifests.
    Diff {
        a: PathBuf,
        b: PathBuf,
        #[arg(long, value_enum, default_value_t)]
        format: Format,
    },
    /// Read a foreign JSON manifest and verify it (and optionally write it as rf.manifest/1).
    Import {
        json: PathBuf,
        /// JSON pointer to a record or an array of records, `*` matching every member
        /// (repeatable); every object in the document when omitted.
        #[arg(long, value_name = "POINTER")]
        records: Vec<String>,
        /// Field holding the file path (a name, or a JSON pointer starting with `/`).
        #[arg(long)]
        path_field: Option<String>,
        /// Field holding the SHA-256.
        #[arg(long)]
        hash_field: Option<String>,
        /// Field holding the size in bytes.
        #[arg(long)]
        bytes_field: Option<String>,
        /// Directory the paths are relative to (default: the JSON file's directory).
        #[arg(long)]
        root: Option<PathBuf>,
        /// Use as the root whichever of the JSON file's directory and its ancestors holds the
        /// most listed paths.
        #[arg(long, conflicts_with = "root")]
        find_root: bool,
        /// Write the imported records as rf.manifest/1.
        #[arg(short, long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// Only convert; do not check the files.
        #[arg(long)]
        no_verify: bool,
        #[arg(long, value_enum, default_value_t)]
        format: Format,
    },
}

#[derive(Args)]
struct DupesArgs {
    dir: PathBuf,
    /// Consider only matching files (repeatable).
    #[arg(long, value_name = "GLOB")]
    include: Vec<String>,
    /// Leave out matching paths (repeatable).
    #[arg(long, value_name = "GLOB")]
    exclude: Vec<String>,
    /// Ignore files smaller than this (e.g. 1MB = 1000000 bytes, 1MiB = 1048576 bytes).
    #[arg(long, default_value = "1", value_parser = prov::parse_size)]
    min_size: u64,
    #[arg(long, value_enum, default_value_t)]
    format: Format,
}

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
struct RunArgs {
    #[command(subcommand)]
    action: Option<RunAction>,
    #[command(flatten)]
    exec: ExecArgs,
}

#[derive(Args)]
struct ExecArgs {
    /// Input file or directory, hashed before and after the run (repeatable).
    #[arg(long = "in", value_name = "PATH")]
    inputs: Vec<String>,
    /// Output file or directory, hashed after the run (repeatable).
    #[arg(long = "out", value_name = "PATH")]
    outputs: Vec<String>,
    /// Name used in the record id (default: the program's file name).
    #[arg(long)]
    name: Option<String>,
    #[command(flatten)]
    common: CommonRunArgs,
    /// Also record environment variables with this name; a trailing `*` matches a prefix.
    /// Names containing KEY, TOKEN, SECRET, PASS, AUTH, COOKIE, CREDENTIAL or PRIVATE, or with
    /// a PAT or PWD part (`GITHUB_PAT`), are never recorded.
    #[arg(long = "env", value_name = "NAME")]
    env: Vec<String>,
    /// Record `uv run --no-project python --version`.
    #[arg(long)]
    python: bool,
    /// The command, after `--`.
    #[arg(last = true, value_name = "COMMAND")]
    command: Vec<String>,
}

#[derive(Args)]
struct CommonRunArgs {
    /// State directory (default: [project] state_dir from research.toml, else .research).
    #[arg(long, value_name = "DIR")]
    state_dir: Option<PathBuf>,
    /// Hash stdout and stderr but do not store them next to the record.
    #[arg(long)]
    no_streams: bool,
    /// Do not record git state.
    #[arg(long)]
    no_git: bool,
}

#[derive(Subcommand)]
enum RunAction {
    /// Re-hash a record's inputs, outputs and stored streams and report drift.
    Verify {
        record: PathBuf,
        /// Directory the record's relative paths resolve against (default: its cwd).
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t)]
        format: Format,
    },
    /// Rerun a recorded command and compare its outputs with the recorded ones.
    Rerun {
        record: PathBuf,
        /// Compare JSON, JSON Lines, CSV and TSV outputs value by value, not only byte-wise.
        #[arg(long)]
        compare: bool,
        /// Run in the original directory; its outputs are moved to the baseline first.
        #[arg(long)]
        in_place: bool,
        /// Scratch directory for the copy (default: <state_dir>/reruns/<id>-<time>).
        #[arg(long, conflicts_with = "in_place")]
        scratch: Option<PathBuf>,
        /// Relative tolerance: |a - b| <= atol + rtol * |a|, a being the recorded value.
        #[arg(long, default_value_t = 0.0)]
        rtol: f64,
        /// Absolute tolerance.
        #[arg(long, default_value_t = 0.0)]
        atol: f64,
        /// Do not pass the command's output through (with --format jsonl it goes to stderr).
        #[arg(long)]
        quiet: bool,
        #[command(flatten)]
        common: CommonRunArgs,
        #[arg(long, value_enum, default_value_t)]
        format: Format,
    },
}

#[derive(Args)]
struct LineageArgs {
    /// Directory of rf.run/1 records (e.g. .research/runs).
    runs: PathBuf,
    #[arg(long, value_enum, default_value_t)]
    format: LineageFormat,
}

#[derive(Clone, Copy, Default, clap::ValueEnum)]
enum LineageFormat {
    #[default]
    Text,
    Dot,
}

fn emit(report: &Report, format: Format) -> Result<u8> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    report.emit(format, &mut out)?;
    Ok(u8::from(report.has_errors()))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            let mut err = io::stderr().lock();
            let _ = writeln!(err, "prov: error: {e:#}");
            match e.downcast_ref::<run::AfterStart>() {
                // The command ran; 125 keeps prov's failure apart from the command's status.
                Some(after) => {
                    if let Some(record) = &after.record {
                        let _ = writeln!(err, "prov: the unsaved run record follows");
                        let _ = err.write_all(record.as_bytes());
                    }
                    ExitCode::from(125)
                }
                None => ExitCode::from(2),
            }
        }
    }
}

fn dispatch(cli: Cli) -> Result<u8> {
    let cwd = std::env::current_dir().context("cannot read the current directory")?;
    match cli.cmd {
        Cmd::Manifest { cmd } => manifest_cmd(cmd),
        Cmd::Dupes(a) => dupes_cmd(a),
        Cmd::Run(a) => match a.action {
            Some(RunAction::Verify {
                record,
                root,
                format,
            }) => emit(&run::verify_record(&record, root.as_deref())?, format),
            Some(RunAction::Rerun {
                record,
                compare,
                in_place,
                scratch,
                rtol,
                atol,
                quiet,
                common,
                format,
            }) => {
                anyhow::ensure!(
                    rtol >= 0.0 && atol >= 0.0 && rtol.is_finite() && atol.is_finite(),
                    "--rtol and --atol must be finite and non-negative"
                );
                let opts = run::RerunOptions {
                    record,
                    in_place,
                    scratch,
                    compare,
                    tol: Tolerance { rtol, atol },
                    state_dir: absolute(&config::state_dir(
                        &cwd,
                        cli.config.as_deref(),
                        common.state_dir.as_deref(),
                    )?)?,
                    // JSON Lines owns stdout; the command's output goes to stderr instead.
                    echo: match (quiet, format) {
                        (true, _) => run::Echo::Off,
                        (false, Format::Jsonl) => run::Echo::Stderr,
                        (false, Format::Text) => run::Echo::Terminal,
                    },
                    store_streams: !common.no_streams,
                    git: !common.no_git,
                };
                let (report, _) = run::rerun(&opts)?;
                emit(&report, format)
            }
            None => run_cmd(a.exec, &cwd, cli.config.as_deref()),
        },
        Cmd::Lineage(a) => {
            let l = lineage::load(&a.runs)?;
            let text = match a.format {
                LineageFormat::Text => lineage::text(&l, &cwd),
                LineageFormat::Dot => lineage::dot(&l, &cwd),
            };
            io::stdout().write_all(text.as_bytes())?;
            for s in &l.skipped {
                eprintln!("prov: skipped {s}");
            }
            Ok(0)
        }
    }
}

fn absolute(p: &Path) -> Result<PathBuf> {
    Ok(std::path::absolute(p)?)
}

fn run_cmd(a: ExecArgs, cwd: &Path, config_path: Option<&Path>) -> Result<u8> {
    anyhow::ensure!(
        !a.command.is_empty(),
        "no command given; usage: prov run [OPTIONS] -- <COMMAND>..."
    );
    let spec = run::RunSpec {
        argv: a.command,
        cwd: cwd.to_path_buf(),
        inputs: a.inputs,
        outputs: a.outputs,
        name: a.name,
        state_dir: absolute(&config::state_dir(
            cwd,
            config_path,
            a.common.state_dir.as_deref(),
        )?)?,
        extra_env: a.env,
        store_streams: !a.common.no_streams,
        git: !a.common.no_git,
        python: a.python,
        rerun_of: None,
        echo: run::Echo::Terminal,
        exclude: Vec::new(),
    };
    let outcome = run::execute(&spec)?;
    let mut err = io::stderr().lock();
    for f in &outcome.record.findings {
        write!(err, "prov: ")?;
        write_text(f, &mut err)?;
    }
    writeln!(err, "prov: run record {}", outcome.path.display())?;
    Ok(outcome.exit_code())
}

fn manifest_cmd(cmd: ManifestCmd) -> Result<u8> {
    match cmd {
        ManifestCmd::Build {
            dir,
            exclude,
            include,
            no_mtime,
            output,
        } => {
            let opts = manifest::BuildOptions {
                root: dir,
                includes: include,
                excludes: exclude,
                mtime: !no_mtime,
                output: output.clone(),
            };
            let clock = Instant::now();
            let stats = match &output {
                Some(p) => manifest::write_atomic(p, |w| manifest::build(&opts, w))?,
                None => manifest::build(&opts, &mut io::stdout().lock())?,
            };
            let mut err = io::stderr().lock();
            for e in &stats.errors {
                write_text(
                    &Finding::new(
                        "build-error",
                        Severity::Error,
                        &e.path,
                        format!("not recorded: {}", e.reason),
                    ),
                    &mut err,
                )?;
            }
            for e in &stats.special {
                write_text(
                    &Finding::new(
                        "special-file",
                        Severity::Info,
                        &e.path,
                        format!("not recorded: {}", e.reason),
                    ),
                    &mut err,
                )?;
            }
            writeln!(
                err,
                "prov: {} files ({} bytes), {} symlinks, {} errors in {:.2} s{}",
                stats.files,
                stats.bytes,
                stats.symlinks,
                stats.errors.len(),
                clock.elapsed().as_secs_f64(),
                output
                    .map(|p| format!(" -> {}", p.display()))
                    .unwrap_or_default()
            )?;
            Ok(u8::from(!stats.errors.is_empty()))
        }
        ManifestCmd::Verify {
            manifest: path,
            root,
            format,
        } => {
            let m = manifest::read_manifest(&path)?;
            let root = match root {
                Some(r) => r,
                None => match &m.header.root {
                    Some(r) => PathBuf::from(r),
                    None => anyhow::bail!("{}: header has no root; pass --root", path.display()),
                },
            };
            emit(
                &manifest::verify(&m, &root, &path.display().to_string())?,
                format,
            )
        }
        ManifestCmd::Diff { a, b, format } => {
            let (ma, mb) = (manifest::read_manifest(&a)?, manifest::read_manifest(&b)?);
            let mut report = Report::default();
            report.extend(ma.problems.iter().cloned());
            report.extend(mb.problems.iter().cloned());
            report.extend(manifest::diff(&ma, &mb).findings);
            emit(&report, format)
        }
        ManifestCmd::Import {
            json,
            records,
            path_field,
            hash_field,
            bytes_field,
            root,
            find_root,
            output,
            no_verify,
            format,
        } => {
            let opts = import::ImportOptions {
                json: json.clone(),
                records,
                path_field,
                hash_field,
                bytes_field,
                root,
                find_root,
            };
            let (m, mut report) = import::import(&opts)?;
            if let Some(p) = &output {
                manifest::write_atomic(p, |w| manifest::write_manifest(w, &m))?;
            }
            if !no_verify {
                let root = PathBuf::from(m.header.root.clone().unwrap_or_default());
                report.extend(manifest::verify(&m, &root, &json.display().to_string())?.findings);
            }
            emit(&report, format)
        }
    }
}

fn dupes_cmd(a: DupesArgs) -> Result<u8> {
    let filter = walk::Filter::new(&a.include, &a.exclude, a.min_size.max(1))?;
    let (d, report) = dupes::find(&a.dir, &filter)?;
    match a.format {
        Format::Jsonl => return emit(&report, Format::Jsonl),
        Format::Text => {
            let mut out = io::stdout().lock();
            for g in &d.groups {
                writeln!(
                    out,
                    "{} copies x {} bytes, {} reclaimable  sha256 {}",
                    g.paths.len(),
                    g.bytes,
                    g.reclaimable_bytes,
                    prov::hash::short(&g.sha256)
                )?;
                for p in &g.paths {
                    writeln!(out, "  {p}")?;
                }
            }
            for f in report
                .findings
                .iter()
                .filter(|f| f.rule != "duplicate-group")
            {
                write_text(f, &mut out)?;
            }
        }
    }
    Ok(u8::from(report.has_errors()))
}
