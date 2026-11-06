# prov

Provenance for research artifacts and experiment runs. `prov` makes results reproducible
and shows whether their inputs are unchanged:

- **Manifests** (`rf.manifest/1`): SHA-256 of every file in a tree; verify the tree later,
  diff two manifests, or verify a manifest another tool wrote, without converting it by hand.
- **Duplicates**: groups of byte-identical files and the bytes they waste. Never deletes or links.
- **Run records** (`rf.run/1`): a command's argv, environment allowlist, git state, tool
  versions, timing, exit status, input/output hashes and stdout/stderr, with inputs checked
  again after the run.
- **Reruns**: rerun a record in a scratch copy (or in place) and compare outputs byte-wise
  and, for JSON, JSON Lines, CSV and TSV, value by value with numeric tolerance.
- **Lineage**: which runs produced which files and which runs consumed them.

Accuracy rule: a check that passes means the bytes match by SHA-256. Anything `prov` could
not check (a foreign manifest without a hash, an unstored stream, a baseline that has
drifted) is reported as unchecked, never as passing.

## Install

```sh
cargo install --path .
```

Requires Rust 1.99 or newer.

## Commands

All checkers write [`rf.finding/1`](#findings) records: human-readable text by default,
JSON Lines with `--format jsonl`. Exit status: `0` when no finding has severity `error`,
`1` when one does, `2` for usage or I/O failure. `prov run` is the exception: see below.

### `prov manifest build <dir> [-o manifest.jsonl]`

```sh
prov manifest build data/ --exclude '*.tmp' --exclude /cache -o data.manifest.jsonl
```

Hashes every regular file (in parallel, streaming, 256 KiB reads) and records symlinks
without following them. Records are sorted by path (byte order), so two builds of the same
tree differ only in the header's `created_at` and, unless `--no-mtime`, in `mtime`.

Globs (`--exclude`, `--include`, repeatable): a pattern without `/` matches a file or
directory name at any depth (`*.pdf`, `node_modules`); a pattern with `/` matches the path
relative to the root, where `*` also crosses `/` (`docs/tmp/*`); a leading `/` anchors a
pattern at the root (`/cache`). Excluded directories are not descended into. When the
output file lies inside the root it is excluded automatically.

Files that exist but cannot be recorded (unreadable, non-UTF-8 name, changed while being
hashed) are listed in the summary record and make the build exit `1`. Sockets, FIFOs and
devices are listed in the header's `special` field. Empty directories are not recorded.

### `prov manifest verify <manifest> [--root dir]`

```sh
prov manifest verify data.manifest.jsonl
prov manifest verify data.manifest.jsonl --root /mnt/copy/data --format jsonl
```

Paths resolve against `--root`, else the header's `root`. Each listed file's size is
compared first; when it matches, the file is hashed. When the manifest is complete (built
by `prov`), the tree is walked with the header's filters to find files not listed;
a new file with the same content as a missing one is reported as moved.

| Rule | Severity | Meaning |
| --- | --- | --- |
| `file-changed` | error | size or SHA-256 differs (`data.expected`, `data.actual`) |
| `file-missing` | error | listed, not found |
| `file-moved` | error | missing at the listed path; identical content found elsewhere (`data.from`, `data.to`) |
| `file-unreadable` | error | exists but cannot be read, or is not a regular file |
| `symlink-changed` | error | symlink target differs, or no longer a symlink |
| `file-new` | warn | under the root, admitted by the filters, not listed |
| `hash-unchecked` | warn | the manifest lists no SHA-256 for this file; only existence and size were checked |
| `unrecorded-at-build` | warn | the build could not record this path |
| `walk-error` | warn | a directory could not be searched for new files |
| `manifest-truncated` | error | the summary record is missing or its counts disagree with the records |
| `manifest-duplicate-path` | error | a path is listed twice; the first record is used |
| `manifest-invalid` | error | records after the summary |
| `unknown-record` | warn | a record type this version does not know; ignored |
| `new-files-unchecked` | info | the manifest does not claim to list every file, so new files were not looked for |
| `verify-summary` | info | counts: `ok`, `changed`, `missing`, `moved`, `unchecked`, `unreadable`, `new` |

### `prov manifest diff <a> <b>`

Compares two manifests by path. Rules (all `info`, except `diff-unchecked`, which is `warn`):
`diff-changed`, `diff-removed` (only in `a`), `diff-added` (only in `b`), `diff-moved` (a
removed and an added path with the same SHA-256), `diff-unchecked` (a manifest has no hash
for the path), `diff-summary`. Exit status is `0` unless a manifest is malformed.

### `prov manifest import <json>`

```sh
prov manifest import sources/source-manifest.json               # verify in place
prov manifest import sources.json --records /downloads --path-field file -o sources.jsonl
```

Reads a JSON (or JSON Lines) manifest written by another tool and verifies it. A record is
any JSON object, at any depth, that pairs a path field with a SHA-256 field:

- a generic hash field (`sha256`, `sha_256`, `sha256sum`, or `hash`, `checksum`, `digest`
  when they hold a 64-hex value; a `sha256:` prefix is accepted) pairs with the first
  present of `path`, `file`, `local_path`, `file_path`, `filepath`, `relative_path`,
  `project_path`, `retained_file`, `artifact`, and its size with `bytes`, `size`,
  `size_bytes` or `length`;
- `<p>_sha256` pairs with `<p>_path`, `<p>_file` or `<p>_artifact`, and `<p>_bytes` or
  `<p>_size` (so one object can hold `path`/`sha256` and `text_path`/`text_sha256`).

`--path-field`, `--hash-field` and `--bytes-field` replace the pairing with one explicit
pair (a field may be a JSON pointer into the object, such as `/artifact/path`). `--records`
(repeatable) restricts the search to the objects at a JSON pointer, or the objects in the
array there; `*` matches every element or member (`/sources/*/artifacts`). Each pairing
used is reported as an `import-mapping` finding with the pointer pattern and record count.

Paths resolve against `--root`, else the JSON file's directory. When more listed paths
exist under an ancestor directory, a `root-hint` warning names it; `--find-root` uses the
directory among the file's directory and its seven nearest ancestors under which the most
paths exist (the nearest on ties) and reports it as `root-chosen`. One root applies to the
whole file: a manifest that mixes path bases reports the others as missing.

| Rule | Severity | Meaning |
| --- | --- | --- |
| `invalid-hash` | error | a SHA-256 field does not hold 64 hex digits; not checked |
| `manifest-conflict` | error | a path listed again with a different hash or size; the first entry is verified |
| `invalid-bytes` | warn | a size that is not a non-negative integer; size not checked |
| `root-hint` | warn | more paths exist under another directory |
| `record-without-path` | info | objects with a hash field but a null or absent path (for example failed downloads) |
| `hash-without-path` | info | SHA-256 fields with no path field to pair with, by pointer pattern |
| `import-mapping`, `root-chosen` | info | what was read and from where |

Verification then uses the `manifest verify` rules; entries with a null hash are
`hash-unchecked`. Findings carry the entry's JSON pointer and fields as evidence. `-o`
writes the records as an `rf.manifest/1` whose header has `complete: false`;
`--no-verify` only converts. A file in which nothing pairs exits `2`.

### `prov dupes <dir>`

```sh
prov dupes docs/ --include '*.pdf'
prov dupes docs/ --min-size 1MB --format jsonl
```

Groups files by size, hashes only sizes that occur more than once, and groups by SHA-256.
Empty files are ignored (`--min-size` defaults to 1; `1MB` = 10^6 bytes, `1MiB` = 2^20).
Hard links to one file count once when computing `reclaimable_bytes = bytes × (distinct − 1)`.
Symlinks are not followed. Rules: `duplicate-group` (info; `data` has `sha256`, `bytes`,
`paths`, `distinct`, `reclaimable_bytes`), `dupes-summary` (info), `walk-error` and
`file-unreadable` (warn).

### `prov run [options] -- <command>…`

```sh
prov run --in data/train.csv --in scripts/train.py --out results/metrics.json --name train \
  -- uv run --no-project --with numpy==2.3.4 python scripts/train.py
```

1. Hashes every `--in` path (file or directory, following a symlink at the path itself);
   a missing input aborts before the command starts. Snapshots every `--out` path.
2. Records the environment allowlist, git state, `uv --version`, `git --version` (and
   `uv run --no-project python --version` with `--python`), and the SHA-256 of the
   resolved executable.
3. Runs the command with inherited stdin; stdout and stderr pass through to the terminal
   and are hashed, counted and stored next to the record (`--no-streams` keeps only hash and
   count). The command sees pipes, not a terminal.
4. Re-hashes the inputs (`input-modified`, error, when the run changed one) and hashes the
   outputs (`output-missing`, `output-unreadable`: error; `output-unchanged`: warn).
5. Writes `<state_dir>/runs/<UTC time>-<name>.json` atomically and prints its path to stderr.

Exit status: the command's own status when it fails (`128 + signal` when killed), else `1`
when a finding is an error, else `0`; `2` when `prov` itself fails before the command runs.

The state directory is `--state-dir`, else `[project] state_dir` from the nearest
`research.toml` (relative to that file), else `.research` in the current directory.

**Environment.** Recorded by default: `PATH`, `LANG`, `LC_ALL`, `LC_CTYPE`, `LC_NUMERIC`,
`TZ`, `SOURCE_DATE_EPOCH`, `PYTHONHASHSEED`, `PYTHONPATH`, `PYTHONUTF8`,
`PYTHONDONTWRITEBYTECODE`, `VIRTUAL_ENV`, `CONDA_PREFIX`, `UV_*`, `CUDA_VISIBLE_DEVICES`,
`OMP_NUM_THREADS`, `MKL_NUM_THREADS`, `OPENBLAS_NUM_THREADS`, `NUMEXPR_NUM_THREADS`,
`RAYON_NUM_THREADS`, `HF_HUB_OFFLINE`, `HF_DATASETS_OFFLINE`, `TRANSFORMERS_OFFLINE`. Add
names or `PREFIX*` patterns with `--env`. A variable is never recorded, even when
allowlisted, if its name contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `AUTH`,
`COOKIE` or `CREDENTIAL` (any case), or its value embeds URL credentials
(`scheme://user:pass@host`); its name, not its value, goes into `env_redacted`. The command
itself always receives the full environment.

**Git.** From the work tree containing the current directory: `head`, `branch`, and the
dirty paths from `git status --porcelain=v1 --untracked-files=all`, with `dirty_sha256`
hashing each dirty path's status and current content. Paths inside the state directory are
left out. `--no-git` skips this.

### `prov run verify <record> [--root dir]`

Re-hashes the record's inputs (against their post-run state), outputs, stored streams and
the executable. Rules: `input-drift`, `input-missing`, `output-drift`, `output-missing`,
`stream-drift`, `stream-missing` (error); `program-changed`, `output-unchecked` (warn;
the run left no output to check); `stream-unchecked` (info; stream not stored);
`run-verify-summary` (info). Directory drift lists `added`, `removed` and `changed` files.

### `prov run rerun <record> [--compare] [--rtol r] [--atol a] [--in-place | --scratch dir]`

```sh
prov run rerun .research/runs/20261107T030000.123Z-train.json --compare --rtol 1e-6
```

By default the declared inputs are copied into a scratch directory
(`<state_dir>/reruns/<id>-<time>/`, or `--scratch`, which must be empty) at the same
relative paths, and the command runs there; output paths outside the run directory refuse
a scratch rerun. An undeclared file the command reads (a script, a config) is therefore
missing in the scratch copy: declare it with `--in`. With `--in-place` the command runs in
the original directory after the current outputs are copied to
`<state_dir>/reruns/<id>-<time>/baseline/`; the originals are overwritten.

The rerun writes its own record with `rerun_of`. Each output is then compared with the
recorded one:

| Rule | Severity | Meaning |
| --- | --- | --- |
| `output-identical` | info | same SHA-256 |
| `output-equal-within-tolerance` | info | bytes differ, every value matches (`--compare`) |
| `output-values-differ` | error | values beyond tolerance; `data.differences` lists up to 50 with location, baseline and rerun values, `data.total` counts all |
| `output-bytes-differ` | error | bytes differ and values were not compared: not JSON/CSV, no `--compare`, parse failure, or the recorded output no longer exists unchanged |
| `output-missing` | error | the rerun did not produce it |
| `output-kind-changed` | error | file became directory, or similar |
| `output-new` | warn | produced by the rerun only |
| `exit-status-differs` | error | exit code differs from the record |
| `input-drift` | error | an input differs from what the recorded run read: the rerun is not a faithful reproduction |
| `input-modified-by-original-run` | warn | the recorded run changed this input, so its pre-run content is gone |
| `input-not-isolated` | warn | an input outside the run directory is read from its original location |
| `argv-absolute-path` | warn | an argument points into the original directory |
| `rerun-summary` | info | counts and the new record's path |

Structural comparison by extension: `.json`; `.jsonl`/`.ndjson` (line by line); `.csv`,
`.tsv` (cell by cell; the first row names columns in locations). Two numbers `a`
(recorded) and `b` (rerun) are equal when `|a − b| ≤ atol + rtol·|a|`; integers are
differenced exactly, NaN equals NaN, and strings, booleans and nulls compare exactly. Both
tolerances default to 0. A CSV cell is numeric when both sides parse as numbers.

### `prov lineage <runs-dir> [--format text|dot]`

```sh
prov lineage .research/runs
prov lineage .research/runs --format dot | dot -Tsvg > lineage.svg
```

Files are identified by absolute path (record `cwd` joined with the declared path, `..`
resolved lexically) and SHA-256, so a run that consumed an older version of a file is not
linked to the run that produced a newer one. The text view lists each run's inputs (with
the run that produced exactly that content, or other versions' producers) and outputs (with
consuming runs), then a per-file index. Paths under the current directory are shown
relative to it. Unreadable records are skipped with a note on stderr.

## Schemas

Every record carries `schema`. Readers reject an unknown major version and ignore unknown
fields. Timestamps are UTC RFC 3339. Hashes are lower-case hexadecimal SHA-256. Unknown
values are `null`.

### `rf.manifest/1` (JSON Lines)

One header record, then one record per file or symlink sorted by `path`, then one summary
record.

```json
{"schema":"rf.manifest/1","type":"header","root":"/abs/path/data","created_at":"2026-11-07T03:00:00.123456Z","tool":"prov","tool_version":"0.1.0","hash":"sha256","includes":[],"excludes":["*.tmp"],"complete":true}
{"schema":"rf.manifest/1","type":"file","path":"sub/c.txt","bytes":12,"sha256":"…","mtime":"2026-11-06T10:00:00Z"}
{"schema":"rf.manifest/1","type":"symlink","path":"latest","target":"runs/42"}
{"schema":"rf.manifest/1","type":"summary","files":1,"symlinks":1,"bytes":12,"errors":[]}
```

| Field | Record | Meaning |
| --- | --- | --- |
| `root` | header | directory `path` is relative to; `null` when unknown |
| `includes`, `excludes` | header | globs used by the build; verification reuses them to find new files |
| `complete` | header | `true` when every admitted file under `root` is listed (built by `prov`); `false` for imports |
| `special` | header | optional `[{path, reason}]`: sockets, FIFOs, devices not recorded |
| `source` | header | imports only: `{path, sha256, arrays: [{records, path_field, hash_field, bytes_field, entries, with_path, without_path}]}` |
| `path` | file, symlink | relative, `/`-separated |
| `bytes`, `sha256` | file | `null` when the source manifest did not give them |
| `mtime` | file | optional |
| `origin` | file | optional: JSON pointer of the entry in an imported manifest |
| `target` | symlink | link target as stored |
| `files`, `symlinks`, `bytes` | summary | counts used to detect truncation |
| `errors` | summary | `[{path, reason}]` for paths that exist but were not recorded |

### `rf.run/1` (one JSON document per run)

```json
{
  "schema": "rf.run/1",
  "id": "20261107T030000.123Z-train",
  "name": "train",
  "tool": "prov", "tool_version": "0.1.0",
  "argv": ["uv", "run", "--no-project", "--with", "numpy==2.3.4", "python", "train.py"],
  "cwd": "/abs/path/project",
  "started_at": "2026-11-07T03:00:00.123456Z", "ended_at": "2026-11-07T03:01:10.5Z", "duration_ms": 70377,
  "exit": {"success": true, "code": 0, "signal": null},
  "env": {"PATH": "…", "UV_CACHE_DIR": "…"},
  "env_redacted": ["UV_PUBLISH_TOKEN"],
  "env_allowlist": ["PATH", "…"],
  "git": {"status": "ok", "toplevel": "…", "head": "…", "branch": "main", "dirty": true,
          "dirty_paths": [{"status": " M", "path": "train.py"}], "dirty_sha256": "…", "state_dir_excluded": true},
  "tools": {"uv": "uv 0.9.0", "git": "git version 2.50.0", "python": "Python 3.13.5"},
  "program": {"path": "/abs/bin/uv", "bytes": 123, "sha256": "…"},
  "inputs": [{"path": "data", "state": {"kind": "dir", "bytes": 10, "sha256": "…", "files": [{"type": "file", "path": "a.csv", "bytes": 10, "sha256": "…"}]}, "modified_by_run": false, "after": null}],
  "outputs": [{"path": "metrics.json", "before": {"kind": "missing"}, "state": {"kind": "file", "bytes": 52, "sha256": "…"}}],
  "stdout": {"bytes": 1200, "sha256": "…", "path": "20261107T030000.123Z-train.stdout"},
  "stderr": {"bytes": 0, "sha256": "…", "path": "20261107T030000.123Z-train.stderr"},
  "findings": [],
  "rerun_of": null
}
```

| Field | Meaning |
| --- | --- |
| `id` | record file stem: UTC start time to the millisecond, then the name; `-2`, `-3` … on collision |
| `cwd` | absolute working directory; relative `inputs`/`outputs` paths resolve against it |
| `git.status` | `ok`, `none` (not a work tree), `unavailable` (no git), `skipped` (`--no-git`) or `error`, with `reason` when not `ok`; `head` is `null` before the first commit, `branch` when detached |
| `tools` | first line of each tool's version output; `null` when the tool could not be run |
| `program` | the resolved executable `argv[0]`; `null` when not found on `PATH` |
| snapshot `kind` | `file` (`bytes`, `sha256`), `dir` (`bytes`, `sha256`, `files`), `missing`, `unreadable` (`error`) |
| dir `sha256` | SHA-256 of one line per entry in path order: `F <sha256> <bytes> <path>\n` for files, `L <target> <path>\n` for symlinks |
| `inputs[].after` | post-run state when the run changed the input, else `null` |
| `outputs[].before` | state before the run |
| `stdout.path`, `stderr.path` | stored stream relative to the record's directory; `null` with `--no-streams` |
| `findings` | `rf.finding/1` records produced while recording |
| `rerun_of` | id of the record this run reran |

### Findings

`prov` emits `rf.finding/1` records as defined by the research-factory
shared interfaces, with `tool: "prov"`. `subject` is a path relative to the manifest root,
a record id, or a manifest path; `evidence` points into the manifest being checked when that
helps (for imports, the JSON pointer of the entry).

## Limits

- Identity is SHA-256 equality; files are not compared byte by byte after a hash match.
- `dupes` reports logical bytes. Copy-on-write clones (APFS `cp -c`, reflinks) already share
  blocks and are not detected, so the disk space actually freed can be smaller.
- `manifest verify` follows a symlink in place of a listed file and checks its target's content.
- A file modified while being hashed is detected only when its size changes.
- Run records hold absolute paths (`cwd`, `program`, `git.toplevel`) and the recorded
  environment; keep the state directory out of public repositories if that matters.
- Reruns isolate only declared inputs and outputs; a command can still read or write
  anything it names by absolute path.

## Licence

MIT OR Apache-2.0.
