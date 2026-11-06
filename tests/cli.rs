//! End-to-end tests through the `prov` binary on synthetic fixtures.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn prov(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_prov"))
        .args(args)
        .current_dir(cwd)
        .env("PROV_TEST_TOKEN", "do-not-record")
        .env("UV_PUBLISH_PASSWORD", "do-not-record")
        .env("UV_CACHE_DIR", "/cache")
        .output()
        .expect("run prov")
}

fn findings(out: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad line {l:?}: {e}")))
        .collect()
}

fn rules(f: &[Value]) -> Vec<(String, String)> {
    f.iter()
        .filter(|x| x["rule"] != "verify-summary" && x["rule"] != "diff-summary")
        .map(|x| {
            (
                x["rule"].as_str().unwrap().to_owned(),
                x["subject"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn summary<'a>(f: &'a [Value], rule: &str) -> &'a Value {
    &f.iter().find(|x| x["rule"] == rule).expect(rule)["data"]
}

fn write(path: &Path, data: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}

/// A small tree: a.txt, b.bin, sub/c.txt, sub/d.txt (same bytes as a.txt).
fn tree(root: &Path) {
    write(&root.join("a.txt"), b"alpha\n");
    write(&root.join("b.bin"), &[0u8, 1, 2, 3, 4, 5, 6, 7]);
    write(&root.join("sub/c.txt"), b"gamma gamma\n");
    write(&root.join("sub/d.txt"), b"alpha\n");
}

fn build(dir: &Path, root: &Path, name: &str) -> PathBuf {
    let m = dir.join(name);
    let out = prov(
        dir,
        &[
            "manifest",
            "build",
            root.to_str().unwrap(),
            "-o",
            m.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    m
}

fn verify(dir: &Path, m: &Path) -> Output {
    prov(
        dir,
        &[
            "manifest",
            "verify",
            m.to_str().unwrap(),
            "--format",
            "jsonl",
        ],
    )
}

#[test]
fn build_is_deterministic_and_verifies_clean() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("data");
    tree(&root);
    let m = build(t.path(), &root, "m.jsonl");
    let lines: Vec<Value> = fs::read_to_string(&m)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines[0]["type"], "header");
    assert_eq!(lines[0]["schema"], "rf.manifest/1");
    let paths: Vec<&str> = lines[1..5]
        .iter()
        .map(|l| l["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["a.txt", "b.bin", "sub/c.txt", "sub/d.txt"]);
    assert_eq!(lines[1]["sha256"], prov::hash::sha256_bytes(b"alpha\n"));
    assert_eq!(lines[1]["bytes"], 6);
    assert_eq!(lines[5]["type"], "summary");
    assert_eq!(lines[5]["files"], 4);
    assert_eq!(lines[5]["bytes"], 6 + 8 + 12 + 6);

    let out = verify(t.path(), &m);
    assert_eq!(out.status.code(), Some(0));
    let f = findings(&out);
    assert!(rules(&f).is_empty(), "{f:?}");
    assert_eq!(summary(&f, "verify-summary")["ok"], 4);

    // Same tree without mtimes gives identical records.
    let m1 = t.path().join("n1.jsonl");
    let m2 = t.path().join("n2.jsonl");
    for m in [&m1, &m2] {
        let o = prov(
            t.path(),
            &[
                "manifest",
                "build",
                root.to_str().unwrap(),
                "--no-mtime",
                "-o",
                m.to_str().unwrap(),
            ],
        );
        assert!(o.status.success());
    }
    let body = |p: &Path| {
        fs::read_to_string(p)
            .unwrap()
            .lines()
            .skip(1)
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(body(&m1), body(&m2));
}

#[test]
fn sha256_matches_reference_value() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("d");
    write(&root.join("abc"), b"abc");
    let m = build(t.path(), &root, "m.jsonl");
    let text = fs::read_to_string(m).unwrap();
    assert!(text.contains("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

#[test]
fn verify_detects_changed_truncated_missing_new_and_moved() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("data");
    tree(&root);
    write(&root.join("e.txt"), b"epsilon\n");
    let m = build(t.path(), &root, "m.jsonl");

    // Same size, different content.
    write(&root.join("b.bin"), &[0u8, 1, 2, 3, 4, 5, 6, 8]);
    // Truncated.
    write(&root.join("sub/c.txt"), b"gamma");
    // Missing.
    fs::remove_file(root.join("a.txt")).unwrap();
    // Renamed.
    fs::rename(root.join("e.txt"), root.join("sub/e-renamed.txt")).unwrap();
    // New.
    write(&root.join("new.txt"), b"new\n");

    let out = verify(t.path(), &m);
    assert_eq!(out.status.code(), Some(1));
    let f = findings(&out);
    let mut r = rules(&f);
    r.sort();
    assert_eq!(
        r,
        [
            ("file-changed".into(), "b.bin".into()),
            ("file-changed".into(), "sub/c.txt".into()),
            ("file-missing".into(), "a.txt".into()),
            ("file-moved".into(), "e.txt".into()),
            ("file-new".into(), "new.txt".into()),
        ]
    );
    let changed = f.iter().find(|x| x["subject"] == "b.bin").unwrap();
    assert_eq!(changed["data"]["actual"]["bytes"], 8);
    let moved = f.iter().find(|x| x["rule"] == "file-moved").unwrap();
    assert_eq!(moved["data"]["to"], "sub/e-renamed.txt");
    let s = summary(&f, "verify-summary");
    assert_eq!(
        (
            s["ok"].as_u64(),
            s["changed"].as_u64(),
            s["missing"].as_u64()
        ),
        (Some(1), Some(2), Some(1))
    );
    assert_eq!((s["moved"].as_u64(), s["new"].as_u64()), (Some(1), Some(1)));
}

#[test]
fn truncated_manifest_is_detected() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("data");
    tree(&root);
    let m = build(t.path(), &root, "m.jsonl");
    let text = fs::read_to_string(&m).unwrap();
    let cut: Vec<&str> = text.lines().take(3).collect();
    fs::write(&m, cut.join("\n") + "\n").unwrap();
    let out = verify(t.path(), &m);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        rules(&findings(&out))
            .iter()
            .any(|(r, _)| r == "manifest-truncated")
    );
}

#[test]
fn excludes_and_output_inside_root() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("data");
    tree(&root);
    write(&root.join("cache/x.tmp"), b"x");
    write(&root.join("sub/cache/keep.txt"), b"y");
    let m = root.join("manifest.jsonl");
    let out = prov(
        t.path(),
        &[
            "manifest",
            "build",
            "data",
            "--exclude",
            "/cache",
            "-o",
            m.to_str().unwrap(),
        ],
    );
    assert!(out.status.success());
    let text = fs::read_to_string(&m).unwrap();
    assert!(!text.contains("\"cache/x.tmp\""));
    assert!(text.contains("\"sub/cache/keep.txt\""));
    assert!(!text.contains("\"path\":\"manifest.jsonl\""));
    // The excluded directory and the manifest itself are not reported as new.
    let out = verify(t.path(), &m);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn diff_reports_changes_and_moves() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("data");
    tree(&root);
    let a = build(t.path(), &root, "a.jsonl");
    write(&root.join("b.bin"), b"changed!");
    fs::rename(root.join("sub/c.txt"), root.join("c-moved.txt")).unwrap();
    fs::remove_file(root.join("a.txt")).unwrap();
    write(&root.join("z.txt"), b"zeta");
    let b = build(t.path(), &root, "b.jsonl");
    let out = prov(
        t.path(),
        &[
            "manifest",
            "diff",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--format",
            "jsonl",
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    let mut r = rules(&findings(&out));
    r.sort();
    assert_eq!(
        r,
        [
            ("diff-added".into(), "z.txt".into()),
            ("diff-changed".into(), "b.bin".into()),
            ("diff-moved".into(), "sub/c.txt".into()),
            ("diff-removed".into(), "a.txt".into()),
        ]
    );
}

#[test]
fn import_foreign_manifest() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("sources");
    write(&root.join("papers/p1.pdf"), b"%PDF-1 one");
    write(&root.join("papers/p2.pdf"), b"%PDF-1 two");
    write(&root.join("text/p1.txt"), b"one");
    let sha = |b: &[u8]| prov::hash::sha256_bytes(b);
    let doc = serde_json::json!({
        "snapshot_date": "2026-01-01",
        "files": [
            {"reference": 1, "path": "papers/p1.pdf", "bytes": 10, "sha256": sha(b"%PDF-1 one")},
            {"reference": 2, "path": "papers/p2.pdf", "bytes": 10, "sha256": sha(b"%PDF-1 XXX")},
            {"reference": 1, "path": "text/p1.txt", "bytes": 3, "sha256": null},
            {"reference": 3, "path": "papers/gone.pdf", "bytes": 5, "sha256": sha(b"gone!")},
            {"reference": 4, "path": null, "sha256": null, "error": "download failed"}
        ]
    });
    let json = root.join("source-manifest.json");
    fs::write(&json, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    let out_m = t.path().join("imported.jsonl");
    let out = prov(
        t.path(),
        &[
            "manifest",
            "import",
            json.to_str().unwrap(),
            "-o",
            out_m.to_str().unwrap(),
            "--format",
            "jsonl",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let f = findings(&out);
    let mut r = rules(&f);
    r.retain(|(x, _)| x != "import-mapping" && x != "new-files-unchecked");
    r.sort();
    assert_eq!(r.len(), 4, "{r:?}");
    assert_eq!(r[0], ("file-changed".into(), "papers/p2.pdf".into()));
    assert_eq!(r[1], ("file-missing".into(), "papers/gone.pdf".into()));
    assert_eq!(r[2], ("hash-unchecked".into(), "text/p1.txt".into()));
    assert_eq!(r[3].0, "record-without-path");
    let missing = f.iter().find(|x| x["rule"] == "file-missing").unwrap();
    assert_eq!(missing["evidence"][0]["locator"], "/files/3 (path, sha256)");
    let s = summary(&f, "verify-summary");
    assert_eq!(s["ok"], 1);
    assert_eq!(s["new_files_checked"], false);

    // The converted manifest verifies the same way, with --root.
    let out = prov(
        t.path(),
        &[
            "manifest",
            "verify",
            out_m.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--format",
            "jsonl",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(summary(&findings(&out), "verify-summary")["changed"], 1);
}

#[test]
fn import_rejects_conflicting_duplicates_and_needs_records() {
    let t = tempfile::tempdir().unwrap();
    write(&t.path().join("a"), b"a");
    let h = prov::hash::sha256_bytes(b"a");
    let doc = serde_json::json!({"sources": [
        {"file": "a", "sha256": h},
        {"file": "a", "sha256": prov::hash::sha256_bytes(b"b")}
    ]});
    let json = t.path().join("m.json");
    fs::write(&json, doc.to_string()).unwrap();
    let out = prov(
        t.path(),
        &["manifest", "import", "m.json", "--format", "jsonl"],
    );
    let f = findings(&out);
    assert!(
        rules(&f)
            .iter()
            .any(|(r, s)| r == "manifest-conflict" && s == "a")
    );
    assert_eq!(summary(&f, "verify-summary")["ok"], 1);

    fs::write(&json, r#"{"list": [{"name": "x"}]}"#).unwrap();
    let out = prov(t.path(), &["manifest", "import", "m.json"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn dupes_groups_identical_files() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("d");
    write(&root.join("x/a.pdf"), b"same bytes here");
    write(&root.join("y/a-copy.pdf"), b"same bytes here");
    write(&root.join("z/a-again.pdf"), b"same bytes here");
    write(&root.join("other.pdf"), b"same size  here"); // same size, different bytes
    write(&root.join("note.txt"), b"same bytes here");
    write(&root.join("empty1"), b"");
    write(&root.join("empty2"), b"");
    let out = prov(
        t.path(),
        &["dupes", "d", "--include", "*.pdf", "--format", "jsonl"],
    );
    assert_eq!(out.status.code(), Some(0));
    let f = findings(&out);
    let groups: Vec<&Value> = f
        .iter()
        .filter(|x| x["rule"] == "duplicate-group")
        .collect();
    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0]["data"]["paths"],
        serde_json::json!(["x/a.pdf", "y/a-copy.pdf", "z/a-again.pdf"])
    );
    assert_eq!(groups[0]["data"]["reclaimable_bytes"], 30);
    let s = summary(&f, "dupes-summary");
    assert_eq!(s["scanned_files"], 4);
    assert_eq!(s["reclaimable_bytes"], 30);
    // Without the filter the .txt joins the group; empty files are ignored.
    let out = prov(t.path(), &["dupes", "d", "--format", "jsonl"]);
    let s = summary(&findings(&out), "dupes-summary").clone();
    assert_eq!(s["groups"], 1);
    assert_eq!(s["reclaimable_bytes"], 45);
    // Size floor.
    let out = prov(
        t.path(),
        &["dupes", "d", "--min-size", "1KB", "--format", "jsonl"],
    );
    assert_eq!(
        summary(&findings(&out), "dupes-summary")["scanned_files"],
        0
    );
    // Nothing was deleted.
    assert!(root.join("y/a-copy.pdf").exists());
}

#[cfg(unix)]
#[test]
fn dupes_counts_hard_links_once() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().join("d");
    write(&root.join("a"), b"0123456789");
    fs::hard_link(root.join("a"), root.join("b")).unwrap();
    write(&root.join("c"), b"0123456789");
    let out = prov(t.path(), &["dupes", "d", "--format", "jsonl"]);
    let f = findings(&out);
    let g = &f.iter().find(|x| x["rule"] == "duplicate-group").unwrap()["data"];
    assert_eq!(g["distinct"], 2);
    assert_eq!(g["reclaimable_bytes"], 10);
}

fn record(state: &Path) -> (PathBuf, Value) {
    let runs = state.join("runs");
    let mut recs: Vec<PathBuf> = fs::read_dir(&runs)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    recs.sort();
    let p = recs.pop().unwrap();
    let v = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    (p, v)
}

#[cfg(unix)]
#[test]
fn run_records_inputs_outputs_streams_and_filters_secrets() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    write(&d.join("in/data.csv"), b"x\n1\n2\n");
    let out = prov(
        d,
        &[
            "run",
            "--in",
            "in/data.csv",
            "--out",
            "out.txt",
            "--name",
            "count",
            "--env",
            "PROV_*",
            "--env",
            "UV_*",
            "--state-dir",
            "state",
            "--no-git",
            "--",
            "sh",
            "-c",
            "wc -l < in/data.csv > out.txt; echo done; echo warn >&2",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "done\n");
    let (path, rec) = record(&d.join("state"));
    assert!(
        path.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .ends_with("-count.json")
    );
    assert_eq!(rec["schema"], "rf.run/1");
    assert_eq!(rec["argv"][0], "sh");
    assert_eq!(rec["exit"]["code"], 0);
    assert_eq!(rec["inputs"][0]["state"]["kind"], "file");
    assert_eq!(rec["inputs"][0]["modified_by_run"], false);
    assert_eq!(rec["outputs"][0]["before"]["kind"], "missing");
    assert_eq!(
        rec["outputs"][0]["state"]["sha256"],
        prov::hash::sha256_bytes(&fs::read(d.join("out.txt")).unwrap())
    );
    assert_eq!(rec["stdout"]["bytes"], 5);
    assert_eq!(rec["stdout"]["sha256"], prov::hash::sha256_bytes(b"done\n"));
    let stored = path
        .parent()
        .unwrap()
        .join(rec["stdout"]["path"].as_str().unwrap());
    assert_eq!(fs::read(stored).unwrap(), b"done\n");
    assert_eq!(rec["stderr"]["bytes"], 5);
    // Secrets: names with TOKEN/PASSWORD are dropped even when allowlisted; values never stored.
    assert_eq!(rec["env"]["UV_CACHE_DIR"], "/cache");
    assert!(rec["env"].get("PROV_TEST_TOKEN").is_none());
    assert!(rec["env"].get("UV_PUBLISH_PASSWORD").is_none());
    let redacted: Vec<&str> = rec["env_redacted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(redacted.contains(&"PROV_TEST_TOKEN") && redacted.contains(&"UV_PUBLISH_PASSWORD"));
    assert!(!fs::read_to_string(&path).unwrap().contains("do-not-record"));

    // Verify: clean, then drift.
    let v = prov(
        d,
        &["run", "verify", path.to_str().unwrap(), "--format", "jsonl"],
    );
    assert_eq!(
        v.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&v.stdout)
    );
    write(&d.join("out.txt"), b"tampered\n");
    let v = prov(
        d,
        &["run", "verify", path.to_str().unwrap(), "--format", "jsonl"],
    );
    assert_eq!(v.status.code(), Some(1));
    assert!(rules(&findings(&v)).contains(&("output-drift".into(), "out.txt".into())));
}

#[cfg(unix)]
#[test]
fn run_flags_inputs_modified_by_the_run_and_propagates_failure() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    write(&d.join("data/a.txt"), b"a\n");
    let out = prov(
        d,
        &[
            "run",
            "--in",
            "data",
            "--state-dir",
            "s",
            "--no-git",
            "--no-streams",
            "--",
            "sh",
            "-c",
            "echo b > data/b.txt",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let (_, rec) = record(&d.join("s"));
    assert_eq!(rec["inputs"][0]["modified_by_run"], true);
    assert_eq!(rec["inputs"][0]["state"]["kind"], "dir");
    assert_eq!(
        rec["inputs"][0]["after"]["files"].as_array().unwrap().len(),
        2
    );
    assert_eq!(rec["findings"][0]["rule"], "input-modified");
    assert!(rec["stdout"]["path"].is_null());

    let out = prov(
        d,
        &[
            "run",
            "--state-dir",
            "s",
            "--no-git",
            "--",
            "sh",
            "-c",
            "exit 3",
        ],
    );
    assert_eq!(out.status.code(), Some(3));
    let out = prov(
        d,
        &["run", "--in", "nope", "--state-dir", "s", "--", "true"],
    );
    assert_eq!(out.status.code(), Some(2));
}

#[cfg(unix)]
#[test]
fn rerun_compares_with_tolerance() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    // The script's output depends on a file outside the declared inputs, so a rerun can drift.
    write(&d.join("noise"), b"0.0001");
    write(
        &d.join("make.sh"),
        b"n=$(cat \"$NOISE\"); printf '{\"loss\": 0.5%s, \"name\": \"m\"}' \"${n#0.}\" > out/m.json\nprintf 'step,loss\\n1,0.25%s\\n' \"${n#0.}\" > out/m.csv\n",
    );
    fs::create_dir_all(d.join("out")).unwrap();
    let noise = d.join("noise");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_prov"))
            .args(args)
            .current_dir(d)
            .env("NOISE", &noise)
            .output()
            .unwrap()
    };
    let out = run(&[
        "run",
        "--in",
        "make.sh",
        "--out",
        "out/m.json",
        "--out",
        "out/m.csv",
        "--env",
        "NOISE",
        "--state-dir",
        "s",
        "--no-git",
        "--",
        "sh",
        "make.sh",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let (rec_path, rec) = record(&d.join("s"));
    assert_eq!(rec["env"]["NOISE"], noise.to_str().unwrap());
    let rec_path = rec_path.to_str().unwrap().to_owned();

    // Identical rerun in a scratch copy.
    let out = run(&[
        "run",
        "rerun",
        &rec_path,
        "--compare",
        "--state-dir",
        "s",
        "--quiet",
        "--format",
        "jsonl",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let f = findings(&out);
    assert_eq!(
        f.iter().filter(|x| x["rule"] == "output-identical").count(),
        2
    );

    // Perturb the numbers: values differ exactly, but match within rtol 1e-3.
    fs::write(&noise, b"0.0002").unwrap();
    let out = run(&[
        "run",
        "rerun",
        &rec_path,
        "--compare",
        "--state-dir",
        "s",
        "--quiet",
        "--format",
        "jsonl",
    ]);
    assert_eq!(out.status.code(), Some(1));
    let f = findings(&out);
    let json_diff = f
        .iter()
        .find(|x| x["rule"] == "output-values-differ" && x["subject"] == "out/m.json")
        .unwrap();
    assert_eq!(json_diff["data"]["differences"][0]["location"], "/loss");
    let csv_diff = f
        .iter()
        .find(|x| x["rule"] == "output-values-differ" && x["subject"] == "out/m.csv")
        .unwrap();
    assert_eq!(
        csv_diff["data"]["differences"][0]["location"],
        "row 2, column 2 (loss)"
    );

    let out = run(&[
        "run",
        "rerun",
        &rec_path,
        "--compare",
        "--rtol",
        "1e-3",
        "--state-dir",
        "s",
        "--quiet",
        "--format",
        "jsonl",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(
        findings(&out)
            .iter()
            .filter(|x| x["rule"] == "output-equal-within-tolerance")
            .count(),
        2
    );

    // Without --compare a byte difference is an error even when values are close.
    let out = run(&[
        "run",
        "rerun",
        &rec_path,
        "--state-dir",
        "s",
        "--quiet",
        "--format",
        "jsonl",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        findings(&out)
            .iter()
            .any(|x| x["rule"] == "output-bytes-differ")
    );

    // In place: originals are overwritten, compared against the saved baseline.
    let out = run(&[
        "run",
        "rerun",
        &rec_path,
        "--in-place",
        "--compare",
        "--rtol",
        "1e-3",
        "--state-dir",
        "s",
        "--quiet",
        "--format",
        "jsonl",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        fs::read_to_string(d.join("out/m.json"))
            .unwrap()
            .contains("0.50002")
    );

    // Lineage sees the original and the reruns.
    let out = run(&["lineage", "s/runs"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("rerun of"), "{text}");
    let out = run(&["lineage", "s/runs", "--format", "dot"]);
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("digraph lineage"));
}

#[cfg(unix)]
#[test]
fn lineage_links_producers_and_consumers() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    write(&d.join("raw.txt"), b"3\n1\n2\n");
    let go = |args: &[&str]| {
        let o = prov(d, args);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    };
    go(&[
        "run",
        "--in",
        "raw.txt",
        "--out",
        "sorted.txt",
        "--name",
        "sort",
        "--state-dir",
        "s",
        "--no-git",
        "--",
        "sh",
        "-c",
        "sort raw.txt > sorted.txt",
    ]);
    go(&[
        "run",
        "--in",
        "sorted.txt",
        "--out",
        "top.txt",
        "--name",
        "top",
        "--state-dir",
        "s",
        "--no-git",
        "--",
        "sh",
        "-c",
        "head -1 sorted.txt > top.txt",
    ]);
    let out = prov(d, &["lineage", "s/runs"]);
    let text = String::from_utf8_lossy(&out.stdout);
    let sort_id = text
        .lines()
        .find(|l| l.starts_with("run ") && l.contains("-sort"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    let top_id = text
        .lines()
        .find(|l| l.starts_with("run ") && l.contains("-top"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    assert!(text.contains(&format!("-> consumed by {top_id}")), "{text}");
    assert!(
        text.contains(&format!("<- produced by {sort_id}")),
        "{text}"
    );
    assert!(text.contains("raw.txt") && text.contains("(no recorded producer)"));
}

#[test]
fn import_nested_and_prefixed_records_and_finds_root() {
    let t = tempfile::tempdir().unwrap();
    let project = t.path().join("project");
    write(&project.join("docs/a.pdf"), b"pdf a");
    write(&project.join("docs/a.txt"), b"text a");
    write(&project.join("code/run.py"), b"print(1)");
    let sha = |b: &[u8]| prov::hash::sha256_bytes(b);
    // Paths relative to the project root, in a manifest two levels below it.
    let doc = serde_json::json!({
        "code_path": "code/run.py", "code_sha256": sha(b"print(1)"),
        "sources": [
            {"key": "a", "artifacts": [
                {"path": "docs/a.pdf", "sha256": sha(b"pdf a"), "text_path": "docs/a.txt", "text_sha256": sha(b"text a")}
            ], "raw_line_sha256": sha(b"line")},
            {"key": "b", "hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "path": "docs/sha1-only"}
        ]
    });
    let json = project.join("notes/session/sources.json");
    write(&json, doc.to_string().as_bytes());
    let j = json.to_str().unwrap();

    let out = prov(t.path(), &["manifest", "import", j, "--format", "jsonl"]);
    assert_eq!(out.status.code(), Some(1));
    let f = findings(&out);
    let hint = f
        .iter()
        .find(|x| x["rule"] == "root-hint")
        .expect("root hint");
    assert!(
        hint["message"]
            .as_str()
            .unwrap()
            .contains("3 of 3 paths exist")
    );
    assert_eq!(summary(&f, "verify-summary")["missing"], 3);

    let out = prov(
        t.path(),
        &["manifest", "import", j, "--find-root", "--format", "jsonl"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let f = findings(&out);
    assert_eq!(summary(&f, "verify-summary")["ok"], 3);
    let orphan = f.iter().find(|x| x["rule"] == "hash-without-path").unwrap();
    assert!(
        orphan["message"]
            .as_str()
            .unwrap()
            .contains("raw_line_sha256")
    );
    let mappings: Vec<&str> = f
        .iter()
        .filter(|x| x["rule"] == "import-mapping")
        .map(|x| x["data"]["records"].as_str().unwrap())
        .collect();
    assert_eq!(
        mappings,
        ["/", "/sources/*/artifacts/*", "/sources/*/artifacts/*"]
    );

    // Explicit selection with a wildcard pointer.
    let out = prov(
        t.path(),
        &[
            "manifest",
            "import",
            j,
            "--records",
            "/sources/*/artifacts",
            "--root",
            project.to_str().unwrap(),
            "--format",
            "jsonl",
        ],
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(summary(&findings(&out), "verify-summary")["ok"], 2);
}

#[cfg(unix)]
#[test]
fn run_records_git_state_without_the_state_dir() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let git = |args: &[&str]| {
        let o = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
            .args(args)
            .current_dir(d)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_owned()
    };
    git(&["init", "-q"]);
    write(&d.join("tracked.txt"), b"v1\n");
    git(&["add", "tracked.txt"]);
    git(&["commit", "-q", "-m", "init"]);
    let head = git(&["rev-parse", "HEAD"]);
    write(&d.join("tracked.txt"), b"v2\n");
    let out = prov(d, &["run", "--state-dir", ".research", "--", "true"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // A second run must not see the first run's record as a dirty path.
    let out = prov(d, &["run", "--state-dir", ".research", "--", "true"]);
    assert!(out.status.success());
    let (_, rec) = record(&d.join(".research"));
    let g = &rec["git"];
    assert_eq!(g["status"], "ok");
    assert_eq!(g["head"], head.as_str());
    assert_eq!(g["dirty"], true);
    assert_eq!(
        g["dirty_paths"],
        serde_json::json!([{"status": " M", "path": "tracked.txt"}])
    );
    assert_eq!(g["dirty_sha256"].as_str().unwrap().len(), 64);
}

fn has(f: &[Value], rule: &str, subject: &str) -> bool {
    f.iter()
        .any(|x| x["rule"] == rule && x["subject"] == subject)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn import_hash_match_wins_over_size_fields() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    write(&d.join("a.txt"), b"alpha\n");
    let h = prov::hash::sha256_bytes(b"alpha\n");
    // `size` and `length` are not byte counts; `bytes` is, but a matching hash still wins.
    let j = format!(
        r#"[{{"path": "a.txt", "sha256": "{h}", "size": 999, "length": 3}},
            {{"file": "a.txt", "hash": "{h}", "bytes": 7}}]"#
    );
    write(&d.join("m.json"), j.as_bytes());
    let out = prov(d, &["manifest", "import", "m.json", "--format", "jsonl"]);
    let f = findings(&out);
    assert_eq!(out.status.code(), Some(0), "{f:?}");
    assert_eq!(summary(&f, "verify-summary")["ok"], 1);
    assert_eq!(summary(&f, "verify-summary")["changed"], 0);
    // Only one record (same path, same hash); the size came from the second object.
    assert!(has(&f, "bytes-mismatch", "a.txt"), "{f:?}");
    // --bytes-field alone is honoured for generically paired objects.
    let j = format!(r#"[{{"path": "a.txt", "sha256": "{h}", "n": 999}}]"#);
    write(&d.join("n.json"), j.as_bytes());
    let out = prov(
        d,
        &[
            "manifest",
            "import",
            "n.json",
            "--bytes-field",
            "n",
            "--format",
            "jsonl",
        ],
    );
    let f = findings(&out);
    assert_eq!(out.status.code(), Some(0), "{f:?}");
    assert!(has(&f, "bytes-mismatch", "a.txt"), "{f:?}");
}

#[test]
fn import_root_is_stored_absolute() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    write(&d.join("data/a.txt"), b"alpha\n");
    let h = prov::hash::sha256_bytes(b"alpha\n");
    write(
        &d.join("m.json"),
        format!(r#"[{{"path": "a.txt", "sha256": "{h}"}}]"#).as_bytes(),
    );
    let out = prov(
        d,
        &[
            "manifest", "import", "m.json", "--root", "data", "-o", "m.jsonl",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    fs::create_dir_all(d.join("elsewhere")).unwrap();
    let out = prov(
        &d.join("elsewhere"),
        &["manifest", "verify", "../m.jsonl", "--format", "jsonl"],
    );
    let f = findings(&out);
    assert_eq!(out.status.code(), Some(0), "{f:?}");
    assert_eq!(summary(&f, "verify-summary")["ok"], 1);
}

#[test]
fn import_output_is_sorted_with_summary_and_pointer_origins() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let h = |s: &str| prov::hash::sha256_bytes(s.as_bytes());
    for n in ["b", "a", "c"] {
        write(&d.join(n), n.as_bytes());
    }
    let j = format!(
        r#"{{"files": [{{"path": "b", "sha256": "{}"}}, {{"path": "a", "sha256": "{}"}}, {{"path": "c", "sha256": "{}"}}]}}"#,
        h("b"),
        h("a"),
        h("c")
    );
    write(&d.join("m.json"), j.as_bytes());
    let out = prov(d, &["manifest", "import", "m.json", "-o", "m.jsonl"]);
    assert_eq!(out.status.code(), Some(0));
    let lines: Vec<Value> = fs::read_to_string(d.join("m.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let paths: Vec<&str> = lines[1..4]
        .iter()
        .map(|l| l["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["a", "b", "c"]);
    assert_eq!(lines[1]["origin"], "/files/1");
    assert_eq!(
        lines[1]["origin_fields"],
        serde_json::json!(["path", "sha256"])
    );
    assert_eq!(lines[4]["type"], "summary");
    assert_eq!(lines[4]["files"], 3);
    // The summary makes truncation detectable.
    let cut: Vec<String> = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, l)| l.to_string())
        .collect();
    write(&d.join("cut.jsonl"), (cut.join("\n") + "\n").as_bytes());
    let out = prov(d, &["manifest", "verify", "cut.jsonl", "--format", "jsonl"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        rules(&findings(&out))
            .iter()
            .any(|(r, _)| r == "manifest-truncated")
    );
}

#[test]
fn import_explicit_fields_report_entries_without_paths() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    write(&d.join("a"), b"a");
    let h = prov::hash::sha256_bytes(b"a");
    let j = format!(r#"[{{"p": "a", "h": "{h}"}}, {{"h": "{h}"}}, {{"p": null, "h": "{h}"}}]"#);
    write(&d.join("m.json"), j.as_bytes());
    let out = prov(
        d,
        &[
            "manifest",
            "import",
            "m.json",
            "--path-field",
            "p",
            "--hash-field",
            "h",
            "--format",
            "jsonl",
        ],
    );
    let f = findings(&out);
    assert_eq!(out.status.code(), Some(0), "{f:?}");
    assert_eq!(summary(&f, "hash-without-path")["/*/h"], 1);
    assert_eq!(
        summary(&f, "record-without-path")["pointers"],
        serde_json::json!(["/2"])
    );
}

#[test]
fn import_pointer_fields_index_arrays_and_records_must_be_pointers() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    write(&d.join("a"), b"a");
    let h = prov::hash::sha256_bytes(b"a");
    let j = format!(r#"{{"items": [{{"files": [{{"p": "a"}}], "h": {{"v": "{h}"}}}}]}}"#);
    write(&d.join("m.json"), j.as_bytes());
    let args = [
        "manifest",
        "import",
        "m.json",
        "--path-field",
        "/files/0/p",
        "--hash-field",
        "/h/v",
    ];
    let mut ok = args.to_vec();
    ok.extend(["--records", "/items", "--format", "jsonl"]);
    let out = prov(d, &ok);
    let f = findings(&out);
    assert_eq!(out.status.code(), Some(0), "{f:?}");
    assert_eq!(summary(&f, "verify-summary")["ok"], 1);
    let mut bad = args.to_vec();
    bad.extend(["--records", "items"]);
    let out = prov(d, &bad);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("not a JSON pointer"));
}

#[test]
fn manifest_build_failure_keeps_the_existing_output() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    write(&d.join("m.jsonl"), b"previous\n");
    let out = prov(d, &["manifest", "build", "missing-dir", "-o", "m.jsonl"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(fs::read(d.join("m.jsonl")).unwrap(), b"previous\n");
    assert!(!d.join("m.jsonl.partial").exists());
    // A successful build inside the root does not list its own partial file.
    tree(&d.join("r"));
    let out = prov(d, &["manifest", "build", "r", "-o", "r/m.jsonl"]);
    assert_eq!(out.status.code(), Some(0));
    let text = fs::read_to_string(d.join("r/m.jsonl")).unwrap();
    assert!(!text.contains("\"path\":\"m.jsonl"), "{text}");
}

#[test]
fn build_include_and_exclude_directories() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    tree(&d.join("r"));
    let out = prov(
        d,
        &["manifest", "build", "r", "--include", "sub", "--no-mtime"],
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\"path\":\"sub/c.txt") && !text.contains("\"path\":\"a.txt"),
        "{text}"
    );
    let out = prov(
        d,
        &["manifest", "build", "r", "--exclude", "sub/", "--no-mtime"],
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("\"path\":\"sub/") && text.contains("\"path\":\"a.txt"),
        "{text}"
    );
}

#[test]
fn diff_treats_unrecorded_paths_as_unchecked() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    tree(&d.join("r"));
    let a = build(d, &d.join("r"), "a.jsonl");
    // b: the same tree, but a.txt could not be read when b was built.
    let mut lines: Vec<Value> = fs::read_to_string(&a)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|l: &Value| l["path"] != "a.txt")
        .collect();
    let s = lines.last_mut().unwrap();
    s["files"] = (s["files"].as_u64().unwrap() - 1).into();
    s["errors"] = serde_json::json!([{"path": "a.txt", "reason": "permission denied"}]);
    let b: Vec<String> = lines.iter().map(Value::to_string).collect();
    write(&d.join("b.jsonl"), (b.join("\n") + "\n").as_bytes());
    let out = prov(
        d,
        &[
            "manifest", "diff", "a.jsonl", "b.jsonl", "--format", "jsonl",
        ],
    );
    let f = findings(&out);
    assert_eq!(out.status.code(), Some(0), "{f:?}");
    assert!(has(&f, "diff-unchecked", "a.txt"), "{f:?}");
    assert!(!has(&f, "diff-removed", "a.txt"));
}
