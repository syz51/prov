//! Locating `research.toml` and the state directory it names.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub const DEFAULT_STATE_DIR: &str = ".research";

/// The first `research.toml` in `start` or its ancestors.
pub fn find_config(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|d| d.join("research.toml"))
        .find(|p| p.is_file())
}

/// Absolute state directory: `--state-dir`, else `[project] state_dir` of the config
/// (relative to the config's directory), else `.research` in `cwd`.
pub fn state_dir(cwd: &Path, config: Option<&Path>, flag: Option<&Path>) -> Result<PathBuf> {
    if let Some(d) = flag {
        return Ok(cwd.join(d));
    }
    let config = match config {
        Some(c) => Some(cwd.join(c)),
        None => find_config(cwd),
    };
    let Some(path) = config else {
        return Ok(cwd.join(DEFAULT_STATE_DIR));
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let doc: toml::Table =
        toml::from_str(&text).with_context(|| format!("{}: invalid TOML", path.display()))?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let state = match doc.get("project").and_then(|p| p.get("state_dir")) {
        None => DEFAULT_STATE_DIR,
        Some(v) => v
            .as_str()
            .with_context(|| format!("{}: [project] state_dir must be a string", path.display()))?,
    };
    Ok(dir.join(state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_state_dir_relative_to_config() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(
            t.path().join("research.toml"),
            "[project]\nname = \"x\"\nstate_dir = \"state\"\n",
        )
        .unwrap();
        let sub = t.path().join("a/b");
        std::fs::create_dir_all(&sub).unwrap();
        assert_eq!(state_dir(&sub, None, None).unwrap(), t.path().join("state"));
        assert_eq!(
            state_dir(&sub, None, Some(Path::new("s2"))).unwrap(),
            sub.join("s2")
        );
    }
}
