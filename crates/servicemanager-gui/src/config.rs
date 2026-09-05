//! Persisted GUI preferences (`%APPDATA%\NGSM\config.json`).
//!
//! `parse_config` / `to_json` are the pure, unit-tested core; `load` / `save`
//! wrap them with file IO and are verified manually.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

fn default_config_version() -> u32 {
    1
}

/// Minimum permitted auto-refresh interval, in seconds. Zero would tick every
/// frame and visibly thrash the UI; anything below 1 s isn't useful here.
pub const AUTO_REFRESH_SECS_MIN: u32 = 1;
/// Maximum permitted auto-refresh interval, in seconds (one hour). Keeps the
/// value well clear of the `i32` overflow the UI cast would hit and prevents
/// effectively-disabled-refresh from hand-edited configs.
pub const AUTO_REFRESH_SECS_MAX: u32 = 3600;

/// User preferences persisted between sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// On-disk schema version. Files written by NGSM ≤0.2.0 lack this
    /// field; serde defaults it to 1. Bump when introducing a breaking
    /// change to the on-disk layout.
    #[serde(default = "default_config_version")]
    pub v: u32,
    pub auto_refresh: bool,
    pub auto_refresh_secs: u32,
    pub managed_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            v: 1,
            auto_refresh: false,
            auto_refresh_secs: 5,
            managed_only: true,
        }
    }
}

/// Parse result: the resolved `Config` plus an optional warning string
/// when the input was corrupt (parse error). Missing-file is NOT a
/// corruption — callers handle that case separately and get no warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigLoad {
    pub config: Config,
    pub warning: Option<String>,
}

/// Parse config JSON. On parse failure, returns defaults with a warning
/// describing what couldn't be parsed. Out-of-range numeric fields are
/// clamped to the supported UI range and the clamp is reported via the
/// returned warning so the user knows their on-disk value was adjusted.
pub fn parse_config(text: &str) -> ConfigLoad {
    match serde_json::from_str::<Config>(text) {
        Ok(mut config) => {
            let warning = normalize(&mut config);
            ConfigLoad { config, warning }
        }
        Err(e) => ConfigLoad {
            config: Config::default(),
            warning: Some(format!("config.json is corrupt — using defaults: {e}")),
        },
    }
}

/// Clamp deserialized fields into their supported runtime ranges. Returns a
/// human-readable warning when any value had to be adjusted, otherwise None.
fn normalize(config: &mut Config) -> Option<String> {
    let raw = config.auto_refresh_secs;
    let clamped = raw.clamp(AUTO_REFRESH_SECS_MIN, AUTO_REFRESH_SECS_MAX);
    if clamped != raw {
        config.auto_refresh_secs = clamped;
        return Some(format!(
            "auto_refresh_secs clamped from {raw} to {clamped} (allowed: {min}..={max})",
            min = AUTO_REFRESH_SECS_MIN,
            max = AUTO_REFRESH_SECS_MAX,
        ));
    }
    None
}

/// Serialise preferences to pretty JSON.
fn to_json(config: &Config) -> Result<String, String> {
    serde_json::to_string_pretty(config).map_err(|e| format!("serialise config: {e}"))
}

/// Path to the config file: `%APPDATA%\NGSM\config.json`.
fn config_path() -> Option<PathBuf> {
    let appdata = std::env::var_os("APPDATA")?;
    Some(PathBuf::from(appdata).join("NGSM").join("config.json"))
}

/// Load preferences from `%APPDATA%\NGSM\config.json`. Returns defaults
/// with no warning if the file is missing (clean first run); defaults with
/// a warning if the file exists but cannot be read (permission denied, IO
/// error, etc.) or is corrupt.
pub fn load() -> ConfigLoad {
    let Some(path) = config_path() else {
        return ConfigLoad {
            config: Config::default(),
            warning: None,
        };
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_config(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ConfigLoad {
            config: Config::default(),
            warning: None,
        },
        Err(e) => ConfigLoad {
            config: Config::default(),
            warning: Some(format!(
                "config.json could not be read — using defaults: {e}"
            )),
        },
    }
}

/// Persist preferences, creating `%APPDATA%\NGSM` if needed. Returns an error
/// string on failure — non-fatal; the caller surfaces it in the status bar.
pub fn save(config: &Config) -> Result<(), String> {
    let path = config_path().ok_or("APPDATA is not set")?;
    save_to_path(&path, config)
}

fn save_to_path(path: &Path, config: &Config) -> Result<(), String> {
    atomic_write_with(
        path,
        to_json(config)?.as_bytes(),
        |file, bytes| {
            file.write_all(bytes)?;
            file.sync_all()
        },
        persist_staged,
    )
}

fn persist_staged(staged: tempfile::NamedTempFile, destination: &Path) -> Result<(), String> {
    let mut path = staged.into_temp_path();
    for attempt in 0..5 {
        match path.persist(destination) {
            Ok(()) => return Ok(()),
            Err(e) => {
                // Concurrent Windows replacements can briefly leave the
                // destination delete-pending. Retry only these transient codes,
                // retaining ownership of the same fully prepared staging file.
                if attempt == 4 || !matches!(e.error.raw_os_error(), Some(5 | 32 | 33)) {
                    return Err(format!("replace config: {e}"));
                }
                path = e.path;
                std::thread::sleep(std::time::Duration::from_millis(10 * (attempt + 1)));
            }
        }
    }
    unreachable!()
}

fn atomic_write_with(
    path: &Path,
    bytes: &[u8],
    prepare: impl FnOnce(&mut std::fs::File, &[u8]) -> std::io::Result<()>,
    replace: impl FnOnce(tempfile::NamedTempFile, &Path) -> Result<(), String>,
) -> Result<(), String> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let mut staged = tempfile::Builder::new()
        .prefix(".ngsm-config-")
        .tempfile_in(dir)
        .map_err(|e| format!("stage config: {e}"))?;
    prepare(staged.as_file_mut(), bytes).map_err(|e| format!("write config: {e}"))?;
    // The sibling staging file is on the same volume. tempfile's Windows
    // implementation replaces atomically and owns cleanup on every error.
    replace(staged, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let c = Config::default();
        assert_eq!(c.v, 1);
        assert!(!c.auto_refresh);
        assert_eq!(c.auto_refresh_secs, 5);
        assert!(c.managed_only);
    }

    #[test]
    fn config_round_trips_through_json() {
        let c = Config {
            v: 1,
            auto_refresh: true,
            auto_refresh_secs: 30,
            managed_only: false,
        };
        assert_eq!(parse_config(&to_json(&c).expect("serialises")).config, c);
    }

    #[test]
    fn parse_config_falls_back_on_corrupt_input() {
        let bad = parse_config("not json at all }");
        assert_eq!(bad.config, Config::default());
        assert!(bad.warning.is_some());
        let empty = parse_config("");
        assert_eq!(empty.config, Config::default());
        assert!(empty.warning.is_some());
    }

    #[test]
    fn parse_config_accepts_v_field_missing_and_defaults_to_one() {
        let no_v = r#"{"auto_refresh":true,"auto_refresh_secs":30,"managed_only":false}"#;
        let result = parse_config(no_v);
        assert_eq!(result.config.v, 1);
        assert!(result.warning.is_none());
    }

    /// Helper: build a config JSON blob with the given `auto_refresh_secs`,
    /// write it to a temp file, read it back, and run it through
    /// `parse_config` — mirroring what `load()` does on disk.
    fn parse_written_with_auto_refresh_secs(secs: u32) -> ConfigLoad {
        use std::io::Write;
        let json = format!(
            r#"{{"v":1,"auto_refresh":true,"auto_refresh_secs":{secs},"managed_only":true}}"#
        );
        let mut f = tempfile::NamedTempFile::new_in(".").unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f.flush().unwrap();
        let text = std::fs::read_to_string(f.path()).unwrap();
        parse_config(&text)
    }

    #[test]
    fn parse_config_clamps_auto_refresh_secs_below_minimum() {
        let result = parse_written_with_auto_refresh_secs(0);
        assert_eq!(result.config.auto_refresh_secs, AUTO_REFRESH_SECS_MIN);
        let w = result.warning.expect("expected a clamp warning");
        assert!(
            w.contains("clamped from 0 to 1"),
            "warning should describe the clamp, got: {w}"
        );
    }

    #[test]
    fn parse_config_clamps_auto_refresh_secs_above_maximum() {
        let result = parse_written_with_auto_refresh_secs(100_000);
        assert_eq!(result.config.auto_refresh_secs, AUTO_REFRESH_SECS_MAX);
        let w = result.warning.expect("expected a clamp warning");
        assert!(
            w.contains("clamped from 100000 to 3600"),
            "warning should describe the clamp, got: {w}"
        );
    }

    #[test]
    fn parse_config_accepts_valid_auto_refresh_secs_without_warning() {
        let result = parse_written_with_auto_refresh_secs(30);
        assert_eq!(result.config.auto_refresh_secs, 30);
        assert!(
            result.warning.is_none(),
            "got warning: {:?}",
            result.warning
        );
    }

    #[test]
    fn atomic_save_round_trips_and_replaces_without_staging_leaks() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let path = dir.path().join("config.json");
        for secs in [3600, 1, 30] {
            let config = Config {
                auto_refresh_secs: secs,
                ..Default::default()
            };
            save_to_path(&path, &config).unwrap();
            let text = std::fs::read_to_string(&path).unwrap();
            assert_eq!(parse_config(&text).config, config);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn failed_preparation_or_replacement_preserves_exact_old_bytes() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let path = dir.path().join("config.json");
        let original = to_json(&Config::default()).unwrap();
        std::fs::write(&path, &original).unwrap();
        let error = atomic_write_with(
            &path,
            b"new",
            |file, bytes| {
                file.write_all(bytes)?;
                Err(std::io::Error::other("injected write failure"))
            },
            |_, _| panic!("must not replace after failed preparation"),
        );
        assert!(error.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        let error = atomic_write_with(
            &path,
            b"new",
            |file, bytes| file.write_all(bytes),
            |_, _| Err("injected replacement failure".into()),
        );
        assert!(error.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original.as_bytes());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_saves_leave_one_complete_snapshot() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let path = dir.path().join("config.json");
        let configs = [
            Config {
                auto_refresh_secs: 3600,
                auto_refresh: false,
                ..Default::default()
            },
            Config {
                auto_refresh_secs: 1,
                auto_refresh: true,
                ..Default::default()
            },
        ];
        save_to_path(&path, &configs[0]).unwrap();
        std::thread::scope(|scope| {
            for config in &configs {
                let path = &path;
                scope.spawn(move || {
                    for _ in 0..20 {
                        save_to_path(path, config).unwrap();
                    }
                });
            }
        });
        let loaded = parse_config(&std::fs::read_to_string(&path).unwrap());
        assert!(loaded.warning.is_none());
        assert!(configs.contains(&loaded.config));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn actual_windows_replacement_failure_keeps_old_file_and_cleans_staging() {
        let dir = tempfile::tempdir_in(".").unwrap();
        let path = dir.path().join("config.json");
        save_to_path(&path, &Config::default()).unwrap();
        let original = std::fs::read(&path).unwrap();
        let permissions = std::fs::metadata(&path).unwrap().permissions();
        let mut read_only = permissions.clone();
        read_only.set_readonly(true);
        std::fs::set_permissions(&path, read_only).unwrap();
        let result = save_to_path(
            &path,
            &Config {
                auto_refresh: true,
                ..Default::default()
            },
        );
        std::fs::set_permissions(&path, permissions).unwrap();
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
