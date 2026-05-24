//! Persisted GUI preferences (`%APPDATA%\NGSM\config.json`).
//!
//! `parse_config` / `to_json` are the pure, unit-tested core; `load` / `save`
//! wrap them with file IO and are verified manually.

use std::path::PathBuf;

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
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let json = to_json(config)?;
    std::fs::write(&path, json).map_err(|e| format!("write config: {e}"))
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
        let mut f = tempfile::NamedTempFile::new().unwrap();
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
}
