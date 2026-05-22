//! Persisted GUI preferences (`%APPDATA%\NGSM\config.json`).
//!
//! `parse_config` / `to_json` are the pure, unit-tested core; `load` / `save`
//! wrap them with file IO and are verified manually.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// User preferences persisted between sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub auto_refresh: bool,
    pub auto_refresh_secs: u32,
    pub managed_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auto_refresh: false,
            auto_refresh_secs: 5,
            managed_only: true,
        }
    }
}

/// Parse config JSON, falling back to built-in defaults on any error (missing
/// keys, corrupt syntax) so a bad file never breaks startup.
pub fn parse_config(text: &str) -> Config {
    serde_json::from_str(text).unwrap_or_default()
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

/// Load preferences, returning built-in defaults if the file is missing,
/// unreadable, or corrupt.
pub fn load() -> Config {
    let Some(path) = config_path() else {
        return Config::default();
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_config(&text),
        Err(_) => Config::default(),
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
        assert!(!c.auto_refresh);
        assert_eq!(c.auto_refresh_secs, 5);
        assert!(c.managed_only);
    }

    #[test]
    fn config_round_trips_through_json() {
        let c = Config {
            auto_refresh: true,
            auto_refresh_secs: 30,
            managed_only: false,
        };
        assert_eq!(parse_config(&to_json(&c).expect("serialises")), c);
    }

    #[test]
    fn parse_config_falls_back_on_corrupt_input() {
        assert_eq!(parse_config("not json at all }"), Config::default());
        assert_eq!(parse_config(""), Config::default());
    }
}
