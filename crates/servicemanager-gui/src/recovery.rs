//! Recovery-policy editor form model.
//!
//! `RecoveryForm` holds the in-progress text/picker state of the Recovery
//! view and converts it into the typed `RecoverySpec` the worker applies. It
//! contains no UI-framework code, so it is unit-tested directly.

use std::collections::BTreeMap;

use servicemanager_core::{ExitAction, ManagedApplicationConfig};

use crate::data::RecoverySpec;

/// One per-exit-code row: an exit code (as typed) and an action index.
#[derive(Debug, Clone, Default)]
pub struct RecoveryExitRow {
    pub exit_code: String,
    pub action: i32,
}

/// In-progress state of the Recovery editor form.
#[derive(Debug, Clone, Default)]
pub struct RecoveryForm {
    pub service: String,
    pub restart_delay: String,
    pub throttle: String,
    pub default_action: i32,
    pub rows: Vec<RecoveryExitRow>,
}

/// Map an `ExitAction` to the 0-3 index the Slint pickers use.
fn exit_action_to_int(a: ExitAction) -> i32 {
    match a {
        ExitAction::Restart => 0,
        ExitAction::Ignore => 1,
        ExitAction::Exit => 2,
        ExitAction::Suicide => 3,
    }
}

/// Inverse of [`exit_action_to_int`]; unknown indices fall back to `Restart`.
fn int_to_exit_action(i: i32) -> ExitAction {
    match i {
        1 => ExitAction::Ignore,
        2 => ExitAction::Exit,
        3 => ExitAction::Suicide,
        _ => ExitAction::Restart,
    }
}

impl RecoveryForm {
    /// Build a form from a service's cached managed config.
    pub fn from_managed(service: &str, cfg: &ManagedApplicationConfig) -> Self {
        let ms_to_string = |v: Option<u32>| v.map(|n| n.to_string()).unwrap_or_default();
        let rows = cfg
            .exit_actions
            .iter()
            .filter(|(code, _)| code.as_str() != "default")
            .map(|(code, policy)| RecoveryExitRow {
                exit_code: code.clone(),
                action: exit_action_to_int(policy.action),
            })
            .collect();
        Self {
            service: service.to_string(),
            restart_delay: ms_to_string(cfg.restart.restart_delay_ms),
            throttle: ms_to_string(cfg.restart.throttle_delay_ms),
            default_action: exit_action_to_int(
                cfg.restart.default_action.unwrap_or(ExitAction::Restart),
            ),
            rows,
        }
    }

    /// Parse and validate the form into a `RecoverySpec` for the worker. An
    /// unfilled (blank exit-code) row is skipped; a non-numeric exit code or
    /// delay is rejected with a message for the Recovery view's status line.
    ///
    /// Duplicate exit-code rows are rejected (#14): silently collapsing them
    /// into a BTreeMap meant the saved policy could differ from what the
    /// user typed (last-write-wins), with no visible feedback.
    pub fn to_spec(&self) -> Result<RecoverySpec, String> {
        let restart_delay_ms = parse_opt_u32(&self.restart_delay, "Restart delay")?;
        let throttle_delay_ms = parse_opt_u32(&self.throttle, "Throttle window")?;
        let mut exit_actions: BTreeMap<String, ExitAction> = BTreeMap::new();
        for row in &self.rows {
            let code = row.exit_code.trim();
            if code.is_empty() {
                continue;
            }
            if code.parse::<u32>().is_err() {
                return Err(format!("Exit code '{code}' is not a valid number."));
            }
            if exit_actions.contains_key(code) {
                return Err(format!(
                    "Duplicate exit code '{code}' — each exit code may appear only once."
                ));
            }
            exit_actions.insert(code.to_string(), int_to_exit_action(row.action));
        }
        Ok(RecoverySpec {
            name: self.service.clone(),
            restart_delay_ms,
            throttle_delay_ms,
            default_action: int_to_exit_action(self.default_action),
            exit_actions,
        })
    }
}

/// Parse an optional millisecond field: blank -> `None`, else a `u32`.
fn parse_opt_u32(s: &str, label: &str) -> Result<Option<u32>, String> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(None);
    }
    t.parse::<u32>()
        .map(Some)
        .map_err(|_| format!("{label} must be a whole number of milliseconds."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use servicemanager_core::{ExitActionPolicy, RestartPolicy};

    fn config_with(
        restart: RestartPolicy,
        exits: &[(&str, ExitAction)],
    ) -> ManagedApplicationConfig {
        ManagedApplicationConfig {
            restart,
            exit_actions: exits
                .iter()
                .map(|(c, a)| (c.to_string(), ExitActionPolicy { action: *a }))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn from_managed_populates_every_field() {
        let cfg = config_with(
            RestartPolicy {
                restart_delay_ms: Some(5000),
                throttle_delay_ms: Some(1500),
                default_action: Some(ExitAction::Ignore),
            },
            &[("1", ExitAction::Exit), ("3", ExitAction::Suicide)],
        );
        let form = RecoveryForm::from_managed("DemoA", &cfg);
        assert_eq!(form.service, "DemoA");
        assert_eq!(form.restart_delay, "5000");
        assert_eq!(form.throttle, "1500");
        assert_eq!(form.default_action, 1); // Ignore
        assert_eq!(form.rows.len(), 2);
        assert_eq!(form.rows[0].exit_code, "1");
        assert_eq!(form.rows[0].action, 2); // Exit
        assert_eq!(form.rows[1].exit_code, "3");
        assert_eq!(form.rows[1].action, 3); // Suicide
    }

    #[test]
    fn from_managed_defaults_empty_restart_policy() {
        let cfg = ManagedApplicationConfig::default();
        let form = RecoveryForm::from_managed("DemoA", &cfg);
        assert_eq!(form.restart_delay, "");
        assert_eq!(form.throttle, "");
        assert_eq!(form.default_action, 0); // Restart
        assert!(form.rows.is_empty());
    }

    #[test]
    fn to_spec_parses_delays_and_actions() {
        let form = RecoveryForm {
            service: "DemoA".into(),
            restart_delay: " 4000 ".into(),
            throttle: "".into(),
            default_action: 2, // Exit
            rows: vec![
                RecoveryExitRow {
                    exit_code: "0".into(),
                    action: 1, // Ignore
                },
                RecoveryExitRow {
                    exit_code: "2".into(),
                    action: 0, // Restart
                },
            ],
        };
        let spec = form.to_spec().expect("should validate");
        assert_eq!(spec.name, "DemoA");
        assert_eq!(spec.restart_delay_ms, Some(4000));
        assert_eq!(spec.throttle_delay_ms, None);
        assert_eq!(spec.default_action, ExitAction::Exit);
        assert_eq!(spec.exit_actions.get("0"), Some(&ExitAction::Ignore));
        assert_eq!(spec.exit_actions.get("2"), Some(&ExitAction::Restart));
    }

    #[test]
    fn to_spec_skips_blank_exit_rows() {
        let form = RecoveryForm {
            service: "DemoA".into(),
            rows: vec![
                RecoveryExitRow {
                    exit_code: "  ".into(),
                    action: 0,
                },
                RecoveryExitRow {
                    exit_code: "5".into(),
                    action: 1,
                },
            ],
            ..Default::default()
        };
        let spec = form.to_spec().expect("should validate");
        assert_eq!(spec.exit_actions.len(), 1);
        assert!(spec.exit_actions.contains_key("5"));
    }

    #[test]
    fn to_spec_rejects_non_numeric_delay() {
        let form = RecoveryForm {
            service: "DemoA".into(),
            restart_delay: "soon".into(),
            ..Default::default()
        };
        assert!(form.to_spec().is_err());
    }

    #[test]
    fn to_spec_rejects_non_numeric_exit_code() {
        let form = RecoveryForm {
            service: "DemoA".into(),
            rows: vec![RecoveryExitRow {
                exit_code: "oops".into(),
                action: 0,
            }],
            ..Default::default()
        };
        assert!(form.to_spec().is_err());
    }

    #[test]
    fn from_managed_excludes_the_default_pseudo_key() {
        // `read_managed_config` carries the default action both as
        // `restart.default_action` and as an `exit_actions["default"]` entry.
        // The form must represent it only via `default_action`, never as a row.
        let cfg = config_with(
            RestartPolicy {
                restart_delay_ms: None,
                throttle_delay_ms: None,
                default_action: Some(ExitAction::Restart),
            },
            &[("default", ExitAction::Restart), ("1", ExitAction::Exit)],
        );
        let form = RecoveryForm::from_managed("DemoA", &cfg);
        assert_eq!(form.rows.len(), 1);
        assert_eq!(form.rows[0].exit_code, "1");
    }

    #[test]
    fn to_spec_rejects_duplicate_exit_code_rows() {
        // Regression for #14: previously, two rows with the same exit code
        // silently collapsed (last-write-wins via BTreeMap). The user got
        // no visible signal that one of their two intended policies had
        // been overwritten. Now `to_spec` must return an error pointing at
        // the duplicate code, surfaced via the Recovery view's status line.
        let form = RecoveryForm {
            service: "DemoA".into(),
            rows: vec![
                RecoveryExitRow {
                    exit_code: "1".into(),
                    action: 0, // Restart
                },
                RecoveryExitRow {
                    exit_code: "1".into(),
                    action: 2, // Exit
                },
            ],
            ..Default::default()
        };
        let err = form.to_spec().expect_err("duplicate code must be rejected");
        assert!(
            err.contains("Duplicate") && err.contains("'1'"),
            "error message should call out the duplicate exit code; got: {err}"
        );
    }

    #[test]
    fn to_spec_accepts_distinct_exit_code_rows() {
        // Companion test: two distinct codes still both survive — the
        // duplicate rejection above must not over-reach.
        let form = RecoveryForm {
            service: "DemoA".into(),
            rows: vec![
                RecoveryExitRow {
                    exit_code: "1".into(),
                    action: 0, // Restart
                },
                RecoveryExitRow {
                    exit_code: "2".into(),
                    action: 2, // Exit
                },
            ],
            ..Default::default()
        };
        let spec = form.to_spec().expect("two distinct codes should validate");
        assert_eq!(spec.exit_actions.len(), 2);
        assert_eq!(spec.exit_actions.get("1"), Some(&ExitAction::Restart));
        assert_eq!(spec.exit_actions.get("2"), Some(&ExitAction::Exit));
    }

    #[test]
    fn to_spec_treats_whitespace_variants_as_the_same_code() {
        // Trimming is applied before the duplicate check, so "  1  " and "1"
        // are the same code (and must be flagged as a duplicate). Otherwise
        // a stray space would silently bypass the new guard.
        let form = RecoveryForm {
            service: "DemoA".into(),
            rows: vec![
                RecoveryExitRow {
                    exit_code: "1".into(),
                    action: 0,
                },
                RecoveryExitRow {
                    exit_code: "  1  ".into(),
                    action: 2,
                },
            ],
            ..Default::default()
        };
        let err = form
            .to_spec()
            .expect_err("trimmed duplicate must be rejected");
        assert!(err.contains("Duplicate"), "got: {err}");
    }
}
