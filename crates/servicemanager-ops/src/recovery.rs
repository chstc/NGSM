use std::collections::BTreeMap;

use servicemanager_core::{ExitAction, ExitActionPolicy};

use crate::error::{message_error, OpResult, Result};
use crate::helpers::{ConfigBackend, RegistryConfigBackend};
use crate::specs::RecoverySpec;
use crate::validate::validate_managed_config;

/// Validate a per-exit-code action map key.
///
/// The supervisor looks up each child exit code using its canonical signed
/// `i32::to_string()` spelling. Numeric aliases such as `01`, `+1` and `-0`
/// must not be newly entered as keys that would never match at runtime.
///
/// `"default"` is rejected explicitly: the default exit action is a
/// separate field (`RestartPolicy::default_action` / the unnamed
/// `AppExit` registry value) and accepting it in the per-code map
/// would create two competing sources of truth for the same setting.
///
/// Whitespace, `=`, NUL, and other control characters are rejected
/// because the CLI's `CODE=ACTION` parser is line-oriented and would
/// produce nonsense splits, and because such characters cannot round-
/// trip cleanly through the registry as a value name.
pub fn validate_exit_action_key(s: &str) -> Result<()> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(message_error("exit-action key must not be empty"));
    }
    if trimmed.eq_ignore_ascii_case("default") {
        return Err(message_error(
            "'default' is not a per-exit-code key; set the default action separately",
        ));
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(message_error(
            "exit-action key must not contain whitespace or control characters",
        ));
    }
    if s.contains('=') {
        return Err(message_error("exit-action key must not contain '='"));
    }
    if s.contains('\0') {
        return Err(message_error("exit-action key must not contain NUL"));
    }
    let code = s.parse::<i32>().map_err(|_| {
        message_error("exit-action key must be an i32 exit code (e.g. -1, 0, 1, 2147483647)")
    })?;
    let canonical = code.to_string();
    if s != canonical {
        return Err(message_error(format!(
            "exit-action key must use canonical signed decimal spelling; use '{canonical}'"
        )));
    }
    Ok(())
}

/// Save a restart-policy and exit-action configuration for a managed service.
///
/// Re-reads the managed config from the registry (never trusting a
/// possibly-stale caller snapshot, exactly as `edit` does), applies the
/// restart-policy and exit-action fields, and writes it all back.
pub fn save_recovery(spec: RecoverySpec) -> OpResult {
    save_recovery_with_backend(spec, &mut RegistryConfigBackend)
}

pub(crate) fn save_recovery_with_backend(
    spec: RecoverySpec,
    backend: &mut impl ConfigBackend,
) -> OpResult {
    // Validate every per-exit-code key up front. `save_recovery` is the
    // single source of truth that every caller (CLI, broker, GUI) ends
    // up funneling through, so an out-of-spec key cannot reach the
    // registry no matter which surface produced it.
    for code in spec.exit_actions.keys() {
        validate_exit_action_key(code)
            .map_err(|e| message_error(format!("exit-action code '{code}': {e}")))?;
    }
    let _guard = servicemanager_registry::lock_service_config(&spec.name)?;
    let Some(original) = backend.read_managed(&spec.name)? else {
        return Err(message_error(format!(
            "'{}' is not an NGSM-managed service — refusing to edit its recovery policy",
            spec.name
        )));
    };
    let mut managed = original.clone();
    managed.restart.restart_delay_ms = spec.restart_delay_ms;
    managed.restart.throttle_delay_ms = spec.throttle_delay_ms;
    // The editor always writes an explicit default action; a service that
    // previously had no explicit default is promoted to one (semantically
    // equivalent at runtime, since the supervisor's implicit fallback is Restart).
    managed.restart.default_action = Some(spec.default_action);
    managed.exit_actions = spec
        .exit_actions
        .iter()
        .map(|(code, action)| (code.clone(), ExitActionPolicy { action: *action }))
        .collect();
    validate_managed_config(&managed)?;
    if let Err(error) = backend.write_managed(&spec.name, &managed) {
        let rollback = match backend.write_managed(&spec.name, &original) {
            Ok(()) => "managed configuration restored".to_string(),
            Err(rollback) => format!(
                "managed rollback also failed ({rollback}); configuration may be partially applied"
            ),
        };
        return Err(message_error(format!(
            "recovery update failed ({error}); {rollback}"
        )));
    }
    Ok(format!("Saved recovery policy for '{}'.", spec.name))
}

/// Merge a recovery change while holding the service's cross-process writer
/// guard across the read, merge and save. The callback must keep the name
/// unchanged and should only calculate the requested policy change.
pub fn update_recovery(
    name: &str,
    update: impl FnOnce(&RecoverySpec) -> Result<RecoverySpec>,
) -> OpResult {
    update_recovery_with_backend(name, update, &mut RegistryConfigBackend)
}

pub(crate) fn update_recovery_with_backend(
    name: &str,
    update: impl FnOnce(&RecoverySpec) -> Result<RecoverySpec>,
    backend: &mut impl ConfigBackend,
) -> OpResult {
    let _guard = servicemanager_registry::lock_service_config(name)?;
    let current = read_recovery_with_backend(name, backend)?;
    let spec = update(&current)?;
    if spec.name != name {
        return Err(message_error(
            "a recovery update must keep the requested service name",
        ));
    }
    save_recovery_with_backend(spec, backend)
}

/// Read the current recovery policy for a managed service. Returns an
/// `Err` if the service is not NGSM-managed or its config is unreadable.
pub fn read_recovery(name: &str) -> Result<RecoverySpec> {
    read_recovery_with_backend(name, &mut RegistryConfigBackend)
}

fn read_recovery_with_backend(
    name: &str,
    backend: &mut impl ConfigBackend,
) -> Result<RecoverySpec> {
    let Some(managed) = backend.read_managed(name)? else {
        return Err(message_error(format!(
            "'{}' is not an NGSM-managed service",
            name
        )));
    };
    // The registry pseudo-key "default" mirrors restart.default_action;
    // filter it out so the returned spec only contains per-exit-code
    // entries (matches what the GUI's RecoveryForm does).
    let exit_actions: BTreeMap<String, ExitAction> = managed
        .exit_actions
        .iter()
        .filter(|(code, _)| code.as_str() != "default")
        .map(|(code, policy)| (code.clone(), policy.action))
        .collect();
    Ok(RecoverySpec {
        name: name.to_string(),
        restart_delay_ms: managed.restart.restart_delay_ms,
        throttle_delay_ms: managed.restart.throttle_delay_ms,
        default_action: managed
            .restart
            .default_action
            .unwrap_or(ExitAction::Restart),
        exit_actions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newly_entered_exit_keys_must_match_the_runtime_decimal_spelling() {
        for alias in ["00", "01", "+1", "+0", "-0", "-01"] {
            assert!(
                validate_exit_action_key(alias).is_err(),
                "noncanonical key {alias} must not be persisted as an inert policy"
            );
        }
    }

    #[cfg(all(test, windows))]
    mod transaction_tests {
        use super::*;
        use crate::config_test_support::{config, service_name, RecordingConfigBackend};
        use crate::edit::edit_with_backend;
        use crate::EditSpec;
        use std::sync::{mpsc, Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        fn policy(name: String) -> RecoverySpec {
            RecoverySpec {
                name,
                restart_delay_ms: Some(5000),
                throttle_delay_ms: Some(8000),
                default_action: ExitAction::Exit,
                exit_actions: [("0".into(), ExitAction::Ignore)].into(),
            }
        }

        #[test]
        fn noncanonical_and_reserved_keys_fail_before_backend_access() {
            for code in ["00", "01", "+1", "-0", "-01", "default", "2147483648"] {
                let mut spec = policy(service_name());
                spec.exit_actions.insert(code.into(), ExitAction::Restart);
                let mut backend = RecordingConfigBackend::new(config());
                let error = save_recovery_with_backend(spec, &mut backend)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("exit-action"), "{error}");
                assert!(backend.calls.is_empty(), "{:?}", backend.calls);
            }
        }

        #[test]
        fn signed_extrema_and_normalized_legacy_keys_save_through_the_production_path() {
            let mut spec = policy(service_name());
            for code in ["-2147483648", "-1073741819", "-1", "0", "2147483647"] {
                spec.exit_actions.insert(code.into(), ExitAction::Ignore);
            }
            let expected = spec.exit_actions.clone();
            let mut backend = RecordingConfigBackend::new(config());
            save_recovery_with_backend(spec, &mut backend).unwrap();
            assert_eq!(backend.calls, ["read", "write"]);
            let config = backend.config.lock().unwrap();
            for (code, action) in expected {
                assert_eq!(config.exit_actions[&code].action, action);
            }
        }

        #[test]
        fn recovery_save_preserves_raw_expandable_metadata_and_unrelated_values() {
            let mut original = config();
            original.application = Some("%SERVICE_ROOT%\\app.exe".into());
            original.app_parameters = Some("%LITERAL_NOT_EXPANDED%".into());
            original.expandable_strings.insert("Application".into());
            let mut backend = RecordingConfigBackend::new(original.clone());
            save_recovery_with_backend(policy(service_name()), &mut backend).unwrap();
            let saved = backend.config.lock().unwrap();
            assert_eq!(saved.application, original.application);
            assert_eq!(saved.app_parameters, original.app_parameters);
            assert_eq!(saved.expandable_strings, original.expandable_strings);
            assert_eq!(saved.environment, original.environment);
            assert_eq!(saved.restart.restart_delay_ms, Some(5000));
            assert_eq!(saved.restart.throttle_delay_ms, Some(8000));
            assert_eq!(
                saved.io.stdout.as_ref().unwrap().share_mode,
                original.io.stdout.as_ref().unwrap().share_mode
            );
        }

        #[test]
        fn shared_preflight_rejects_invalid_complete_config_before_recovery_write() {
            let mut original = config();
            original.environment.push(String::new());
            let mut backend = RecordingConfigBackend::new(original);
            assert!(save_recovery_with_backend(policy(service_name()), &mut backend).is_err());
            assert_eq!(backend.calls, ["read"]);
        }

        #[test]
        fn recovery_write_failure_restores_or_reports_the_original_snapshot() {
            for rollback_error in [None, Some("restore denied")] {
                let original = config();
                let mut backend = RecordingConfigBackend::new(original.clone());
                backend.write_errors = [Some("recovery write denied"), rollback_error].into();
                let error = save_recovery_with_backend(policy(service_name()), &mut backend)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("recovery write denied"), "{error}");
                if let Some(rollback_error) = rollback_error {
                    assert!(error.contains(rollback_error), "{error}");
                } else {
                    assert!(error.contains("configuration restored"), "{error}");
                }
                assert_eq!(backend.calls, ["read", "write", "write"]);
                crate::config_test_support::assert_config_eq(
                    &backend.config.lock().unwrap(),
                    &original,
                );
            }
        }

        #[test]
        fn update_callback_runs_under_the_guard_and_default_mirror_is_not_a_per_code_key() {
            let name = service_name();
            let mut backend = RecordingConfigBackend::new(config());
            update_recovery_with_backend(
                &name,
                |current| {
                    assert!(!current.exit_actions.contains_key("default"));
                    assert_eq!(current.default_action, ExitAction::Exit);
                    let mut updated = current.clone();
                    updated.restart_delay_ms = None;
                    Ok(updated)
                },
                &mut backend,
            )
            .unwrap();
            assert_eq!(backend.calls, ["read", "read", "write"]);
            let saved = backend.config.lock().unwrap();
            assert_eq!(saved.restart.restart_delay_ms, None);
            assert_eq!(saved.restart.throttle_delay_ms, Some(2000));
            assert_eq!(saved.restart.default_action, Some(ExitAction::Exit));
        }

        #[test]
        fn callback_errors_and_target_changes_do_not_write_and_release_the_guard() {
            for change_target in [false, true] {
                let name = service_name();
                let mut backend = RecordingConfigBackend::new(config());
                let result = update_recovery_with_backend(
                    &name,
                    |current| {
                        if change_target {
                            let mut updated = current.clone();
                            updated.name = "DifferentService".into();
                            Ok(updated)
                        } else {
                            Err(message_error("merge rejected"))
                        }
                    },
                    &mut backend,
                );
                assert!(result.is_err());
                assert_eq!(backend.calls, ["read"]);
                thread::spawn(move || {
                    servicemanager_registry::lock_service_config(&name).map(drop)
                })
                .join()
                .unwrap()
                .expect("failed merge must release its outer guard");
            }
        }

        #[test]
        fn two_recovery_merges_do_not_derive_complete_specs_from_the_same_stale_read() {
            let name = service_name();
            let alias = name.to_uppercase();
            let mut first = RecordingConfigBackend::new(config());
            let store = Arc::clone(&first.config);
            let release = Arc::new(Barrier::new(2));
            let worker_release = Arc::clone(&release);
            let (entered_tx, entered_rx) = mpsc::channel();
            first.after_read = Some(Box::new(move || {
                entered_tx.send(()).unwrap();
                worker_release.wait();
            }));
            let first_worker = thread::spawn(move || {
                update_recovery_with_backend(
                    &name,
                    |current| {
                        let mut updated = current.clone();
                        updated.restart_delay_ms = Some(5000);
                        Ok(updated)
                    },
                    &mut first,
                )
            });
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let mut second = RecordingConfigBackend::sharing(Arc::clone(&store));
            let (read_tx, read_rx) = mpsc::channel();
            second.after_read = Some(Box::new(move || read_tx.send(()).unwrap()));
            let second_worker = thread::spawn(move || {
                update_recovery_with_backend(
                    &alias,
                    |current| {
                        let mut updated = current.clone();
                        updated.throttle_delay_ms = Some(8000);
                        Ok(updated)
                    },
                    &mut second,
                )
            });
            let blocked = matches!(
                read_rx.recv_timeout(Duration::from_millis(80)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
            release.wait();
            first_worker.join().unwrap().unwrap();
            second_worker.join().unwrap().unwrap();
            assert!(
                blocked,
                "the merge read must be protected, not only save_recovery"
            );
            let saved = store.lock().unwrap();
            assert_eq!(saved.restart.restart_delay_ms, Some(5000));
            assert_eq!(saved.restart.throttle_delay_ms, Some(8000));
            assert_eq!(saved.app_parameters.as_deref(), Some("--original"));
            assert_eq!(saved.exit_actions["0"].action, ExitAction::Ignore);
        }

        #[test]
        fn edit_and_recovery_save_preserve_both_changes_in_either_order() {
            for recovery_first in [false, true] {
                let name = service_name();
                let second_name = name.clone();
                let mut first = RecordingConfigBackend::new(config());
                let store = Arc::clone(&first.config);
                let release = Arc::new(Barrier::new(2));
                let worker_release = Arc::clone(&release);
                let (entered_tx, entered_rx) = mpsc::channel();
                first.after_read = Some(Box::new(move || {
                    entered_tx.send(()).unwrap();
                    worker_release.wait();
                }));
                let run = |name: String, recovery: bool, backend: &mut RecordingConfigBackend| {
                    if recovery {
                        save_recovery_with_backend(policy(name), backend)
                    } else {
                        edit_with_backend(
                            EditSpec {
                                name,
                                app_parameters: Some("--edited".into()),
                                ..Default::default()
                            },
                            backend,
                        )
                    }
                };
                let first_worker = thread::spawn(move || run(name, recovery_first, &mut first));
                entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                let mut second = RecordingConfigBackend::sharing(Arc::clone(&store));
                let (read_tx, read_rx) = mpsc::channel();
                second.after_read = Some(Box::new(move || read_tx.send(()).unwrap()));
                let second_worker =
                    thread::spawn(move || run(second_name, !recovery_first, &mut second));
                let blocked = matches!(
                    read_rx.recv_timeout(Duration::from_millis(80)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                );
                release.wait();
                first_worker.join().unwrap().unwrap();
                second_worker.join().unwrap().unwrap();
                assert!(blocked, "edit and recovery must share the same outer guard");
                let saved = store.lock().unwrap();
                assert_eq!(saved.app_parameters.as_deref(), Some("--edited"));
                assert_eq!(saved.restart.restart_delay_ms, Some(5000));
                assert_eq!(saved.restart.throttle_delay_ms, Some(8000));
            }
        }
    }

    #[test]
    fn read_recovery_for_unknown_service_returns_error_mentioning_managed() {
        let err = read_recovery("__definitely_does_not_exist_zzz")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not an NGSM-managed service") || err.contains("not"),
            "error should mention not-managed: {err}"
        );
    }

    #[test]
    fn validate_exit_action_key_accepts_negative_and_zero_and_large() {
        // Every valid signed-32 exit code is acceptable. The supervisor
        // matches arbitrary i32 codes, so the validator must too.
        assert!(validate_exit_action_key("-1").is_ok());
        assert!(validate_exit_action_key("0").is_ok());
        assert!(validate_exit_action_key("1").is_ok());
        assert!(validate_exit_action_key("2147483647").is_ok());
        assert!(validate_exit_action_key("-2147483648").is_ok());
    }

    #[test]
    fn validate_exit_action_key_rejects_default_and_empty() {
        // "default" belongs in `RestartPolicy::default_action`, not the
        // per-code map — accepting it here would silently shadow that
        // separate field at write time.
        assert!(validate_exit_action_key("default").is_err());
        assert!(validate_exit_action_key("Default").is_err());
        assert!(validate_exit_action_key("DEFAULT").is_err());
        assert!(validate_exit_action_key("").is_err());
        assert!(validate_exit_action_key("   ").is_err());
    }

    #[test]
    fn validate_exit_action_key_rejects_garbage() {
        // `=` would have been split off by the CLI's CODE=ACTION parser,
        // so anything that still contains `=` here is malformed input.
        assert!(validate_exit_action_key("=ignore").is_err());
        // Non-numeric: would never match a real exit code at runtime.
        assert!(validate_exit_action_key("abc").is_err());
        assert!(validate_exit_action_key("1=foo").is_err());
        // Embedded NUL: cannot round-trip as a registry value name.
        assert!(validate_exit_action_key("1\0").is_err());
        // Trailing space: i32::parse rejects, so the key would never
        // match anything (yet would persist in the registry).
        assert!(validate_exit_action_key("1 ").is_err());
        // Whitespace in the middle: same.
        assert!(validate_exit_action_key("1\t2").is_err());
        // Out-of-range integers are rejected by i32::parse.
        assert!(validate_exit_action_key("2147483648").is_err());
        assert!(validate_exit_action_key("-2147483649").is_err());
    }
}
