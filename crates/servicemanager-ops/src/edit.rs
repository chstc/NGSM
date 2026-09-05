use servicemanager_core::{IoStream, ManagedApplicationConfig};
use servicemanager_win32::validate_native_update;

use crate::error::{message_error, OpResult};
use crate::helpers::{io_stream, ConfigBackend, RegistryConfigBackend};
use crate::specs::EditSpec;
use crate::validate::validate_managed_config;

/// Edit an existing NGSM-managed service.
///
/// All native inputs are preflighted before reading or changing managed
/// config. Managed changes are validated and written before SCM mutation,
/// and restored on a later failure. Native account/password changes cannot
/// be undone from a snapshot; errors preserve the native phase's partial-
/// application diagnostics and explicitly describe the managed rollback.
///
/// `edit` only mutates NGSM-managed services. Re-validates ownership against
/// current registry state — the UI button / CLI snapshot may be stale, and a
/// native-only edit must not slip through unchecked.
pub fn edit(spec: EditSpec) -> OpResult {
    edit_with_backend(spec, &mut RegistryConfigBackend)
}

pub(crate) fn edit_with_backend(spec: EditSpec, backend: &mut impl ConfigBackend) -> OpResult {
    if !spec.has_changes() {
        return Err(servicemanager_core::Error::InvalidConfig(
            "no edit fields specified".into(),
        ));
    }

    validate_native_update(
        &spec.name,
        spec.display_name.as_deref(),
        spec.description.as_deref(),
        spec.dependencies.as_ref(),
        spec.account.as_deref(),
        spec.password.as_deref(),
    )?;
    let _guard = servicemanager_registry::lock_service_config(&spec.name)?;
    let touches_managed = spec.application.is_some()
        || spec.app_parameters.is_some()
        || spec.app_directory.is_some()
        || spec.stdout.is_some()
        || spec.stderr.is_some();

    let Some(original) = backend.read_managed(&spec.name)? else {
        return Err(message_error(format!(
            "'{}' is not an NGSM-managed service — refusing to edit it",
            spec.name
        )));
    };

    if touches_managed {
        let mut managed = original.clone();
        merge_managed_fields(&mut managed, &spec)?;
        validate_managed_config(&managed)?;
        if let Err(error) = backend.write_managed(&spec.name, &managed) {
            return Err(rollback_managed(backend, &spec, &original, error, false));
        }
    }

    if spec.display_name.is_some()
        || spec.description.is_some()
        || spec.start_type.is_some()
        || spec.dependencies.is_some()
        || spec.account.is_some()
        || spec.password.is_some()
    {
        if let Err(error) = backend.update_native(&spec) {
            return Err(if touches_managed {
                rollback_managed(backend, &spec, &original, error, true)
            } else {
                error
            });
        }
    }
    Ok(format!("Edited '{}'.", spec.name))
}

fn merge_managed_fields(
    managed: &mut ManagedApplicationConfig,
    spec: &EditSpec,
) -> servicemanager_core::Result<()> {
    if let Some(v) = &spec.application {
        if v.trim().is_empty() {
            return Err(message_error("Application path must not be empty."));
        }
        managed.application = Some(v.clone());
    }
    if let Some(v) = &spec.app_parameters {
        managed.app_parameters = Some(v.clone());
    }
    if let Some(v) = &spec.app_directory {
        managed.app_directory = Some(v.clone());
    }
    merge_stream_path(&mut managed.io.stdout, spec.stdout.clone());
    merge_stream_path(&mut managed.io.stderr, spec.stderr.clone());
    for (path, key) in [
        (spec.stdout.as_deref(), "AppStdout"),
        (spec.stderr.as_deref(), "AppStderr"),
    ] {
        if path == Some("") {
            managed
                .expandable_strings
                .retain(|marked| !marked.eq_ignore_ascii_case(key));
        }
    }
    Ok(())
}

fn rollback_managed(
    backend: &mut impl ConfigBackend,
    spec: &EditSpec,
    original: &ManagedApplicationConfig,
    error: servicemanager_core::Error,
    native_attempted: bool,
) -> servicemanager_core::Error {
    let (phase, native_status) = if native_attempted {
        (
            "native edit",
            "Native SCM fields (including account/password) were not rolled back; \
             inspect native configuration for partial application.",
        )
    } else {
        ("managed edit", "No native SCM changes were attempted.")
    };
    let restored = match backend.write_managed(&spec.name, original) {
        Ok(()) => "managed configuration restored".to_string(),
        Err(rollback) => format!(
            "managed rollback also failed ({rollback}); managed configuration may be partially applied"
        ),
    };
    message_error(format!(
        "{phase} failed ({error}); {restored}. {native_status}"
    ))
}

fn merge_stream_path(stream: &mut Option<IoStream>, path: Option<String>) {
    match path {
        None => {}
        Some(path) if path.is_empty() => *stream = None,
        Some(path) => match stream {
            Some(stream) => stream.path = path,
            None => *stream = Some(io_stream(path)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_path_merge_preserves_options_for_changed_and_unchanged_paths() {
        for path in ["C:\\logs\\old.log", "C:\\logs\\new.log"] {
            let mut stream = Some(IoStream {
                path: "C:\\logs\\old.log".into(),
                share_mode: Some(3),
                creation_disposition: Some(4),
                flags_and_attributes: Some(128),
                copy_and_truncate: Some(true),
            });

            merge_stream_path(&mut stream, Some(path.into()));

            let stream = stream.unwrap();
            assert_eq!(stream.path, path);
            assert_eq!(stream.share_mode, Some(3));
            assert_eq!(stream.creation_disposition, Some(4));
            assert_eq!(stream.flags_and_attributes, Some(128));
            assert_eq!(stream.copy_and_truncate, Some(true));
        }
    }

    #[test]
    fn stream_path_merge_handles_missing_untouched_and_cleared_streams() {
        for original in [None, Some(io_stream("C:\\logs\\old.log".into()))] {
            let mut stream = original.clone();
            merge_stream_path(&mut stream, None);
            assert_eq!(
                stream.as_ref().map(|s| &s.path),
                original.as_ref().map(|s| &s.path)
            );

            merge_stream_path(&mut stream, Some(String::new()));
            assert!(stream.is_none());
        }

        let mut stream = None;
        merge_stream_path(&mut stream, Some("C:\\logs\\new.log".into()));
        let stream = stream.unwrap();
        assert_eq!(stream.path, "C:\\logs\\new.log");
        assert!(stream.share_mode.is_none());
        assert!(stream.creation_disposition.is_none());
        assert!(stream.flags_and_attributes.is_none());
        assert!(stream.copy_and_truncate.is_none());
    }

    #[test]
    fn edit_rejects_noop_before_registry_lookup() {
        let spec = EditSpec {
            name: "NoSuchServiceNeeded".into(),
            ..Default::default()
        };

        let err = edit(spec)
            .expect_err("no-op edit must be rejected before registry/SCM access")
            .to_string();
        assert!(err.contains("no edit fields"), "got: {err}");
    }

    #[test]
    fn edit_spec_with_only_display_name_touches_no_managed_fields() {
        let spec = EditSpec {
            name: "MySvc".into(),
            display_name: Some("New Name".into()),
            ..Default::default()
        };
        // touches_managed should be false for this spec
        let touches_managed = spec.application.is_some()
            || spec.app_parameters.is_some()
            || spec.app_directory.is_some()
            || spec.stdout.is_some()
            || spec.stderr.is_some();
        assert!(!touches_managed);
        assert!(spec.display_name.is_some());
    }

    #[cfg(all(test, windows))]
    mod transaction_tests {
        use super::*;
        use crate::config_test_support::{
            assert_config_eq, config, configured_stream, service_name, RecordingConfigBackend,
        };
        use std::sync::{mpsc, Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        #[test]
        fn production_edit_covers_the_full_stdout_and_stderr_merge_matrix() {
            for stdout in [false, true] {
                for exists in [false, true] {
                    for path in [
                        None,
                        Some(""),
                        Some("C:\\logs\\old.log"),
                        Some("C:\\logs\\new.log"),
                    ] {
                        let mut original = config();
                        let stream = exists.then(|| configured_stream("C:\\logs\\old.log"));
                        if stdout {
                            original.io.stdout = stream.clone();
                        } else {
                            original.io.stderr = stream.clone();
                        }
                        let mut expected = original.clone();
                        let expected_stream = match path {
                            None => stream,
                            Some("") => None,
                            Some(path) => Some(match stream {
                                Some(mut stream) => {
                                    stream.path = path.into();
                                    stream
                                }
                                None => io_stream(path.into()),
                            }),
                        };
                        if stdout {
                            expected.io.stdout = expected_stream;
                        } else {
                            expected.io.stderr = expected_stream;
                        }
                        let mut spec = EditSpec {
                            name: service_name(),
                            display_name: Some("Display".into()),
                            ..Default::default()
                        };
                        if stdout {
                            spec.stdout = path.map(str::to_string);
                        } else {
                            spec.stderr = path.map(str::to_string);
                        }
                        let mut backend = RecordingConfigBackend::new(original);
                        edit_with_backend(spec, &mut backend).unwrap();
                        assert_config_eq(&backend.config.lock().unwrap(), &expected);
                    }
                }
            }
        }

        #[test]
        fn native_preflight_rejects_every_invalid_input_before_read_or_write() {
            let base = EditSpec {
                name: service_name(),
                app_parameters: Some("--changed".into()),
                ..Default::default()
            };
            let cases = [
                EditSpec {
                    account: Some("invalid\naccount".into()),
                    ..base.clone()
                },
                EditSpec {
                    password: Some("never-echo-this-password".into()),
                    ..base.clone()
                },
                EditSpec {
                    account: Some(".\\test-account".into()),
                    password: Some("never-echo\0this-password".into()),
                    ..base.clone()
                },
                EditSpec {
                    display_name: Some("invalid\0display".into()),
                    ..base.clone()
                },
                EditSpec {
                    description: Some("invalid\0description".into()),
                    ..base.clone()
                },
                EditSpec {
                    dependencies: Some(servicemanager_win32::ServiceDependencies {
                        services: vec![String::new()],
                        groups: Vec::new(),
                    }),
                    ..base
                },
            ];
            for spec in cases {
                let original = config();
                let mut backend = RecordingConfigBackend::new(original.clone());
                let error = edit_with_backend(spec, &mut backend)
                    .unwrap_err()
                    .to_string();
                assert!(backend.calls.is_empty(), "{:?}", backend.calls);
                assert!(!error.contains("never-echo"), "{error}");
                assert_config_eq(&backend.config.lock().unwrap(), &original);
            }
        }

        #[test]
        fn managed_validation_failure_never_writes_or_reaches_native_mutation() {
            for application in ["", "   ", "relative.exe"] {
                let original = config();
                let mut backend = RecordingConfigBackend::new(original.clone());
                let spec = EditSpec {
                    name: service_name(),
                    application: Some(application.into()),
                    display_name: Some("New Display".into()),
                    ..Default::default()
                };
                assert!(edit_with_backend(spec, &mut backend).is_err());
                assert_eq!(backend.calls, ["read"]);
                assert_config_eq(&backend.config.lock().unwrap(), &original);
            }
            let mut backend = RecordingConfigBackend::new(config());
            let spec = EditSpec {
                name: service_name(),
                stdout: Some("relative.log".into()),
                display_name: Some("New Display".into()),
                ..Default::default()
            };
            assert!(edit_with_backend(spec, &mut backend).is_err());
            assert_eq!(backend.calls, ["read"]);
        }

        #[test]
        fn native_failure_restores_managed_snapshot_and_preserves_partial_native_diagnostics() {
            let original = config();
            let mut backend = RecordingConfigBackend::new(original.clone());
            backend.native_error = Some("native fields applied; description failed");
            let spec = EditSpec {
                name: service_name(),
                app_parameters: Some("--changed".into()),
                display_name: Some("New Display".into()),
                ..Default::default()
            };
            let error = edit_with_backend(spec, &mut backend)
                .unwrap_err()
                .to_string();
            assert_eq!(backend.calls, ["read", "write", "native", "write"]);
            assert_config_eq(&backend.config.lock().unwrap(), &original);
            assert!(error.contains("description failed"), "{error}");
            assert!(error.contains("managed configuration restored"), "{error}");
            assert!(
                error.contains("account/password) were not rolled back"),
                "{error}"
            );
        }

        #[test]
        fn rollback_failure_reports_both_failures_and_does_not_claim_full_restoration() {
            let mut backend = RecordingConfigBackend::new(config());
            backend.native_error = Some("native update denied");
            backend.write_errors = [None, Some("rollback denied")].into();
            let spec = EditSpec {
                name: service_name(),
                app_parameters: Some("--changed".into()),
                display_name: Some("New Display".into()),
                ..Default::default()
            };
            let error = edit_with_backend(spec, &mut backend)
                .unwrap_err()
                .to_string();
            assert!(error.contains("native update denied"), "{error}");
            assert!(error.contains("rollback denied"), "{error}");
            assert!(error.contains("partially applied"), "{error}");
            assert!(!error.contains("configuration restored"), "{error}");
            assert_eq!(
                backend.config.lock().unwrap().app_parameters.as_deref(),
                Some("--changed")
            );
        }

        #[test]
        fn managed_write_failure_attempts_restoration_without_native_changes() {
            for rollback_error in [None, Some("restore denied")] {
                let original = config();
                let mut backend = RecordingConfigBackend::new(original.clone());
                backend.write_errors = [Some("write denied"), rollback_error].into();
                let spec = EditSpec {
                    name: service_name(),
                    app_parameters: Some("--changed".into()),
                    display_name: Some("New Display".into()),
                    ..Default::default()
                };
                let error = edit_with_backend(spec, &mut backend)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains("write denied"), "{error}");
                if let Some(rollback_error) = rollback_error {
                    assert!(error.contains(rollback_error), "{error}");
                }
                assert!(
                    error.contains("No native SCM changes were attempted"),
                    "{error}"
                );
                assert_eq!(backend.calls, ["read", "write", "write"]);
                assert_config_eq(&backend.config.lock().unwrap(), &original);
            }
        }

        #[test]
        fn successful_mixed_and_native_only_edits_preserve_unrelated_fields() {
            for managed_change in [false, true] {
                let original = config();
                let mut expected = original.clone();
                let mut backend = RecordingConfigBackend::new(original);
                let spec = EditSpec {
                    name: service_name(),
                    display_name: Some("New Display".into()),
                    app_parameters: managed_change.then(|| "--changed".into()),
                    ..Default::default()
                };
                edit_with_backend(spec, &mut backend).unwrap();
                if managed_change {
                    expected.app_parameters = Some("--changed".into());
                    assert_eq!(backend.calls, ["read", "write", "native"]);
                } else {
                    assert_eq!(backend.calls, ["read", "native"]);
                }
                assert_config_eq(&backend.config.lock().unwrap(), &expected);
            }
        }

        #[test]
        fn unreadable_and_unmanaged_services_never_reach_native_edit() {
            for unreadable in [false, true] {
                let mut backend = RecordingConfigBackend::new(config());
                backend.managed = unreadable;
                backend.read_error = unreadable.then_some("managed read denied");
                let spec = EditSpec {
                    name: service_name(),
                    display_name: Some("New Display".into()),
                    ..Default::default()
                };
                assert!(edit_with_backend(spec, &mut backend).is_err());
                assert_eq!(backend.calls, ["read"]);
            }
        }

        #[test]
        fn expandable_values_and_types_survive_unrelated_edits_and_rollback() {
            for fail_native in [false, true] {
                let mut original = config();
                original.application = Some("%SERVICE_HOME%\\app.exe".into());
                original.io.stdout.as_mut().unwrap().path = "%LOG_HOME%\\out.log".into();
                original.expandable_strings = ["Application".into(), "AppStdout".into()].into();
                let mut expected = original.clone();
                let mut backend = RecordingConfigBackend::new(original);
                backend.native_error = fail_native.then_some("native denied");
                let spec = EditSpec {
                    name: service_name(),
                    app_parameters: Some("%LITERAL_UNEXPANDED%".into()),
                    display_name: Some("New Display".into()),
                    ..Default::default()
                };
                let result = edit_with_backend(spec, &mut backend);
                assert_eq!(result.is_err(), fail_native);
                if !fail_native {
                    expected.app_parameters = Some("%LITERAL_UNEXPANDED%".into());
                }
                assert_config_eq(&backend.config.lock().unwrap(), &expected);
            }
        }

        #[test]
        fn concurrent_case_alias_edits_serialize_reads_and_protect_rollback() {
            for rollback in [false, true] {
                let name = format!("{}_é", service_name());
                let alias = name.to_uppercase();
                let mut first = RecordingConfigBackend::new(config());
                let store = Arc::clone(&first.config);
                let release = Arc::new(Barrier::new(2));
                let worker_release = Arc::clone(&release);
                let (first_tx, first_rx) = mpsc::channel();
                let gate = Box::new(move || {
                    first_tx.send(()).unwrap();
                    worker_release.wait();
                });
                if rollback {
                    first.before_native = Some(gate);
                    first.native_error = Some("native denied");
                } else {
                    first.after_read = Some(gate);
                }
                let first_worker = thread::spawn(move || {
                    edit_with_backend(
                        EditSpec {
                            name,
                            app_parameters: Some("--first".into()),
                            display_name: rollback.then(|| "Display".into()),
                            ..Default::default()
                        },
                        &mut first,
                    )
                });
                first_rx.recv_timeout(Duration::from_secs(2)).unwrap();

                let mut second = RecordingConfigBackend::sharing(Arc::clone(&store));
                let (entered_tx, entered_rx) = mpsc::channel();
                second.after_read = Some(Box::new(move || entered_tx.send(()).unwrap()));
                let (attempted_tx, attempted_rx) = mpsc::channel();
                let second_worker = thread::spawn(move || {
                    attempted_tx.send(()).unwrap();
                    edit_with_backend(
                        EditSpec {
                            name: alias,
                            stdout: Some("C:\\logs\\second.log".into()),
                            ..Default::default()
                        },
                        &mut second,
                    )
                });
                attempted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                let blocked = matches!(
                    entered_rx.recv_timeout(Duration::from_millis(80)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                );
                release.wait();
                let first_result = first_worker.join().unwrap();
                second_worker.join().unwrap().unwrap();
                assert!(blocked, "the second read must wait for the full first edit");
                assert_eq!(first_result.is_err(), rollback);
                let final_config = store.lock().unwrap();
                assert_eq!(
                    final_config.app_parameters.as_deref(),
                    Some(if rollback { "--original" } else { "--first" })
                );
                assert_eq!(
                    final_config.io.stdout.as_ref().unwrap().path,
                    "C:\\logs\\second.log"
                );
            }
        }

        #[test]
        fn unrelated_services_do_not_share_the_edit_guard() {
            let mut first = RecordingConfigBackend::new(config());
            let release = Arc::new(Barrier::new(2));
            let worker_release = Arc::clone(&release);
            let (entered_tx, entered_rx) = mpsc::channel();
            first.after_read = Some(Box::new(move || {
                entered_tx.send(()).unwrap();
                worker_release.wait();
            }));
            let first_worker = thread::spawn(move || {
                edit_with_backend(
                    EditSpec {
                        name: service_name(),
                        app_parameters: Some("--first".into()),
                        ..Default::default()
                    },
                    &mut first,
                )
            });
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let result = edit_with_backend(
                EditSpec {
                    name: service_name(),
                    app_parameters: Some("--second".into()),
                    ..Default::default()
                },
                &mut RecordingConfigBackend::new(config()),
            );
            release.wait();
            first_worker.join().unwrap().unwrap();
            result.expect("a different service must not wait for the first service guard");
        }

        #[test]
        fn real_single_value_registry_writer_waits_for_the_outer_edit_guard() {
            let name = service_name();
            let alias = name.to_uppercase();
            let mut backend = RecordingConfigBackend::new(config());
            let release = Arc::new(Barrier::new(2));
            let worker_release = Arc::clone(&release);
            let (entered_tx, entered_rx) = mpsc::channel();
            backend.after_read = Some(Box::new(move || {
                entered_tx.send(()).unwrap();
                worker_release.wait();
            }));
            let edit_worker = thread::spawn(move || {
                edit_with_backend(
                    EditSpec {
                        name,
                        app_parameters: Some("--changed".into()),
                        ..Default::default()
                    },
                    &mut backend,
                )
            });
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let (done_tx, done_rx) = mpsc::channel();
            let writer = thread::spawn(move || {
                // Empty Application is always rejected, even if a service with
                // this unique name existed. This exercises real writer locking
                // without allowing any HKLM mutation.
                done_tx
                    .send(servicemanager_registry::set_value(
                        &alias,
                        "Application",
                        "",
                    ))
                    .unwrap();
            });
            let blocked = matches!(
                done_rx.recv_timeout(Duration::from_millis(80)),
                Err(mpsc::RecvTimeoutError::Timeout)
            );
            release.wait();
            edit_worker.join().unwrap().unwrap();
            let result = done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            writer.join().unwrap();
            assert!(
                blocked,
                "single-value writers must use the same service guard"
            );
            assert!(result.is_err(), "this probe must never mutate the registry");
        }
    }
}
