# Changelog

All notable changes to NGSM. Versions follow `vMAJOR.MINOR.PATCH`; categories follow [Keep a Changelog](https://keepachangelog.com).

## [v0.2.3] — 2026-05-23

Two days of intensive iteration since v0.1.0 — three feature increments, two end-to-end code reviews, and substantial remediation. 114 commits.

### Added

- **Persistent supervisor event log** at `%ProgramData%\NGSM\events.log` (JSON Lines, append-only, rotated at 1 MiB with a `Global\NGSM-events-log-rotate` named mutex for cross-process safety). The supervisor records `started`, `stopped`, `child_exited`, `restarted`, `throttled` events; the GUI Dashboard's Recent Events panel reads from this so it survives restarts.
- **Recovery-policy editor in the GUI** for restart delay / throttle delay / default action / per-exit-code actions.
- **`ngsm recovery <name>` CLI subcommand** (show + set), plus broker `recovery_get` / `recovery_set` ops.
- **Recent Events feed** on the Dashboard.
- **Settings view** in the GUI (auto-refresh toggle, managed-only filter persistence) — preferences persisted to `%APPDATA%\NGSM\config.json` with a `v` schema-versioning field.
- **`servicemanager-ops` crate** centralizes install / list / edit / remove / start / stop / pause / continue / restart / rotate / recovery business logic; CLI, GUI worker, and broker delegate to it.
- **22 new tests** in `servicemanager-win32` covering `JobObject`, `enumerate_descendants`, `validate_runner_location`, `build_run_service_command` (the crate that holds every `unsafe` Win32 call).
- **`clippy::undocumented_unsafe_blocks` lint** enabled on `servicemanager-win32`; all 40 unsafe blocks now carry `// SAFETY:` documentation.

### Changed

- Supervisor `lib.rs` split into focused modules (`rotation.rs`, `hooks.rs`, `event_log.rs`) — 1731 → 1153 lines.
- `validate_absolute_path` tightened to require `X:\…` or `\\server\share\…` (rejects drive-relative `\foo`, drive-with-no-separator `C:foo`, and bare `\\`).
- `install_service` requests `SERVICE_QUERY_STATUS` instead of `SERVICE_ALL_ACCESS` for the handle it immediately drops.
- GUI worker queue is bounded (capacity 16) with Refresh-request coalescing; SCM control channel bounded (capacity 8).
- Scan-warning dialog renamed to "Scan warnings" with service-name-prefixed entries and plain-language labels.
- Slint runtime + build helper hoisted to a single `~1.16` workspace pin.

### Fixed

- **Concurrent event-log rotation** could clobber `events.log.1` under contention; now serialized with a Global named mutex and removes any stale backup before rename (Windows `rename` won't overwrite by default).
- **`ngsm restart --timeout-ms`** was silently ignored after a refactor; now respected.
- **`ngsm rotate --json`** had lost the `state` field; restored.
- **`ngsm remove`** on a running service no longer leaves it marked-for-deletion with its managed config already purged (CLI + broker now match the GUI's stopped-state gate).
- **`--force-native` edits combined with managed-field flags** are now rejected instead of silently dropping the managed fields.
- **Restart button** is no longer enabled for stopped services.
- **`tail_file`** detects UTF-16 BOMs so PowerShell-emitted logs are readable.
- **Function-pointer transmute** in `process_tree::load_ntdll_fn` now goes via `*const ()` (latent UB on x86 `stdcall`).
- **Poisoned-mutex recovery** at six sites in `runtime.rs` / `windows_close.rs` (no longer cascade-panic into SCM status reporting).
- **`PostMessageW` close counter** no longer over-reports successful posts on failure.
- **Config-read errors** are now distinguished from missing-file and surfaced as warnings instead of silently resetting preferences.
- **Background-worker dispatch errors** are now surfaced to the GUI status bar instead of leaving an infinite spinner.

### Security

- `validate_absolute_path` no longer accepts ambiguous drive-relative paths (`\foo` resolves against per-process CWD).
- `ServiceControlSignal::User` codes are validated against the SCM-reserved 128..=255 range before reaching `ControlService`.
- Path-comparison in `validate_runner_location` fails closed on UTF-8 replacement characters rather than risking a heuristic match against the wrong directory.

## [v0.1.0] — 2026-05-21

Initial public release.

- Single `ngsm.exe` binary: desktop GUI, CLI, and Windows service host.
- NSSM-compatible registry layout under each service's `Parameters` key.
- Process supervision with restart / throttle policies, per-exit-code actions (`AppExit`), and a Job Object so the whole process tree dies with the service.
- Graceful shutdown: CTRL+BREAK → WM_CLOSE → WM_QUIT → terminate, each step configurable.
- Log handling — redirect stdout/stderr to files with offline (on-restart) and online (live) rotation by size or age.
- Lifecycle hooks on Start / Stop / Exit / Rotate / Power events, each contained in its own kill-on-close job.
- Environment control — replacement (`AppEnvironment`) and additive (`AppEnvironmentExtra`) environment variables.
- Desktop GUI (Slint) for browse / install / manage.
- Full CLI: `install`, `remove`, `edit`, `list`, `status`, `start` / `stop` / `restart` / `pause` / `continue`, `rotate`, `get` / `set` / `unset`.
- Optional named-pipe broker for headless automation (feature-gated, off by default).
- Statically-linked C runtime — no DLLs to ship.

[v0.2.3]: https://github.com/chstc/NGSM/releases/tag/v0.2.3
[v0.1.0]: https://github.com/chstc/NGSM/releases/tag/v0.1.0
