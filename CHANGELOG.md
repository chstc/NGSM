# Changelog

All notable changes to NGSM. Versions follow `vMAJOR.MINOR.PATCH`; categories follow [Keep a Changelog](https://keepachangelog.com).

## [v0.3.1] — 2026-05-23

Code-review remediation cycle on top of v0.3.0. 20 findings addressed across
3 HIGH (security and correctness), 10 MEDIUM (validation, race, registry
hygiene, doc accuracy), and 7 LOW (cosmetic, error reporting). No new
features; no public API breakage.

### Fixed

- **(H-01)** `validate_absolute_path` now rejects embedded NUL and control
  characters, closing a latent path-truncation hazard at the registry/Win32
  boundary.
- **(H-02)** GUI's `JobSender` no longer leaves `pending_refresh` stuck on
  `true` when a Refresh `try_send` fails — previously, a single transient
  queue-full / disconnected error would silently disable all future
  refreshes until restart.
- **(H-03)** Broker connection watchdog now operates on a duplicated handle
  it owns, eliminating a TOCTOU race where the watchdog could cancel or
  disconnect a reused handle value belonging to an unrelated object.
- **(M-01)** Install now validates the full managed config before touching
  SCM. Invalid `Application` paths, exit-action keys, or hooks are rejected
  up front; rollback remains as defense-in-depth.
- **(M-02)** Supervisor records the child-exit result before clearing
  `current_pid`, so a Stop arriving after the exit but before the
  ChildExited message no longer skips `record_child_exit` (Exit/Post hook
  + `last_exit_code` update).
- **(M-03)** Broker post-op state-query failures are now reported as
  `state: null` + a `warning` field, instead of being collapsed to an empty
  string that looks like success.
- **(M-04)** Registry path-valued fields cleared via the GUI now delete the
  value instead of writing `""`. For stdio paths, the associated
  sharing/disposition/flags/copy-and-truncate attributes are also deleted
  so no orphan settings linger.
- **(M-05)** Registry writer pre-validates every string for embedded NUL
  before any mutation, so a later invalid field can no longer leave earlier
  fields partially written.
- **(M-06)** Recovery exit-action map keys are now validated at the ops
  boundary: only numeric `i32` strings are accepted; `"default"`, empty
  strings, and embedded controls/whitespace/`=` are rejected.
- **(M-07)** CLI hook parser now rejects unsupported `event/action` pairs
  and empty hook commands, so a hook that would never run can no longer
  install successfully.
- **(M-08)** Event-schema doc-comments corrected: unknown variants are
  serde rejections (the GUI reader catches and skips), not silent passes.
  Tests pin the current behavior so adding `#[serde(other)]` later is a
  deliberate, test-breaking change.
- **(M-09)** GUI edit-form trims leading/trailing whitespace in path-like
  fields (`application`, `app_directory`, `stdout`, `stderr`) before
  diffing, so accidental whitespace no longer reaches the registry.
  `app_parameters` whitespace is preserved (CLI args may carry intentional
  spacing).
- **(M-10)** GUI config loader clamps `auto_refresh_secs` into `1..=3600`
  on disk, with a startup warning when correction is needed. Previously
  a hand-edited `0` would display `0` while ticking every second.
- **(L-01)** `cargo fmt` applied across v0.3.0-introduced files
  (paths.rs, data.rs, event_log_reader.rs, metrics.rs, event_log.rs).
- **(L-02)** Supervisor stop/rotate/power signal send failures are now
  logged with the specific signal name instead of being silently dropped.
- **(L-03)** `create_dir_all` failures before log open are now logged with
  the parent path, giving clearer diagnostics than the downstream open
  error alone.

### Changed

- **(L-04)** Supervisor stop-method comment now describes the four
  implemented phases (console, window, thread, terminate) accurately,
  matching the current `AppStopMethodSkip` behavior.
- **(L-05)** CLI package description updated to reflect the full v0.3
  command surface.
- **(L-06)** Runner and supervisor package descriptions dropped historical
  "Phase 2" labels.
- **(L-07)** README architecture statement clarified: NGSM targets all
  Windows architectures, with x64 as the only one routinely built and
  tested.

### Notes

This is a code-review remediation release. The new validation surfaces
(M-01, M-06, M-07, H-01, M-05) reject configurations that v0.3.0 (and
earlier) accepted but the runtime then quietly mishandled. Upgrading from
v0.3.0 will surface those as install/edit errors at the boundary instead
of broken services at runtime.

## [v0.3.0] — 2026-05-23

Dashboard v0.3 — availability metric + tile classification breakdowns. The
mockup's CPU/Memory live charts are deferred to v0.4.

### Added

- **Availability (30d) tile** on the Dashboard, computed from the supervisor
  event log. Per-service availability = fraction of the 30-day window the
  service was up (started/restarted → child_exited/stopped/throttled). The
  aggregate is the unweighted mean across services with any event history.
- **30-day availability sparkline** rendered into the Availability tile,
  one bucket per UTC calendar day. Days with no data carry forward from
  the previous bucket.
- **Tile sub-captions:** "Running N" under Managed services, "Manual start N"
  under Stopped, "Auto-recovering N" under Failed.
- **`Failed` tile** — managed service currently Stopped, last event
  `child_exited` with non-zero exit code within the last 24 h. Future-dated
  events excluded (clock-skew safety).
- **`Auto-recovering` sub-count** — managed service whose last event is
  `throttled` (or a `restarted` following a `child_exited`) within the last
  5 minutes. Future-dated events excluded.
- **"Availability unknown" handling** — when the event log can't be read,
  the tile renders "—" instead of falsely showing 100 %, and a warning
  surfaces in the scan-warnings dialog.
- **`metrics` module** in `servicemanager-gui` (pure, ~30 unit tests
  including cross-bucket carry-over and future-ts regressions).
- **`event_log_reader::read_since`** — windowed scan across all retained
  log files, returns `Result<Vec<EventRecord>>` sorted by parsed
  `OffsetDateTime` (not raw string), with a per-file 16 MiB cap.

### Changed

- **Supervisor event-log retention** widened from 1 MiB / 1 backup to
  8 MiB / 4 backups — 32 MiB in backups, ~40 MiB including the active
  log. Existing v0.2.3 deployments grow their retained history naturally
  on the next rotation; no migration is needed.
- Dashboard "Needs attention" tile replaced by "Failed" + Availability —
  the underlying signal (managed + Automatic + Stopped) is now expressed
  more precisely as "Failed" + the per-tile sub-captions.

### Notes

- Stopped-via-SCM (intentional shutdowns) currently count as downtime in
  the availability metric and sparkline. Planned vs. unplanned distinction
  will follow once event categorisation is richer.
- Daily buckets use UTC calendar days for stability (no DST midnight
  surprises; the supervisor log is also UTC). Drift relative to a user's
  local clock is at most a few hours — well within the precision of a
  30-bucket sparkline.

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

[v0.3.1]: https://github.com/chstc/NGSM/releases/tag/v0.3.1
[v0.3.0]: https://github.com/chstc/NGSM/releases/tag/v0.3.0
[v0.2.3]: https://github.com/chstc/NGSM/releases/tag/v0.2.3
[v0.1.0]: https://github.com/chstc/NGSM/releases/tag/v0.1.0
