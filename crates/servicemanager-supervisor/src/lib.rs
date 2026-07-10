//! Runtime supervision of a managed child process.
//!
//! Phase 2 + hardening responsibilities:
//!
//! - redirects stdout/stderr to the configured log files,
//! - rotates log files in *offline* mode (i.e. on every spawn) when the
//!   configured size/age thresholds are exceeded,
//! - assigns the child to a Job Object so the entire process tree dies with
//!   the runner (or on explicit stop),
//! - attempts a graceful console `CTRL+BREAK` before terminating, gated by
//!   `AppStopMethodSkip` and `AppStopMethodConsole` (NSSM-compatible),
//! - runs `start/pre`, `start/post`, `stop/pre`, and `exit/post` hooks with
//!   a fixed timeout, exposing NSSM-style `NGSM_*` env vars,
//! - applies the per-exit-code `AppExit\<code>` action, falling back to the
//!   default action.
//!
//! Still out of scope (deferred):
//!
//! - the rest of NSSM's hook event surface beyond start/stop/exit/rotate/power.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use servicemanager_core::{ExitAction, IoStream, LogRotationConfig, ManagedApplicationConfig};

#[cfg(windows)]
use servicemanager_win32::{
    enumerate_descendants, post_wm_close_to_process, post_wm_quit_to_process, resume_process,
    send_ctrl_break, suspend_process, terminate_process, JobObject,
};

pub mod event_log;
pub mod hooks;
pub mod rotation;

#[cfg(test)]
pub(crate) static TEST_PROGRAM_DATA_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use hooks::{find_hook, is_resume_event, run_hook, HookPoint};
use rotation::{dedup_sinks, maybe_rotate, pipe_reader_loop, RotationSink};

pub const DEFAULT_RESTART_DELAY_MS: u32 = 0;
pub const DEFAULT_THROTTLE_DELAY_MS: u32 = 1500;
pub const THROTTLE_THRESHOLD_MS: u128 = 1500;
/// Matches NSSM's default grace period for the console-event step.
pub const DEFAULT_CONSOLE_GRACE_MS: u32 = 1500;
/// Matches NSSM's default grace period for the WM_CLOSE step.
pub const DEFAULT_WINDOW_GRACE_MS: u32 = 1500;
/// Matches NSSM's default grace period for the WM_QUIT (thread-message) step.
pub const DEFAULT_THREADS_GRACE_MS: u32 = 1500;

/// Bits in `AppStopMethodSkip` (mirrors NSSM's `AppStopMethodSkip`). Each bit
/// suppresses one phase of the graceful-stop pipeline implemented by
/// [`Supervisor::stop_child_gracefully`]. The phases run in order; each one
/// is skipped if the corresponding bit is set in
/// `ManagedApplicationConfig::shutdown::stop_method_skip`, otherwise it runs
/// and waits up to its configured grace period for the child to exit before
/// the next phase is attempted:
///
/// 1. **Console** (`0x1`) — send `CTRL+BREAK` to the child's process group
///    (`GenerateConsoleCtrlEvent`). Honoured by console apps that install a
///    handler with `SetConsoleCtrlHandler`. Grace: `kill_console_grace_ms`.
/// 2. **Window** (`0x2`) — walk every visible top-level window owned by any
///    process in the job and `PostMessage(WM_CLOSE)`. Honoured by
///    well-behaved GUI apps. Grace: `kill_window_grace_ms`.
/// 3. **Threads** (`0x4`) — `PostThreadMessage(WM_QUIT)` to every thread in
///    every process in the job. Catches UI threads whose message loops pump
///    thread messages but never dispatch a `WindowProc`. Grace:
///    `kill_threads_grace_ms`.
/// 4. **Terminate** (`0x8`) — last-resort kill. If `kill_process_tree` is
///    set (the default), this calls `TerminateJobObject(1)` so the entire
///    descendant tree dies promptly; otherwise the single managed child is
///    killed via `TerminateProcess` and the rest of the tree only dies a
///    moment later when the job handle is dropped (the job is always
///    `KILL_ON_JOB_CLOSE`).
pub const STOP_METHOD_SKIP_CONSOLE: u32 = 0x1;
pub const STOP_METHOD_SKIP_WINDOW: u32 = 0x2;
pub const STOP_METHOD_SKIP_THREADS: u32 = 0x4;
pub const STOP_METHOD_SKIP_TERMINATE: u32 = 0x8;

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("application path is not configured")]
    MissingApplication,
    #[error("spawn {0:?}: {1}")]
    Spawn(PathBuf, #[source] std::io::Error),
    #[error("open log file {0:?}: {1}")]
    OpenLog(PathBuf, #[source] std::io::Error),
    #[error("open stdin file {0:?}: {1}")]
    OpenStdin(PathBuf, #[source] std::io::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("core: {0}")]
    Core(#[from] servicemanager_core::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Stopped,
    ChildExited,
    SpawnFailed,
    /// The supervisor applied `ExitAction::Suicide` for the most recent
    /// child generation. Per NSSM convention this is a *deliberate* failure
    /// — the supervisor exits so SCM's recovery actions (restart-service,
    /// reboot, run-command) fire. The runner MUST report a non-zero exit
    /// code to SCM in this case; reporting zero would look like a clean
    /// stop and silently suppress recovery. The carried `exit_code` is the
    /// child's own exit code, preserved so the runner can pass through a
    /// meaningful non-zero value when one is available.
    Suicide {
        exit_code: i32,
    },
}

#[derive(Clone)]
pub struct StopSignal {
    tx: Sender<SupervisorMessage>,
}

impl StopSignal {
    pub fn stop(&self) {
        if let Err(e) = self.tx.send(SupervisorMessage::Stop) {
            eprintln!("[supervisor:stop] signal channel closed: {e}");
        }
    }
}

enum SupervisorMessage {
    Stop,
    Rotate,
    /// Suspend the process tree. The supervisor reports the outcome (`true`
    /// = every process suspended) back over the enclosed channel so the
    /// runner only tells SCM `PAUSED` once the work has actually happened.
    Pause(Sender<bool>),
    /// Resume the process tree; acknowledged like [`SupervisorMessage::Pause`].
    Continue(Sender<bool>),
    /// SCM delivered a power event; payload is the `dwEventType` (`PBT_*`).
    PowerEvent(u32),
    ChildExited(io::Result<std::process::ExitStatus>),
}

/// Sender side used by the runner to ask the supervisor to rotate logs on
/// demand (e.g. from `servicemanager rotate <name>`).
#[derive(Clone)]
pub struct RotateSignal {
    tx: Sender<SupervisorMessage>,
}

impl RotateSignal {
    pub fn rotate(&self) {
        if let Err(e) = self.tx.send(SupervisorMessage::Rotate) {
            eprintln!("[supervisor:rotate] signal channel closed: {e}");
        }
    }
}

/// Sender side used by the runner to forward SCM pause/continue controls.
#[derive(Clone)]
pub struct PauseContinueSignal {
    tx: Sender<SupervisorMessage>,
}

/// How long [`PauseContinueSignal::pause`]/`resume` waits for the supervisor
/// to acknowledge the suspend/resume. The supervisor normally answers
/// immediately; the only real delay is a hook (or graceful-stop step) it is
/// in the middle of running.
const PAUSE_CONTINUE_ACK_TIMEOUT: Duration = Duration::from_secs(15);

impl PauseContinueSignal {
    /// Ask the supervisor to suspend the process tree and block until it
    /// reports the outcome. `Ok(())` means every process was suspended;
    /// `Err` means the supervisor is gone, did not answer in time, or could
    /// not suspend at least one process. The runner uses this to avoid
    /// telling SCM `PAUSED` before the pause has actually taken effect.
    pub fn pause(&self) -> Result<(), String> {
        let (ack_tx, ack_rx) = mpsc::channel();
        self.tx
            .send(SupervisorMessage::Pause(ack_tx))
            .map_err(|_| "supervisor is no longer running".to_string())?;
        interpret_ack(ack_rx.recv_timeout(PAUSE_CONTINUE_ACK_TIMEOUT), "pause")
    }

    /// Resume the process tree; semantics mirror [`Self::pause`].
    pub fn resume(&self) -> Result<(), String> {
        let (ack_tx, ack_rx) = mpsc::channel();
        self.tx
            .send(SupervisorMessage::Continue(ack_tx))
            .map_err(|_| "supervisor is no longer running".to_string())?;
        interpret_ack(ack_rx.recv_timeout(PAUSE_CONTINUE_ACK_TIMEOUT), "continue")
    }
}

fn interpret_ack(
    ack: std::result::Result<bool, RecvTimeoutError>,
    what: &str,
) -> Result<(), String> {
    match ack {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!(
            "{what}: one or more processes could not be updated"
        )),
        Err(_) => Err(format!("{what}: supervisor did not acknowledge in time")),
    }
}

/// Sender side used by the runner to forward SCM power events. The
/// supervisor maps the `dwEventType` to a `Power/Change` or
/// `Power/Resume` hook.
#[derive(Clone)]
pub struct PowerEventSignal {
    tx: Sender<SupervisorMessage>,
}

impl PowerEventSignal {
    pub fn power_event(&self, event_type: u32) {
        if let Err(e) = self.tx.send(SupervisorMessage::PowerEvent(event_type)) {
            eprintln!("[supervisor:power] signal channel closed: {e}");
        }
    }
}

pub struct Supervisor {
    name: String,
    config: ManagedApplicationConfig,
    rx: Receiver<SupervisorMessage>,
    tx: Sender<SupervisorMessage>,
    current_child: Arc<Mutex<Option<Child>>>,
    current_pid: Arc<Mutex<Option<u32>>>,
    last_exit_code: Arc<Mutex<Option<i32>>>,
    /// Exit code of a child that exited but whose `ChildExited` message
    /// has not yet been observed by the main supervisor loop. Written by
    /// the exit watcher *before* it clears `current_pid`, so a Stop that
    /// arrives in the racing window between "child died" and "main loop
    /// processed ChildExited" can still find the result and run
    /// `record_child_exit` (which fires the `Exit/Post` hook and updates
    /// `last_exit_code`). Without this, a Stop that won the channel race
    /// would see `current_pid == None`, return early from
    /// `stop_child_gracefully`, and skip both bookkeeping steps.
    pending_exit: Arc<Mutex<Option<i32>>>,
    /// Sinks that own the actual log files when online rotation is enabled.
    /// One per redirected stream, keyed by stream name ("stdout"/"stderr").
    sinks: Vec<Arc<RotationSink>>,
    /// Fires exactly once, when the first managed child has actually been
    /// spawned and its `start/post` hook has run. The runner waits on the
    /// matching receiver before reporting `SERVICE_RUNNING` to the SCM.
    startup_tx: Sender<()>,
    startup_rx: Option<Receiver<()>>,
    #[cfg(windows)]
    job: Option<Arc<JobObject>>,
}

impl Supervisor {
    pub fn new(name: impl Into<String>, config: ManagedApplicationConfig) -> Self {
        let (tx, rx) = mpsc::channel();
        let (startup_tx, startup_rx) = mpsc::channel();
        Self {
            name: name.into(),
            config,
            rx,
            tx,
            current_child: Arc::new(Mutex::new(None)),
            current_pid: Arc::new(Mutex::new(None)),
            last_exit_code: Arc::new(Mutex::new(None)),
            pending_exit: Arc::new(Mutex::new(None)),
            sinks: Vec::new(),
            startup_tx,
            startup_rx: Some(startup_rx),
            #[cfg(windows)]
            job: None,
        }
    }

    /// Take the receiver that fires once the first managed child has started.
    /// The runner waits on this before reporting `SERVICE_RUNNING` to SCM, so
    /// the service is not announced as running before the application is.
    ///
    /// Must be called exactly once, before [`Supervisor::run`].
    pub fn startup_receiver(&mut self) -> Receiver<()> {
        self.startup_rx
            .take()
            .expect("startup_receiver must be called exactly once")
    }

    pub fn stop_signal(&self) -> StopSignal {
        StopSignal {
            tx: self.tx.clone(),
        }
    }

    pub fn rotate_signal(&self) -> RotateSignal {
        RotateSignal {
            tx: self.tx.clone(),
        }
    }

    pub fn pause_continue_signal(&self) -> PauseContinueSignal {
        PauseContinueSignal {
            tx: self.tx.clone(),
        }
    }

    pub fn power_event_signal(&self) -> PowerEventSignal {
        PowerEventSignal {
            tx: self.tx.clone(),
        }
    }

    pub fn last_exit_code(&self) -> Option<i32> {
        *self.last_exit_code.lock().unwrap()
    }

    pub fn run(mut self) -> Result<ExitReason, SupervisorError> {
        let default_action = self
            .config
            .restart
            .default_action
            .unwrap_or(ExitAction::Restart);
        let restart_delay = Duration::from_millis(
            self.config
                .restart
                .restart_delay_ms
                .unwrap_or(DEFAULT_RESTART_DELAY_MS) as u64,
        );
        let throttle_delay = Duration::from_millis(
            self.config
                .restart
                .throttle_delay_ms
                .unwrap_or(DEFAULT_THROTTLE_DELAY_MS) as u64,
        );

        let writer = event_log::EventWriter::for_service(self.name.clone());

        // Track restart bookkeeping: `is_first_generation` distinguishes
        // the initial spawn from a restart, and `last_delay_ms` is the
        // delay we just slept so the upcoming `restarted` event can
        // report it.
        let mut is_first_generation = true;
        let mut last_delay_ms: u64 = 0;

        // Set once the first child generation is up, so the startup signal
        // to the runner fires exactly once (not again on every restart).
        let mut startup_reported = false;

        loop {
            // start/pre hook runs *before* we spawn so the hook can prepare
            // the environment (warm caches, fetch secrets, etc.).
            self.fire_hook(HookPoint::StartPre, None, None);

            // A fresh job object per child generation. Installing the new
            // job drops the previous one; KILL_ON_JOB_CLOSE then terminates
            // any grandchildren of the prior generation that outlived their
            // parent, so they cannot collide with the process we spawn next.
            #[cfg(windows)]
            self.refresh_job()?;

            // Drop the previous generation's rotation sinks before this spawn
            // repopulates them; otherwise `self.sinks` grows without bound
            // across restarts, leaking file handles and memory.
            self.sinks.clear();

            let spawn_started = Instant::now();
            match self.spawn_once() {
                Ok(child) => {
                    let pid = child.id();
                    // Job assignment must succeed before the child runs. If it
                    // fails, the child would run *outside* the kill-on-close
                    // job and its descendants could escape lifecycle cleanup —
                    // so kill the still-suspended child and apply the restart
                    // policy instead of resuming it un-jobbed.
                    if let Err(e) = self.attach_to_job(&child) {
                        eprintln!(
                            "[supervisor:{}] job assignment failed: {e} — killing un-jobbed child",
                            self.name
                        );
                        let mut child = child;
                        let _ = child.kill();
                        let _ = child.wait();
                        self.set_current(None);
                        if matches!(default_action, ExitAction::Exit | ExitAction::Suicide) {
                            return Err(e);
                        }
                        if !self.sleep_or_stop(throttle_delay)? {
                            return Ok(ExitReason::Stopped);
                        }
                        continue;
                    }
                    self.set_current(Some(child));
                    // The child was created suspended so it could be placed in
                    // the job before executing anything. Resume it *before*
                    // spawning the exit watcher: a failed resume means the
                    // child never ran, and with no watcher running we can reap
                    // it here without racing for the `Child` handle. Treat a
                    // failed resume as a startup failure — StartPost must not
                    // fire and SERVICE_RUNNING must not be reported for a
                    // child that is dead on arrival.
                    #[cfg(windows)]
                    if let Err(e) = self.resume_child(pid) {
                        eprintln!(
                            "[supervisor:{}] could not resume child pid={pid}: {e} — \
                             terminating it and applying the restart policy",
                            self.name
                        );
                        let _ = terminate_process(pid, 1);
                        if let Some(mut c) = self.current_child.lock().unwrap().take() {
                            let _ = c.wait();
                        }
                        self.set_current(None);
                        if matches!(default_action, ExitAction::Exit | ExitAction::Suicide) {
                            return Err(e);
                        }
                        if !self.sleep_or_stop(throttle_delay)? {
                            return Ok(ExitReason::Stopped);
                        }
                        continue;
                    }
                    self.spawn_exit_watcher();
                    self.fire_hook(HookPoint::StartPost, Some(pid), None);
                    if is_first_generation {
                        writer.started(pid);
                        is_first_generation = false;
                    } else {
                        writer.restarted(pid, last_delay_ms);
                    }
                    // The application is now genuinely running — let the
                    // runner report SERVICE_RUNNING to SCM.
                    if !startup_reported {
                        let _ = self.startup_tx.send(());
                        startup_reported = true;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[supervisor:{}] spawn failed: {e}. Applying restart policy.",
                        self.name
                    );
                    self.set_current(None);
                    if matches!(default_action, ExitAction::Exit | ExitAction::Suicide) {
                        return Err(e);
                    }
                    // A spawn failure is a failed start — throttle the retry
                    // (`throttle_delay`, not the possibly-zero `restart_delay`)
                    // so a permanently-bad application path cannot spin this
                    // loop at full tilt, starving the Stop signal.
                    if !self.sleep_or_stop(throttle_delay)? {
                        return Ok(ExitReason::Stopped);
                    }
                    continue;
                }
            }

            // Drain channel: handle Rotate / Pause / Continue / Power
            // without leaving the outer state machine. Stop and
            // ChildExited are the only transitions.
            let next = loop {
                match self.rx.recv() {
                    Ok(SupervisorMessage::Rotate) => self.rotate_sinks_now(),
                    Ok(SupervisorMessage::Pause(ack)) => {
                        let _ = ack.send(self.suspend_tree());
                    }
                    Ok(SupervisorMessage::Continue(ack)) => {
                        let _ = ack.send(self.resume_tree());
                    }
                    Ok(SupervisorMessage::PowerEvent(ev)) => self.handle_power_event(ev),
                    other => break other,
                }
            };

            match next {
                Ok(SupervisorMessage::Stop) => {
                    let pid = *self.current_pid.lock().unwrap();
                    self.fire_hook(HookPoint::StopPre, pid, None);
                    // If we were paused when stop arrives, resume first
                    // so the graceful steps and the kernel terminate
                    // path can actually run.
                    self.resume_tree();
                    self.stop_child_gracefully();
                    writer.stopped(servicemanager_core::events::StopReason::ScmStop);
                    return Ok(ExitReason::Stopped);
                }
                Ok(SupervisorMessage::Rotate)
                | Ok(SupervisorMessage::Pause(_))
                | Ok(SupervisorMessage::Continue(_))
                | Ok(SupervisorMessage::PowerEvent(_)) => unreachable!(),
                Ok(SupervisorMessage::ChildExited(result)) => {
                    let lived = spawn_started.elapsed();
                    let exit_code = exit_code_of(&result);
                    self.record_child_exit(exit_code);
                    writer.child_exited(exit_code, lived.as_millis() as u64);

                    // A configured `AppExit\<code>` action takes precedence
                    // over the default; fall back to the default action when
                    // this exit code has no specific entry.
                    let action = self
                        .config
                        .exit_actions
                        .get(&exit_code.to_string())
                        .map(|p| p.action)
                        .unwrap_or(default_action);

                    match action {
                        ExitAction::Restart => {
                            let delay = if lived.as_millis() < THROTTLE_THRESHOLD_MS {
                                throttle_delay
                            } else {
                                restart_delay
                            };
                            let delay_ms = delay.as_millis() as u64;
                            last_delay_ms = delay_ms;
                            if delay_ms > 0 {
                                writer.throttled(delay_ms);
                                if !self.sleep_or_stop(delay)? {
                                    return Ok(ExitReason::Stopped);
                                }
                            }
                            continue;
                        }
                        ExitAction::Ignore => {
                            // `Ignore` means "the child exited; don't respawn,
                            // but the *service* (i.e. the supervisor itself)
                            // stays running so SCM can stop it cleanly later".
                            // Collapsing this into the `Restart` arm — as the
                            // pre-fix code did — defeats the recovery policy
                            // by silently restarting the child anyway.
                            //
                            // The supervisor therefore enters a quiesced wait:
                            // no child is spawned, but the message loop keeps
                            // draining control signals so a later Stop /
                            // Shutdown from SCM still ends the service
                            // cleanly. Rotate / Pause / Continue / Power are
                            // also handled so the channel cannot fill up and
                            // strand the runner.
                            eprintln!(
                                "[supervisor:{}] child exited with code {exit_code}; \
                                 AppExit action is `Ignore` — supervisor remains \
                                 running and will NOT respawn the child until \
                                 SCM stops the service",
                                self.name
                            );
                            return self.wait_for_stop_quiesced();
                        }
                        ExitAction::Exit => {
                            // Clean stop: the supervisor gives up; SCM is
                            // NOT expected to run recovery actions.
                            return Ok(ExitReason::ChildExited);
                        }
                        ExitAction::Suicide => {
                            // Deliberate failure: the supervisor exits and
                            // SCM's recovery actions are expected to fire.
                            // Carry the child's exit code so the runner can
                            // pass through a meaningful non-zero value
                            // (falling back to 1 when the child's own code
                            // was 0).
                            return Ok(ExitReason::Suicide { exit_code });
                        }
                    }
                }
                Err(_) => {
                    self.stop_child_gracefully();
                    writer.stopped(servicemanager_core::events::StopReason::ScmStop);
                    return Ok(ExitReason::Stopped);
                }
            }
        }
    }

    fn spawn_once(&mut self) -> Result<Child, SupervisorError> {
        let application = self
            .config
            .application
            .as_ref()
            .ok_or(SupervisorError::MissingApplication)?;
        // A relative application path would resolve through the service
        // account's PATH / current directory — refuse to spawn an ambiguous
        // binary. `AppDirectory` and the stdio paths are revalidated the
        // same way: full-config writes already check them, but the
        // single-value `set` API and legacy-NSSM imports can still persist a
        // relative path, and the service account is about to use them.
        servicemanager_core::validate_absolute_path("application", application)
            .map_err(SupervisorError::Core)?;
        if let Some(dir) = self
            .config
            .app_directory
            .as_deref()
            .filter(|d| !d.is_empty())
        {
            servicemanager_core::validate_absolute_path("app_directory", dir)
                .map_err(SupervisorError::Core)?;
        }
        for (label, stream) in [
            ("stdin", &self.config.io.stdin),
            ("stdout", &self.config.io.stdout),
            ("stderr", &self.config.io.stderr),
        ] {
            if let Some(s) = stream {
                servicemanager_core::validate_absolute_path(label, &s.path)
                    .map_err(SupervisorError::Core)?;
            }
        }
        let exe = PathBuf::from(application);

        let mut cmd = Command::new(&exe);
        if let Some(args) = self.config.app_parameters.as_deref() {
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.raw_arg(args);
            }
            #[cfg(not(windows))]
            {
                cmd.arg(args);
            }
        }
        if let Some(dir) = self.config.app_directory.as_deref() {
            if !dir.is_empty() {
                cmd.current_dir(dir);
            }
        }

        // Apply the configured environment. `environment` (NSSM
        // `AppEnvironment`) fully *replaces* the inherited environment;
        // `environment_extra` (`AppEnvironmentExtra`) is then layered on top
        // — of the replacement set, or of the inherited environment when no
        // replacement was configured.
        if !self.config.environment.is_empty() {
            cmd.env_clear();
            for entry in &self.config.environment {
                let (k, v) = parse_env_entry(entry)?;
                cmd.env(k, v);
            }
        }
        for entry in &self.config.environment_extra {
            let (k, v) = parse_env_entry(entry)?;
            cmd.env(k, v);
        }

        // stdout/stderr file redirection. Online rotation (when
        // `AppRotateOnline != 0`) uses a pipe so the supervisor's reader
        // thread can rotate the file mid-flight; offline rotation just
        // hands the file directly to the child like before.
        //
        // Clone the streams up front so the closures we hand to
        // `attach_pipe_sink` (which take `&mut self`) don't fight the
        // borrow checker over the immutable `&self.config`.
        let online = matches!(self.config.rotation.online, Some(v) if v != 0)
            && self.config.rotation.enabled == Some(true);
        let stdout_stream = self.config.io.stdout.clone();
        let stderr_stream = self.config.io.stderr.clone();
        let stdin_stream = self.config.io.stdin.clone();
        let rotation = self.config.rotation.clone();

        if online {
            // Online rotation: stdout and stderr may target the same file.
            // Build at most one `RotationSink` per unique path and share it
            // between both streams so a rotation triggered by one writer is
            // visible to the other (single mutex, single file handle, single
            // byte counter). Two independent sinks would race on every
            // rotation — see finding #11.
            let (stdout_sink, stderr_sink, unique) =
                dedup_sinks(stdout_stream.as_ref(), stderr_stream.as_ref(), &rotation)?;
            // Keep the deduplicated sinks alive for the lifetime of this
            // child. `rotate_sinks_now` iterates `self.sinks`, so storing
            // only the unique set ensures an on-demand `Rotate` doesn't
            // rotate the same underlying file twice.
            for sink in unique {
                self.sinks.push(sink);
            }
            if let Some(sink) = stdout_sink {
                cmd.stdout(self.attach_pipe_sink("stdout", sink)?);
            }
            if let Some(sink) = stderr_sink {
                cmd.stderr(self.attach_pipe_sink("stderr", sink)?);
            }
        } else {
            if let Some(stream) = &stdout_stream {
                cmd.stdout(open_log_file(stream, &rotation)?);
            }
            if let Some(stream) = &stderr_stream {
                cmd.stderr(open_log_file(stream, &rotation)?);
            }
        }
        if let Some(stream) = &stdin_stream {
            // Stdin is an *input*: open it read-only. It must never be
            // created, truncated, appended to, or rotated like a log file.
            cmd.stdin(open_stdin_file(stream)?);
        }

        #[cfg(windows)]
        {
            // CREATE_NEW_PROCESS_GROUP scopes the CTRL+BREAK we send later to
            // the child instead of leaking it to us or its siblings.
            // CREATE_SUSPENDED lets the supervisor assign the child to its
            // job object before it runs a single instruction, so descendants
            // it spawns cannot escape the job. We use the literals to avoid
            // pulling the `windows` crate in for two numbers.
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            const CREATE_SUSPENDED: u32 = 0x0000_0004;
            use std::os::windows::process::CommandExt;
            let mut flags = CREATE_SUSPENDED;
            if self.console_step_enabled() {
                flags |= CREATE_NEW_PROCESS_GROUP;
            }
            cmd.creation_flags(flags);
        }

        cmd.spawn()
            .map_err(|e| SupervisorError::Spawn(exe.clone(), e))
    }

    /// Install a fresh job object for the next child generation. Replacing
    /// `self.job` drops the previous `Arc<JobObject>` — of which the
    /// supervisor is the only owner — closing that handle and terminating
    /// the prior generation's surviving members via KILL_ON_JOB_CLOSE.
    #[cfg(windows)]
    fn refresh_job(&mut self) -> Result<(), SupervisorError> {
        self.job = Some(Arc::new(JobObject::new_kill_on_close()?));
        Ok(())
    }

    /// Resume a child that was created with `CREATE_SUSPENDED`. Returns an
    /// error if the resume fails; the caller terminates the dead-on-arrival
    /// child and applies the restart policy as a startup failure, rather than
    /// reporting a child that never executed as running.
    #[cfg(windows)]
    fn resume_child(&self, pid: u32) -> Result<(), SupervisorError> {
        resume_process(pid).map_err(SupervisorError::Core)
    }

    /// Assign the freshly-spawned (still-suspended) child to the current job.
    /// Returns an error if assignment fails, so the caller can refuse to
    /// resume a child that would run outside the kill-on-close job.
    #[cfg(windows)]
    fn attach_to_job(&self, child: &Child) -> Result<(), SupervisorError> {
        match &self.job {
            Some(job) => job.assign_child(child).map_err(SupervisorError::Core),
            None => Err(SupervisorError::Core(servicemanager_core::Error::other(
                "no job object available for child assignment",
            ))),
        }
    }

    #[cfg(not(windows))]
    fn attach_to_job(&self, _child: &Child) -> Result<(), SupervisorError> {
        Ok(())
    }

    fn spawn_exit_watcher(&self) {
        let child_slot = Arc::clone(&self.current_child);
        let pid_slot = Arc::clone(&self.current_pid);
        let pending_exit = Arc::clone(&self.pending_exit);
        let tx = self.tx.clone();
        thread::spawn(move || {
            let mut child = {
                let mut guard = child_slot.lock().unwrap();
                match guard.take() {
                    Some(c) => c,
                    None => return,
                }
            };
            let result = child.wait();
            // Stash the resolved exit code *before* we clear `current_pid`.
            // The PID clear is what makes a racing Stop see "no child" and
            // skip the graceful-stop pipeline; without `pending_exit` first
            // that Stop would never reach `record_child_exit`, dropping the
            // `last_exit_code` update and the `Exit/Post` hook. With it,
            // `stop_child_gracefully` can detect "the child already exited"
            // and run the bookkeeping deterministically. The exit code is
            // stored *before* the PID clear so the Stop handler that beats
            // the `ChildExited` message in the channel can still see it.
            let exit_code = exit_code_of(&result);
            *pending_exit.lock().unwrap() = Some(exit_code);
            // Clear the PID *before* announcing the exit. Once the child is
            // dead the OS can recycle its PID, so any stop/pause/continue
            // path that snapshots `current_pid` after this point gets `None`
            // and skips — it can never target a process that inherited the
            // reused PID, even while the `ChildExited` message is still
            // queued.
            *pid_slot.lock().unwrap() = None;
            *child_slot.lock().unwrap() = Some(child);
            let _ = tx.send(SupervisorMessage::ChildExited(result));
        });
    }

    fn set_current(&self, child: Option<Child>) {
        *self.current_pid.lock().unwrap() = child.as_ref().map(|c| c.id());
        *self.current_child.lock().unwrap() = child;
    }

    fn stop_child_gracefully(&mut self) {
        // If the exit watcher already saw the child die — but its
        // `ChildExited` message has not yet been processed by the main loop
        // — `pending_exit` holds the resolved code while `current_pid` has
        // already been cleared. Process the exit here so `last_exit_code`
        // gets updated and the `Exit/Post` hook fires; otherwise this code
        // path returns early below and both bookkeeping steps are skipped.
        if let Some(code) = self.pending_exit.lock().unwrap().take() {
            self.record_child_exit(code);
            return;
        }
        let pid = *self.current_pid.lock().unwrap();
        let Some(pid) = pid else {
            return;
        };

        let skip_mask = self.config.shutdown.stop_method_skip.unwrap_or(0);
        let skip_console = skip_mask & STOP_METHOD_SKIP_CONSOLE != 0;
        let skip_window = skip_mask & STOP_METHOD_SKIP_WINDOW != 0;
        let skip_threads = skip_mask & STOP_METHOD_SKIP_THREADS != 0;
        let skip_terminate = skip_mask & STOP_METHOD_SKIP_TERMINATE != 0;
        let console_grace_ms = self
            .config
            .shutdown
            .kill_console_grace_ms
            .unwrap_or(DEFAULT_CONSOLE_GRACE_MS);
        let window_grace_ms = self
            .config
            .shutdown
            .kill_window_grace_ms
            .unwrap_or(DEFAULT_WINDOW_GRACE_MS);
        let threads_grace_ms = self
            .config
            .shutdown
            .kill_threads_grace_ms
            .unwrap_or(DEFAULT_THREADS_GRACE_MS);

        // Every PID-based step below is guarded by `pid_in_job`: it confirms
        // the PID still refers to a live member of our job, so a child that
        // exited (and a PID Windows then recycled) can never be sent a
        // control meant for the managed child.
        #[cfg(windows)]
        if !skip_console && self.pid_in_job(pid) {
            if let Err(e) = send_ctrl_break(pid) {
                eprintln!("[supervisor:{}] CTRL+BREAK failed: {e}", self.name);
            } else if let Some(code) =
                self.wait_for_exit(Duration::from_millis(console_grace_ms as u64))
            {
                self.record_child_exit(code);
                return;
            }
        }

        // Window-message step. Walks every visible top-level window owned
        // by the child (and descendants) and posts `WM_CLOSE`. Most
        // well-behaved GUI apps start their shutdown sequence on receipt.
        #[cfg(windows)]
        if !skip_window {
            self.post_wm_close_to_tree();
            if let Some(code) = self.wait_for_exit(Duration::from_millis(window_grace_ms as u64)) {
                self.record_child_exit(code);
                return;
            }
        }

        // Thread-message step. PostThreadMessage WM_QUIT to every thread in
        // the process tree — handles UI threads whose message loops don't
        // dispatch WindowProc calls but still pump thread messages.
        #[cfg(windows)]
        if !skip_threads {
            self.post_wm_quit_to_tree();
            if let Some(code) = self.wait_for_exit(Duration::from_millis(threads_grace_ms as u64)) {
                self.record_child_exit(code);
                return;
            }
        }

        // `AppKillProcessTree` semantics: the supervisor's job object is
        // *always* `KILL_ON_JOB_CLOSE`, so when the service stops and the job
        // handle is dropped the entire process tree is terminated regardless
        // of this setting. `kill_process_tree` therefore only controls
        // whether the tree is killed *promptly* here (an explicit
        // `TerminateJobObject`) or a moment later when the job closes — it
        // cannot keep descendants alive past service stop.
        let kill_tree = self.config.shutdown.kill_process_tree.unwrap_or(true);

        if !skip_terminate {
            #[cfg(windows)]
            {
                if kill_tree {
                    if let Some(job) = self.job.as_ref() {
                        if let Err(e) = job.terminate(1) {
                            eprintln!("[supervisor:{}] TerminateJobObject failed: {e}", self.name);
                        }
                    }
                }
                // The exit-watcher thread owns the `Child` (it is blocked in
                // `wait()`), so `Child::kill` is not available here.
                // Terminating by PID covers a job termination that was
                // skipped (`kill_tree` false) or failed — but only once
                // `pid_in_job` confirms the PID is still our child, so a
                // recycled PID is never terminated.
                if self.pid_in_job(pid) {
                    if let Err(e) = terminate_process(pid, 1) {
                        eprintln!(
                            "[supervisor:{}] terminate_process({pid}) failed: {e}",
                            self.name
                        );
                    }
                }
            }
            // Fall back to killing the immediate child where there is no job.
            //
            // KNOWN LIMITATION (finding #15): while the exit watcher is
            // blocked in `Child::wait()` it has already `take()`n the
            // `Child` out of `self.current_child` (see `spawn_exit_watcher`).
            // The slot we re-acquire here is therefore `None` for the
            // common case of "child still running", and this fallback
            // becomes a no-op — leaving the managed child running while the
            // supervisor reports `Stopped`. A robust fix would require a
            // shared kill handle (e.g. cache the PID separately and signal
            // via `libc::kill(pid, SIGTERM)` / `nix::sys::signal::kill`),
            // but neither `libc` nor `nix` is a workspace dependency today
            // and NGSM is a Windows-only product (the Windows path above
            // covers the same scenario via Job Objects + `TerminateProcess`).
            // Accepting the limitation rather than pulling in a new
            // dependency for a CI-only code path. If the project ever
            // ships a non-Windows release, revisit and add `libc`/`nix`.
            #[cfg(not(windows))]
            if let Some(mut child) = self.current_child.lock().unwrap().take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            // Let the exit watcher observe the termination and report it so
            // the child handle is reaped (and Exit/Post fires) before we
            // return.
            if let Some(code) = self.wait_for_exit(Duration::from_millis(2_000)) {
                self.record_child_exit(code);
            }
        } else {
            // Caller asked us not to terminate. Give the console step one
            // final chance to register a clean exit so the runner doesn't
            // block forever.
            if let Some(code) = self.wait_for_exit(Duration::from_millis(2_000)) {
                self.record_child_exit(code);
            }
        }

        // Drop kill_tree unused warning when not on Windows.
        let _ = kill_tree;
    }

    /// Wait up to `delay` for the exit watcher to report `ChildExited`.
    /// Returns the child's exit code if it exited within the window, so the
    /// caller can record the exit and fire the `Exit/Post` hook.
    fn wait_for_exit(&self, delay: Duration) -> Option<i32> {
        let deadline = Instant::now() + delay;
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            match self.rx.recv_timeout(remaining) {
                Ok(SupervisorMessage::ChildExited(result)) => return Some(exit_code_of(&result)),
                Ok(SupervisorMessage::Stop) => { /* drain duplicate stops */ }
                Ok(SupervisorMessage::Rotate) => self.rotate_sinks_now(),
                Ok(SupervisorMessage::Pause(ack)) => {
                    let _ = ack.send(self.suspend_tree());
                }
                Ok(SupervisorMessage::Continue(ack)) => {
                    let _ = ack.send(self.resume_tree());
                }
                Ok(SupervisorMessage::PowerEvent(ev)) => self.handle_power_event(ev),
                Err(RecvTimeoutError::Timeout) => return None,
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
        None
    }

    /// Build a write-end pipe handed to the child as its stdio and spawn a
    /// reader thread that funnels the child's output into the provided
    /// [`RotationSink`]. The sink is supplied by [`dedup_sinks`] so that
    /// stdout and stderr targeting the same path share a single mutex,
    /// file handle, and rotation state (see finding #11).
    fn attach_pipe_sink(
        &mut self,
        label: &str,
        sink: Arc<RotationSink>,
    ) -> Result<Stdio, SupervisorError> {
        let (reader, writer) = os_pipe::pipe().map_err(SupervisorError::Io)?;

        let name = self.name.clone();
        let label = label.to_string();
        thread::spawn(move || pipe_reader_loop(name, label, reader, sink));

        Ok(Stdio::from(writer))
    }

    /// Force-rotate every active sink. Called when a `Rotate` message
    /// arrives (either from the runner via `SERVICE_CONTROL_USER 174` or
    /// internally during shutdown).
    fn rotate_sinks_now(&self) {
        // Only online (pipe-backed) stdout/stderr produce rotatable sinks.
        // With offline redirection the child holds the log handle directly,
        // so an on-demand rotate genuinely has nothing to do — say so rather
        // than pretend it rotated.
        if self.sinks.is_empty() {
            eprintln!(
                "[supervisor:{}] rotate requested, but this service has no online log \
                 sinks — offline logs rotate on restart, not on demand",
                self.name
            );
        }
        // Pre-rotate hook fires once per rotation event; we don't bother
        // firing per-sink. Order is Pre → rotate all sinks → Post.
        self.fire_hook(
            HookPoint::RotatePre,
            *self.current_pid.lock().unwrap(),
            None,
        );
        for sink in &self.sinks {
            if let Err(e) = sink.force_rotate() {
                eprintln!("[supervisor:{}] force_rotate failed: {e}", self.name);
            }
        }
        self.fire_hook(
            HookPoint::RotatePost,
            *self.current_pid.lock().unwrap(),
            None,
        );
    }

    /// True only if `pid` is still a live member of the current job — i.e.
    /// it still refers to our managed child tree and not a process that
    /// reused the PID after the child exited. Every PID-based control is
    /// gated on this so a recycled PID can never be targeted.
    #[cfg(windows)]
    fn pid_in_job(&self, pid: u32) -> bool {
        self.job.as_ref().is_some_and(|job| job.contains(pid))
    }

    /// Suspend the supervised child process and every descendant we can see.
    /// Returns `true` only if the whole tree was suspended: a failed
    /// enumeration (descendants would escape) or any per-process failure
    /// makes this `false` so the runner does not report `PAUSED` for a
    /// partially-suspended tree. With no child running the pause is
    /// vacuously satisfied.
    #[cfg(windows)]
    fn suspend_tree(&self) -> bool {
        let Some(root) = *self.current_pid.lock().unwrap() else {
            return true;
        };
        match enumerate_descendants(root) {
            Ok(descendants) => {
                let mut all_ok = true;
                for p in descendants {
                    // Skip a PID that is no longer a member of our job: the
                    // process exited and Windows may have recycled the PID.
                    if !self.pid_in_job(p.pid) {
                        continue;
                    }
                    if let Err(e) = suspend_process(p.pid) {
                        eprintln!(
                            "[supervisor:{}] suspend pid={} ({}) failed: {e}",
                            self.name, p.pid, p.image_name
                        );
                        all_ok = false;
                    }
                }
                all_ok
            }
            Err(e) => {
                eprintln!(
                    "[supervisor:{}] enumerate for suspend failed: {e}",
                    self.name
                );
                // Fall back to suspending just the immediate child, but the
                // tree as a whole was not confirmed suspended.
                if self.pid_in_job(root) {
                    let _ = suspend_process(root);
                }
                false
            }
        }
    }

    /// Resume the process tree; mirrors [`Self::suspend_tree`]'s return
    /// contract.
    #[cfg(windows)]
    fn resume_tree(&self) -> bool {
        let Some(root) = *self.current_pid.lock().unwrap() else {
            return true;
        };
        match enumerate_descendants(root) {
            Ok(descendants) => {
                // Reverse order so deeper processes resume before their
                // parents — avoids races where a parent immediately
                // forks before children are running.
                let mut all_ok = true;
                for p in descendants.iter().rev() {
                    if !self.pid_in_job(p.pid) {
                        continue;
                    }
                    if let Err(e) = resume_process(p.pid) {
                        eprintln!(
                            "[supervisor:{}] resume pid={} ({}) failed: {e}",
                            self.name, p.pid, p.image_name
                        );
                        all_ok = false;
                    }
                }
                all_ok
            }
            Err(e) => {
                eprintln!(
                    "[supervisor:{}] enumerate for resume failed: {e}",
                    self.name
                );
                if self.pid_in_job(root) {
                    let _ = resume_process(root);
                }
                false
            }
        }
    }

    #[cfg(not(windows))]
    fn suspend_tree(&self) -> bool {
        true
    }
    #[cfg(not(windows))]
    fn resume_tree(&self) -> bool {
        true
    }

    /// Post WM_CLOSE to every top-level window owned by the child *and*
    /// its descendants. NSSM only walks the direct child's windows, but
    /// many modern apps (Electron, browsers, IDEs) host their main UI in
    /// a child renderer — covering descendants is the more user-visible
    /// behavior.
    #[cfg(windows)]
    fn post_wm_quit_to_tree(&self) {
        let Some(root) = *self.current_pid.lock().unwrap() else {
            return;
        };
        let pids: Vec<u32> = match enumerate_descendants(root) {
            Ok(list) => list.into_iter().map(|p| p.pid).collect(),
            Err(_) => vec![root],
        };
        for pid in pids {
            if !self.pid_in_job(pid) {
                continue;
            }
            if let Err(e) = post_wm_quit_to_process(pid) {
                eprintln!(
                    "[supervisor:{}] post_wm_quit pid={pid} failed: {e}",
                    self.name
                );
            }
        }
    }

    #[cfg(windows)]
    fn post_wm_close_to_tree(&self) {
        let Some(root) = *self.current_pid.lock().unwrap() else {
            return;
        };
        let mut total = 0usize;
        let pids: Vec<u32> = match enumerate_descendants(root) {
            Ok(list) => list.into_iter().map(|p| p.pid).collect(),
            Err(_) => vec![root],
        };
        for pid in pids {
            if !self.pid_in_job(pid) {
                continue;
            }
            match post_wm_close_to_process(pid) {
                Ok(n) => total += n,
                Err(e) => eprintln!(
                    "[supervisor:{}] post_wm_close pid={pid} failed: {e}",
                    self.name
                ),
            }
        }
        if total == 0 {
            // Console apps never have a window — skip the wait entirely
            // by setting an extremely short grace period. We can't really
            // know that here, so we just log it for debug visibility.
            eprintln!(
                "[supervisor:{}] WM_CLOSE step: no windows found for tree rooted at {root}",
                self.name
            );
        }
    }

    fn fire_hook(&self, point: HookPoint, child_pid: Option<u32>, exit_code: Option<i32>) {
        if let Some(hook) = find_hook(&self.config.hooks, point) {
            run_hook(
                &self.name,
                self.config.application.as_deref(),
                hook,
                child_pid,
                exit_code,
                None,
            );
        }
    }

    fn handle_power_event(&self, event_type: u32) {
        let point = if is_resume_event(event_type) {
            HookPoint::PowerResume
        } else {
            HookPoint::PowerChange
        };
        if let Some(hook) = find_hook(&self.config.hooks, point) {
            run_hook(
                &self.name,
                self.config.application.as_deref(),
                hook,
                *self.current_pid.lock().unwrap(),
                None,
                Some(event_type),
            );
        }
    }

    /// Record a child exit exactly once: stash the exit code, clear the
    /// current-child state (reaping the handle), and fire the `Exit/Post`
    /// hook. Used by both the spontaneous-exit path and controlled stop, so
    /// the hook runs no matter how the child ended.
    ///
    /// Also clears `pending_exit` so the stop-race short-circuit in
    /// [`Self::stop_child_gracefully`] cannot fire a second time for the
    /// same child generation (e.g. once via the racing Stop path and again
    /// via the normal `ChildExited` arm in the main loop).
    fn record_child_exit(&self, exit_code: i32) {
        *self.last_exit_code.lock().unwrap() = Some(exit_code);
        *self.pending_exit.lock().unwrap() = None;
        self.set_current(None);
        self.fire_hook(HookPoint::ExitPost, None, Some(exit_code));
    }

    /// Block forever draining the control channel until a Stop / Shutdown
    /// arrives. Used by the `ExitAction::Ignore` quiesce path: the child has
    /// exited and we've decided not to respawn it, but the service stays
    /// alive so SCM can still stop it cleanly. Rotate / Pause / Continue /
    /// Power are handled normally (the pause/continue ones report a vacuous
    /// success because there is no child tree to act on); a disconnected
    /// channel is treated like Stop so the supervisor cannot get stuck.
    fn wait_for_stop_quiesced(&self) -> Result<ExitReason, SupervisorError> {
        let writer = event_log::EventWriter::for_service(self.name.clone());
        loop {
            match self.rx.recv() {
                Ok(SupervisorMessage::Stop) => {
                    // No child to gracefully stop, but fire the pre-stop hook
                    // (mirrors the spawn-loop's Stop arm) and emit the
                    // stopped event so the dashboard sees a clean shutdown.
                    self.fire_hook(HookPoint::StopPre, None, None);
                    writer.stopped(servicemanager_core::events::StopReason::ScmStop);
                    return Ok(ExitReason::Stopped);
                }
                Ok(SupervisorMessage::Rotate) => self.rotate_sinks_now(),
                Ok(SupervisorMessage::Pause(ack)) => {
                    // No tree to suspend — `suspend_tree` already returns
                    // `true` when `current_pid` is `None`, so the runner
                    // sees the pause as vacuously satisfied.
                    let _ = ack.send(self.suspend_tree());
                }
                Ok(SupervisorMessage::Continue(ack)) => {
                    let _ = ack.send(self.resume_tree());
                }
                Ok(SupervisorMessage::PowerEvent(ev)) => self.handle_power_event(ev),
                // A stray ChildExited cannot reach here in practice (the exit
                // watcher fired before we entered quiesce, and no new child
                // was spawned), but if it did arrive late we just drop it.
                Ok(SupervisorMessage::ChildExited(_)) => {}
                // Sender side gone — treat as an implicit stop so the
                // runner's join returns instead of blocking forever.
                Err(_) => {
                    writer.stopped(servicemanager_core::events::StopReason::ScmStop);
                    return Ok(ExitReason::Stopped);
                }
            }
        }
    }

    fn sleep_or_stop(&self, delay: Duration) -> Result<bool, SupervisorError> {
        let deadline = Instant::now() + delay;
        loop {
            let remaining = match deadline.checked_duration_since(Instant::now()) {
                Some(r) => r,
                None => return Ok(true),
            };
            match self.rx.recv_timeout(remaining) {
                Err(RecvTimeoutError::Timeout) => return Ok(true),
                Ok(SupervisorMessage::Stop) => return Ok(false),
                Ok(SupervisorMessage::ChildExited(_)) => return Ok(true),
                Ok(SupervisorMessage::Rotate) => self.rotate_sinks_now(),
                Ok(SupervisorMessage::Pause(ack)) => {
                    let _ = ack.send(self.suspend_tree());
                }
                Ok(SupervisorMessage::Continue(ack)) => {
                    let _ = ack.send(self.resume_tree());
                }
                Ok(SupervisorMessage::PowerEvent(ev)) => self.handle_power_event(ev),
                Err(RecvTimeoutError::Disconnected) => return Ok(false),
            }
        }
    }

    /// True if we want the console step on stop. Currently always true unless
    /// the user explicitly skipped it via `AppStopMethodSkip`. Spawning with
    /// `CREATE_NEW_PROCESS_GROUP` keeps the event from leaking to siblings.
    fn console_step_enabled(&self) -> bool {
        let mask = self.config.shutdown.stop_method_skip.unwrap_or(0);
        mask & STOP_METHOD_SKIP_CONSOLE == 0
    }
}

fn open_log_file(
    stream: &IoStream,
    rotation: &LogRotationConfig,
) -> Result<Stdio, SupervisorError> {
    let path = Path::new(&stream.path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("[supervisor] cannot create log dir {parent:?}: {e}");
            }
        }
    }
    maybe_rotate(path, rotation);
    let file = match stream.copy_and_truncate {
        Some(true) => OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path),
        _ => OpenOptions::new().create(true).append(true).open(path),
    }
    .map_err(|e| SupervisorError::OpenLog(path.to_path_buf(), e))?;
    Ok(Stdio::from(file))
}

/// Open the configured stdin-redirection file for the child to *read*.
///
/// Unlike stdout/stderr logs this is an input, so it is opened read-only
/// and is never created, truncated, appended to, or rotated. A missing
/// stdin file is a hard error rather than something to create.
fn open_stdin_file(stream: &IoStream) -> Result<Stdio, SupervisorError> {
    let path = Path::new(&stream.path);
    let file = File::open(path).map_err(|e| SupervisorError::OpenStdin(path.to_path_buf(), e))?;
    Ok(Stdio::from(file))
}

/// Resolve a child's reported exit code, using `-1` when no code is
/// available (terminated by signal, or the `wait()` itself failed).
fn exit_code_of(result: &io::Result<std::process::ExitStatus>) -> i32 {
    match result {
        Ok(status) => status.code().unwrap_or(-1),
        Err(_) => -1,
    }
}

/// Parse a `NAME=VALUE` environment entry. Rejects a missing `=`, an empty
/// name, and embedded NULs (which cannot be represented in an environment
/// variable). The value may itself contain `=` — only the first splits.
fn parse_env_entry(entry: &str) -> Result<(&str, &str), SupervisorError> {
    let invalid =
        |msg: String| SupervisorError::Core(servicemanager_core::Error::InvalidConfig(msg));
    let (name, value) = entry
        .split_once('=')
        .ok_or_else(|| invalid(format!("environment entry '{entry}' must be NAME=VALUE")))?;
    if name.is_empty() {
        return Err(invalid(format!(
            "environment entry '{entry}' has an empty variable name"
        )));
    }
    if name.contains('\0') || value.contains('\0') {
        return Err(invalid(format!(
            "environment entry '{entry}' contains an embedded NUL"
        )));
    }
    Ok((name, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use servicemanager_core::HookConfig;

    fn isolate_program_data() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = crate::TEST_PROGRAM_DATA_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("NGSM_PROGRAM_DATA_DIR", dir.path());
        (guard, dir)
    }

    #[test]
    fn resume_events_are_classified() {
        // PBT_APMRESUMEAUTOMATIC = 18, PBT_APMRESUMESUSPEND = 7
        assert!(is_resume_event(18));
        assert!(is_resume_event(7));
        // PBT_APMSUSPEND (4) is a power *change*, not a resume.
        assert!(!is_resume_event(4));
    }

    #[test]
    fn find_hook_matches_event_action_case_insensitively() {
        let hooks = vec![
            HookConfig {
                event: "start".into(),
                action: "PRE".into(),
                command: "warmup".into(),
            },
            HookConfig {
                event: "Stop".into(),
                action: "Pre".into(),
                command: "drain".into(),
            },
        ];
        assert_eq!(
            find_hook(&hooks, HookPoint::StartPre).map(|h| h.command.as_str()),
            Some("warmup")
        );
        assert!(find_hook(&hooks, HookPoint::ExitPost).is_none());
    }

    #[test]
    fn rotated_name_keeps_stem_and_extension() {
        let rotated = rotation::build_rotated_name(Path::new("C:\\logs\\service.log"));
        let name = rotated.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("service."), "{name}");
        assert!(name.ends_with(".log"), "{name}");
    }

    #[test]
    fn env_entry_parsing() {
        assert_eq!(parse_env_entry("FOO=bar").unwrap(), ("FOO", "bar"));
        // The value may contain '=' — only the first one splits.
        assert_eq!(parse_env_entry("FOO=a=b").unwrap(), ("FOO", "a=b"));
        // An empty value is allowed.
        assert_eq!(parse_env_entry("EMPTY=").unwrap(), ("EMPTY", ""));
        // Missing '=', empty name, and embedded NULs are rejected.
        assert!(parse_env_entry("noequals").is_err());
        assert!(parse_env_entry("=value").is_err());
        assert!(parse_env_entry("BAD\0NAME=x").is_err());
    }

    #[test]
    fn pending_exit_starts_empty_and_is_take_consumable() {
        // The supervisor's stop/child-exit race fix relies on the
        // `pending_exit` slot being empty until the exit watcher populates
        // it, and being `take()`-consumable so the stop path can run
        // `record_child_exit` for it at most once. Pin both invariants so
        // a future refactor that switches storage strategy keeps the same
        // contract.
        let sup = Supervisor::new("Test", ManagedApplicationConfig::default());
        assert!(
            sup.pending_exit.lock().unwrap().is_none(),
            "pending_exit must start empty"
        );
        // Simulate the exit watcher storing a code.
        *sup.pending_exit.lock().unwrap() = Some(42);
        // The stop path uses `take()` to read-and-clear in one shot, so a
        // second concurrent stop cannot fire `record_child_exit` again for
        // the same exit.
        let taken = sup.pending_exit.lock().unwrap().take();
        assert_eq!(taken, Some(42));
        assert!(sup.pending_exit.lock().unwrap().is_none());
    }

    #[test]
    fn record_child_exit_clears_pending_exit_to_avoid_double_fire() {
        // The race fix has two paths that could record the exit: the racing
        // Stop path (which `take`s pending_exit) and the main loop's normal
        // ChildExited arm (which calls `record_child_exit` directly with
        // the exit code from the channel message). `record_child_exit`
        // therefore unconditionally clears pending_exit so the Stop path's
        // short-circuit cannot fire after a normal ChildExited has already
        // been handled.
        let sup = Supervisor::new("Test", ManagedApplicationConfig::default());
        *sup.pending_exit.lock().unwrap() = Some(7);
        sup.record_child_exit(7);
        assert!(
            sup.pending_exit.lock().unwrap().is_none(),
            "record_child_exit must clear pending_exit"
        );
        assert_eq!(*sup.last_exit_code.lock().unwrap(), Some(7));
    }

    #[test]
    fn ignore_quiesce_returns_stopped_when_stop_message_arrives() {
        let (_g, _dir) = isolate_program_data();
        // `ExitAction::Ignore` parks the supervisor in `wait_for_stop_quiesced`
        // instead of respawning the child. Pin the contract: the quiesce
        // loop must NOT exit on its own, and a Stop message must end it
        // cleanly with `ExitReason::Stopped` (so the runner reports a clean
        // service stop to SCM rather than treating Ignore as a failure).
        let sup = Supervisor::new("IgnoreQuiesce", ManagedApplicationConfig::default());
        let stop = sup.stop_signal();
        // Send Stop *before* entering the quiesce loop. Because Stop is in
        // the channel, the very first `recv()` returns it and we exit
        // immediately — no race, no hang risk in CI.
        stop.stop();
        let result = sup
            .wait_for_stop_quiesced()
            .expect("quiesce should not error");
        assert_eq!(result, ExitReason::Stopped);
    }

    #[test]
    fn ignore_quiesce_drains_non_terminal_signals_until_stop() {
        let (_g, _dir) = isolate_program_data();
        // Rotate must NOT terminate the quiesce loop — only Stop (or a
        // disconnected channel) does. Queue a Rotate, then a Stop on the
        // same thread (mpsc preserves single-thread FIFO order across
        // cloned senders), and assert the loop drains the Rotate and only
        // returns once Stop is processed.
        let sup = Supervisor::new("IgnoreDrain", ManagedApplicationConfig::default());
        let rotate = sup.rotate_signal();
        let stop = sup.stop_signal();

        rotate.rotate();
        stop.stop();
        let result = sup
            .wait_for_stop_quiesced()
            .expect("quiesce should not error");
        assert_eq!(result, ExitReason::Stopped);
    }

    #[test]
    fn ignore_quiesce_returns_stopped_when_channel_disconnects() {
        let (_g, _dir) = isolate_program_data();
        // A disconnected channel must be treated as an implicit Stop so the
        // runner's join can return. Drop the supervisor's external signal
        // handles before entering the quiesce loop — the internal `tx`
        // belongs to the Supervisor itself, so we have to consume it by
        // taking it out. Easiest equivalent: send Stop *after* dropping
        // every external sender; alternatively, drop the only remaining
        // external sender and rely on the internal one to keep the channel
        // alive. To exercise the disconnect path, we replace the receiver
        // with a fresh, sender-less one and rebuild a stand-in Supervisor.
        // Here we exercise the simpler invariant: with no senders left, the
        // quiesce loop must not block forever.
        let (tx, rx) = mpsc::channel::<SupervisorMessage>();
        drop(tx); // all senders gone
        let sup = Supervisor {
            name: "IgnoreDisconnect".into(),
            config: ManagedApplicationConfig::default(),
            rx,
            // The remaining fields are unused by the quiesce path, but must
            // be valid. Use a throwaway `tx` so the struct constructs; the
            // quiesce loop only reads `self.rx`.
            tx: mpsc::channel().0,
            current_child: Arc::new(Mutex::new(None)),
            current_pid: Arc::new(Mutex::new(None)),
            last_exit_code: Arc::new(Mutex::new(None)),
            pending_exit: Arc::new(Mutex::new(None)),
            sinks: Vec::new(),
            startup_tx: mpsc::channel().0,
            startup_rx: None,
            #[cfg(windows)]
            job: None,
        };
        let result = sup
            .wait_for_stop_quiesced()
            .expect("quiesce should not error");
        assert_eq!(result, ExitReason::Stopped);
    }

    // NOTE: A genuine end-to-end regression test for the stop/child-exit
    // race would need a test harness that lets us spawn a real child, then
    // interpose between "child has exited" and "supervisor processes
    // ChildExited" to inject a Stop. No such harness exists today (the
    // supervisor owns its channel privately, and there is no
    // dependency-injection seam on the child handle), and standing one up
    // is a non-trivial restructure. The unit tests above pin the shared-
    // state contract the fix relies on; a follow-up integration test
    // should be added once that harness lands.
}
