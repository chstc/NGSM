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
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use servicemanager_core::{
    ExitAction, HookConfig, IoStream, LogRotationConfig, ManagedApplicationConfig,
};

#[cfg(windows)]
use servicemanager_win32::{
    enumerate_descendants, post_wm_close_to_process, post_wm_quit_to_process, resume_process,
    send_ctrl_break, suspend_process, terminate_process, JobObject,
};

pub mod event_log;

pub const DEFAULT_RESTART_DELAY_MS: u32 = 0;
pub const DEFAULT_THROTTLE_DELAY_MS: u32 = 1500;
pub const THROTTLE_THRESHOLD_MS: u128 = 1500;
/// Matches NSSM's default grace period for the console-event step.
pub const DEFAULT_CONSOLE_GRACE_MS: u32 = 1500;
/// Matches NSSM's default grace period for the WM_CLOSE step.
pub const DEFAULT_WINDOW_GRACE_MS: u32 = 1500;
/// Matches NSSM's default grace period for the WM_QUIT (thread-message) step.
pub const DEFAULT_THREADS_GRACE_MS: u32 = 1500;

/// Bits in `AppStopMethodSkip`. We currently implement the console + terminate
/// steps; window/thread message bits are recognized for compatibility but
/// have no effect because we never attempt those steps.
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
}

#[derive(Clone)]
pub struct StopSignal {
    tx: Sender<SupervisorMessage>,
}

impl StopSignal {
    pub fn stop(&self) {
        let _ = self.tx.send(SupervisorMessage::Stop);
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
        let _ = self.tx.send(SupervisorMessage::Rotate);
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
        let _ = self.tx.send(SupervisorMessage::PowerEvent(event_type));
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
                        ExitAction::Ignore | ExitAction::Restart => {
                            let delay = if lived.as_millis() < THROTTLE_THRESHOLD_MS {
                                throttle_delay
                            } else {
                                restart_delay
                            };
                            if delay.as_millis() > 0 && !self.sleep_or_stop(delay)? {
                                return Ok(ExitReason::Stopped);
                            }
                            continue;
                        }
                        ExitAction::Exit | ExitAction::Suicide => {
                            return Ok(ExitReason::ChildExited);
                        }
                    }
                }
                Err(_) => {
                    self.stop_child_gracefully();
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

        if let Some(stream) = &stdout_stream {
            if online {
                cmd.stdout(self.attach_pipe_sink("stdout", stream)?);
            } else {
                cmd.stdout(open_log_file(stream, &rotation)?);
            }
        }
        if let Some(stream) = &stderr_stream {
            if online {
                cmd.stderr(self.attach_pipe_sink("stderr", stream)?);
            } else {
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

    /// Build a write-end pipe handed to the child as its stdio, attach the
    /// matching read-end to a [`RotationSink`], and spawn a reader thread
    /// that funnels the child's output into the rotating log file.
    fn attach_pipe_sink(
        &mut self,
        label: &str,
        stream: &IoStream,
    ) -> Result<Stdio, SupervisorError> {
        let sink = Arc::new(RotationSink::open(stream, self.config.rotation.clone())?);
        let (reader, writer) = os_pipe::pipe().map_err(SupervisorError::Io)?;

        let sink_clone = Arc::clone(&sink);
        let name = self.name.clone();
        let label = label.to_string();
        thread::spawn(move || pipe_reader_loop(name, label, reader, sink_clone));

        self.sinks.push(sink);
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
    fn record_child_exit(&self, exit_code: i32) {
        *self.last_exit_code.lock().unwrap() = Some(exit_code);
        self.set_current(None);
        self.fire_hook(HookPoint::ExitPost, None, Some(exit_code));
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
            let _ = std::fs::create_dir_all(parent);
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

/// Offline rotation: if rotation is enabled and the existing log file is
/// over the configured size or older than the configured seconds, rename it
/// to `<stem>.<YYYYMMDD-HHMMSS>.<ext>`. Failures are logged but never
/// propagated — a missing rotation must not block service start.
fn maybe_rotate(path: &Path, rotation: &LogRotationConfig) {
    if rotation.enabled != Some(true) {
        return;
    }
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return, // file does not exist yet — nothing to rotate
    };
    let size = metadata.len();
    let age = metadata.modified().ok().and_then(|t| t.elapsed().ok());

    let mut should_rotate = false;
    if let Some(threshold) = rotation.bytes {
        if threshold > 0 && size >= threshold {
            should_rotate = true;
        }
    }
    if let (Some(secs), Some(age)) = (rotation.seconds, age) {
        if secs > 0 && age.as_secs() >= secs as u64 {
            should_rotate = true;
        }
    }
    if !should_rotate {
        return;
    }

    let rotated = build_rotated_name(path);
    if let Err(e) = std::fs::rename(path, &rotated) {
        eprintln!(
            "[supervisor] rotate {} -> {} failed: {e}",
            path.display(),
            rotated.display()
        );
    }
}

/// Pick a rotated log file name that does not already exist.
///
/// The base name is `<stem>.<YYYYMMDD-HHMMSS>[.<ext>]`. Because the stamp is
/// only second-resolution, two rotations within the same second would
/// otherwise collide and the second rename would silently clobber the first;
/// a `-<n>` counter is appended until a free name is found.
fn build_rotated_name(path: &Path) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // YYYYMMDD-HHMMSS in UTC for cross-locale stability.
    let (y, mo, d, h, mi, s) = epoch_seconds_to_utc(stamp);
    let stamp_str = format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}");

    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "log".to_string());
    let ext = path
        .extension()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    let make = |suffix: &str| -> PathBuf {
        let name = match (ext.is_empty(), suffix.is_empty()) {
            (true, true) => format!("{stem}.{stamp_str}"),
            (false, true) => format!("{stem}.{stamp_str}.{ext}"),
            (true, false) => format!("{stem}.{stamp_str}{suffix}"),
            (false, false) => format!("{stem}.{stamp_str}{suffix}.{ext}"),
        };
        path.with_file_name(name)
    };

    let first = make("");
    if !first.exists() {
        return first;
    }
    for n in 1..=9999 {
        let candidate = make(&format!("-{n}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    first
}

/// Convert a Unix epoch seconds value to broken-down UTC components.
/// Hand-rolled to keep the dependency surface small.
fn epoch_seconds_to_utc(mut secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let s = (secs % 60) as u32;
    secs /= 60;
    let mi = (secs % 60) as u32;
    secs /= 60;
    let h = (secs % 24) as u32;
    let mut days = secs / 24;

    let mut year = 1970u32;
    loop {
        let dy = if is_leap_year(year) { 366 } else { 365 };
        if days < dy as u64 {
            break;
        }
        days -= dy as u64;
        year += 1;
    }
    let days_in_month = [
        31u32,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u32;
    for &dm in &days_in_month {
        if (days as u32) < dm {
            break;
        }
        days -= dm as u64;
        month += 1;
    }
    let day = days as u32 + 1;
    (year, month, day, h, mi, s)
}

fn is_leap_year(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

/// Owns the destination log file when online rotation is enabled. Each
/// write goes through the mutex so the supervisor's `Rotate` thread can
/// safely swap the underlying file out without racing the reader.
pub struct RotationSink {
    state: Mutex<RotationState>,
}

struct RotationState {
    path: PathBuf,
    file: File,
    bytes_in_current: u64,
    opened_at: Instant,
    config: LogRotationConfig,
}

impl RotationSink {
    fn open(stream: &IoStream, config: LogRotationConfig) -> Result<Self, SupervisorError> {
        let path = PathBuf::from(&stream.path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| SupervisorError::OpenLog(path.clone(), e))?;
        let bytes_in_current = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            state: Mutex::new(RotationState {
                path,
                file,
                bytes_in_current,
                opened_at: Instant::now(),
                config,
            }),
        })
    }

    fn write(&self, buf: &[u8]) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.file.write_all(buf)?;
        state.bytes_in_current = state.bytes_in_current.saturating_add(buf.len() as u64);
        if state.should_rotate() {
            // A rotation failure is recoverable: `rotate()` always leaves the
            // real log reopened, so writes keep flowing. Log it but do not
            // propagate — propagating would break the pipe-reader loop and
            // permanently stop copying this stream.
            if let Err(e) = state.rotate() {
                eprintln!("[supervisor] online log rotation failed (continuing): {e}");
            }
        }
        Ok(())
    }

    fn force_rotate(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.rotate()
    }
}

impl RotationState {
    fn should_rotate(&self) -> bool {
        if let Some(threshold) = self.config.bytes {
            if threshold > 0 && self.bytes_in_current >= threshold {
                return true;
            }
        }
        if let Some(secs) = self.config.seconds {
            if secs > 0 && self.opened_at.elapsed().as_secs() >= secs as u64 {
                return true;
            }
        }
        false
    }

    fn rotate(&mut self) -> io::Result<()> {
        let rotated = build_rotated_name(&self.path);
        // Flush the current file before rename — required on Windows.
        self.file.sync_all().ok();
        let scratch = scratch_path(&self.path);
        // Point `self.file` at a scratch file so the OS releases the real log
        // handle, then rename the log aside.
        let rename_result = (|| -> io::Result<()> {
            let tmp = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&scratch)
                .or_else(|_| File::create(&scratch))?;
            let _ = std::mem::replace(&mut self.file, tmp);
            std::fs::rename(&self.path, &rotated)
        })();
        // Reopen the real log file regardless of whether the rename
        // succeeded, so the stream never gets stuck writing to the scratch
        // file. A failed rotation is thus recoverable — writes simply
        // continue to the (un-rotated) log.
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.bytes_in_current = self.file.metadata().map(|m| m.len()).unwrap_or(0);
        self.opened_at = Instant::now();
        let _ = std::fs::remove_file(&scratch);
        rename_result
    }
}

/// Scratch path used as a placeholder while the old log handle is released
/// for the rename. Kept in the log file's *own* directory so rotation does
/// not depend on the process temp directory being writable, on the same
/// volume, or sharing the log directory's ACLs.
fn scratch_path(log_path: &Path) -> PathBuf {
    let name = format!(".ngsm-rotate-scratch-{}.tmp", std::process::id());
    match log_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(name),
        None => PathBuf::from(name),
    }
}

/// Reader thread that streams a child's stdio into a [`RotationSink`].
/// Exits when the pipe reports EOF (i.e. the child closed its end).
fn pipe_reader_loop(
    service_name: String,
    label: String,
    mut reader: os_pipe::PipeReader,
    sink: Arc<RotationSink>,
) {
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = sink.write(&buf[..n]) {
                    eprintln!("[supervisor:{service_name}] sink-write {label} failed: {e}");
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// Hook lifecycle points (`<event>/<action>` in NSSM terms).
#[derive(Debug, Clone, Copy)]
enum HookPoint {
    StartPre,
    StartPost,
    StopPre,
    ExitPost,
    RotatePre,
    RotatePost,
    PowerChange,
    PowerResume,
}

impl HookPoint {
    fn event(&self) -> &'static str {
        match self {
            HookPoint::StartPre | HookPoint::StartPost => "Start",
            HookPoint::StopPre => "Stop",
            HookPoint::ExitPost => "Exit",
            HookPoint::RotatePre | HookPoint::RotatePost => "Rotate",
            HookPoint::PowerChange | HookPoint::PowerResume => "Power",
        }
    }
    fn action(&self) -> &'static str {
        match self {
            HookPoint::StartPre | HookPoint::RotatePre | HookPoint::StopPre => "Pre",
            HookPoint::StartPost | HookPoint::RotatePost | HookPoint::ExitPost => "Post",
            HookPoint::PowerChange => "Change",
            HookPoint::PowerResume => "Resume",
        }
    }
}

// Subset of `PBT_*` we care about classifying as "resume" events.
const PBT_APMRESUMEAUTOMATIC: u32 = 18;
const PBT_APMRESUMECRITICAL: u32 = 6;
const PBT_APMRESUMESTANDBY: u32 = 8;
const PBT_APMRESUMESUSPEND: u32 = 7;

fn is_resume_event(event_type: u32) -> bool {
    matches!(
        event_type,
        PBT_APMRESUMEAUTOMATIC
            | PBT_APMRESUMECRITICAL
            | PBT_APMRESUMESTANDBY
            | PBT_APMRESUMESUSPEND
    )
}

/// Maximum time a hook is allowed to run before we kill it. Matches NSSM's
/// historical 30-second default; later we can make this configurable.
const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

fn find_hook(hooks: &[HookConfig], point: HookPoint) -> Option<&HookConfig> {
    hooks.iter().find(|h| {
        h.event.eq_ignore_ascii_case(point.event()) && h.action.eq_ignore_ascii_case(point.action())
    })
}

/// Absolute path to the system `cmd.exe`, resolved from `%SystemRoot%`
/// rather than the ambient `PATH` / current-directory search.
fn system_cmd_exe() -> PathBuf {
    let root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("windir"))
        .unwrap_or_else(|| std::ffi::OsString::from("C:\\Windows"));
    Path::new(&root).join("System32").join("cmd.exe")
}

/// Place a freshly-spawned (suspended) hook process into a kill-on-close job
/// and resume it. Returns an error — leaving the hook *still suspended and
/// not running* — if either job creation or assignment fails, so an
/// uncontained privileged hook is never resumed.
#[cfg(windows)]
fn contain_hook(child: &Child) -> Result<JobObject, SupervisorError> {
    let job = JobObject::new_kill_on_close()?;
    job.assign_child(child)?;
    // The hook was created suspended; resume it only now that the job
    // contains it (and will therefore catch every process it spawns).
    resume_process(child.id())?;
    Ok(job)
}

fn run_hook(
    service_name: &str,
    application: Option<&str>,
    hook: &HookConfig,
    child_pid: Option<u32>,
    exit_code: Option<i32>,
    power_event_type: Option<u32>,
) {
    if hook.command.trim().is_empty() {
        return;
    }
    // Resolve `cmd.exe` from `%SystemRoot%` explicitly. A privileged service
    // process must not resolve the interpreter through the ambient `PATH` or
    // current-directory search, which an attacker could influence.
    let mut cmd = Command::new(system_cmd_exe());
    cmd.arg("/c");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.raw_arg(&hook.command);
        // Create the hook suspended so it can be placed in a job object
        // before it executes — so every process the hook spawns is captured
        // by the job and cannot escape the hook timeout.
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        cmd.creation_flags(CREATE_SUSPENDED);
    }
    #[cfg(not(windows))]
    {
        cmd.arg(&hook.command);
    }
    cmd.env("NGSM_SERVICE_NAME", service_name);
    cmd.env("NGSM_EVENT", format!("{}/{}", hook.event, hook.action));
    if let Some(app) = application {
        cmd.env("NGSM_APPLICATION", app);
    }
    if let Some(pid) = child_pid {
        cmd.env("NGSM_APPLICATION_PID", pid.to_string());
    }
    if let Some(code) = exit_code {
        cmd.env("NGSM_EXIT_CODE", code.to_string());
    }
    if let Some(ev) = power_event_type {
        cmd.env("NGSM_POWER_EVENT_TYPE", ev.to_string());
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[supervisor:{service_name}] hook {}/{} spawn failed: {e}",
                hook.event, hook.action
            );
            return;
        }
    };

    // Contain the hook's whole process tree in a kill-on-close job, so a
    // timed-out (or misbehaving) hook cannot leave privileged descendants
    // running after we report it killed. If containment cannot be
    // established, kill the still-suspended hook *without running it* —
    // resuming an uncontained privileged hook is not acceptable.
    #[cfg(windows)]
    let hook_job: JobObject = match contain_hook(&child) {
        Ok(job) => job,
        Err(e) => {
            eprintln!(
                "[supervisor:{service_name}] hook {}/{} containment failed: {e} — \
                 killing the suspended hook without running it",
                hook.event, hook.action
            );
            let _ = child.kill();
            let _ = child.wait();
            return;
        }
    };

    let deadline = Instant::now() + HOOK_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return,
            Ok(None) => {
                if Instant::now() >= deadline {
                    eprintln!(
                        "[supervisor:{service_name}] hook {}/{} timed out — killing",
                        hook.event, hook.action
                    );
                    // Terminate the hook's entire process tree, not just the
                    // immediate cmd.exe child, so no descendant survives.
                    #[cfg(windows)]
                    if let Err(e) = hook_job.terminate(1) {
                        eprintln!(
                            "[supervisor:{service_name}] hook {}/{} job terminate failed: {e}",
                            hook.event, hook.action
                        );
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!(
                    "[supervisor:{service_name}] hook {}/{} wait failed: {e}",
                    hook.event, hook.action
                );
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leap_years_are_recognized() {
        assert!(is_leap_year(2000));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2023));
    }

    #[test]
    fn epoch_zero_is_unix_origin() {
        assert_eq!(epoch_seconds_to_utc(0), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn epoch_known_timestamp_round_trips() {
        // 1_700_000_000 == 2023-11-14 22:13:20 UTC.
        assert_eq!(
            epoch_seconds_to_utc(1_700_000_000),
            (2023, 11, 14, 22, 13, 20)
        );
    }

    #[test]
    fn resume_events_are_classified() {
        assert!(is_resume_event(PBT_APMRESUMEAUTOMATIC));
        assert!(is_resume_event(PBT_APMRESUMESUSPEND));
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
        let rotated = build_rotated_name(Path::new("C:\\logs\\service.log"));
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
}
