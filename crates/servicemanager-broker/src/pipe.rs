//! Named-pipe server.
//!
//! - The pipe name embeds a public, launcher-supplied CSPRNG nonce, so it is
//!   unpredictable to anyone the launcher did not hand the nonce to. A
//!   same-user process therefore cannot pre-create ("squat") the pipe to
//!   intercept the real client's connection. The name is never derived from
//!   the secret capability token, so the namespace leaks nothing about it.
//! - The pipe's DACL grants the broker identity (elevated Administrators)
//!   full client + instance-creation rights, and the unelevated owner SID
//!   only the read/write rights a *client* needs — never the
//!   `FILE_CREATE_PIPE_INSTANCE` bit.
//! - Authorization is the capability token delivered over stdin (an
//!   inherited handle, not visible in the command line); every request must
//!   carry it.
//! - Length-prefixed JSON framing (4-byte big-endian length, then body).
//! - A bounded number of pipe instances and worker threads, a per-connection
//!   idle/lifetime watchdog, and an idle process watchdog keep a misbehaving
//!   client from exhausting resources.

use std::io::{Read, Write};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use servicemanager_core::{Error, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    DuplicateHandle, GetLastError, LocalFree, DUPLICATE_SAME_ACCESS, ERROR_NOT_FOUND,
    ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, HANDLE, HLOCAL, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::System::IO::CancelIoEx;

use crate::handlers;
use crate::protocol::{pipe_name_for, token_matches, Request, Response};

const SDDL_REVISION_1: u32 = 1;
const IN_BUFFER: u32 = 64 * 1024;
const OUT_BUFFER: u32 = 64 * 1024;
/// Cap on simultaneously-served connections. Past this, new connections are
/// rejected immediately so a flood cannot exhaust threads/handles.
const MAX_CONCURRENT_CONNECTIONS: usize = 16;
const MAX_BUSY_CONNECTIONS: usize = 1;
/// Cap on the number of pipe instances the OS keeps for us. A finite value
/// (instead of `PIPE_UNLIMITED_INSTANCES`) bounds kernel pipe-buffer use.
/// Reserve a bounded busy-response slot and a listener beyond the normal
/// workers, so a non-reading rejected client cannot block the accept loop.
const MAX_PIPE_INSTANCES: u32 = (MAX_CONCURRENT_CONNECTIONS + MAX_BUSY_CONNECTIONS + 1) as u32;
/// A frame body larger than this is rejected outright. A frame is fully
/// read and JSON-parsed *before* its token is authenticated, so this is
/// deliberately modest — broker requests are small JSON objects, and a
/// generous-but-bounded cap limits the pre-auth work an unauthenticated
/// peer can force.
const MAX_FRAME_BYTES: usize = 256 * 1024;
#[derive(Clone, Copy)]
struct ConnectionLimits {
    io_timeout: Duration,
    lifetime: Duration,
    watchdog_tick: Duration,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            io_timeout: Duration::from_secs(30),
            lifetime: Duration::from_secs(600),
            watchdog_tick: Duration::from_secs(2),
        }
    }
}
/// Minimum capability-token length. The token is the broker's primary
/// authorization boundary — the pipe DACL admits *every* same-user process —
/// so it must carry real entropy (at least 128 bits). 32 characters covers a
/// hex-encoded 128-bit value with margin; anything shorter is refused.
const MIN_TOKEN_LEN: usize = 32;
/// Minimum number of *distinct* characters a token must contain. A genuine
/// CSPRNG token of the required length has many; this cheaply rejects
/// obviously non-random tokens (e.g. a repeated character) without pretending
/// to measure true entropy.
const MIN_TOKEN_DISTINCT: usize = 10;
/// Minimum length for the launcher-supplied public pipe nonce. It is not
/// secret, but it must be long enough that a same-user process cannot
/// feasibly guess the pipe name and squat it.
const MIN_PIPE_NONCE_LEN: usize = 16;

/// Shared server state passed to each connection worker.
struct ServerState {
    auth_token: String,
    activity: Activity,
    active_connections: Arc<AtomicUsize>,
    busy_connections: Arc<AtomicUsize>,
}

impl ServerState {
    fn new(auth_token: &str) -> Self {
        Self {
            auth_token: auth_token.to_string(),
            activity: Activity::new(Instant::now()),
            active_connections: Arc::new(AtomicUsize::new(0)),
            busy_connections: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct Activity {
    state: Mutex<ActivityState>,
}

struct ActivityState {
    last_activity: Instant,
    active_work: usize,
    authenticated_work: usize,
    draining: bool,
    shutdown_claimed: bool,
}

impl Activity {
    fn new(now: Instant) -> Self {
        Self {
            state: Mutex::new(ActivityState {
                last_activity: now,
                active_work: 0,
                authenticated_work: 0,
                draining: false,
                shutdown_claimed: false,
            }),
        }
    }

    fn admit(&self, authenticated: bool) -> Option<WorkGuard<'_>> {
        self.admit_at(authenticated, Instant::now())
    }

    fn admit_at(&self, authenticated: bool, now: Instant) -> Option<WorkGuard<'_>> {
        let mut state = lock_unpoisoned(&self.state);
        if state.draining || state.shutdown_claimed {
            return None;
        }
        state.active_work += 1;
        if authenticated {
            state.authenticated_work += 1;
            state.last_activity = now;
        }
        Some(WorkGuard {
            activity: self,
            authenticated,
        })
    }

    fn finish(&self, authenticated: bool, now: Instant) {
        let mut state = lock_unpoisoned(&self.state);
        if authenticated {
            state.last_activity = now;
            state.authenticated_work -= 1;
        }
        state.active_work -= 1;
    }

    fn claim_idle_shutdown(&self, now: Instant, timeout: Duration) -> bool {
        let mut state = lock_unpoisoned(&self.state);
        if state.shutdown_claimed || state.authenticated_work != 0 {
            return false;
        }
        if now.saturating_duration_since(state.last_activity) >= timeout {
            // Let already-started error responses drain, but do not allow
            // unauthenticated traffic to postpone shutdown indefinitely.
            state.draining = true;
        }
        if state.draining && state.active_work == 0 {
            state.shutdown_claimed = true;
            return true;
        }
        false
    }
}

struct WorkGuard<'a> {
    activity: &'a Activity,
    authenticated: bool,
}

impl Drop for WorkGuard<'_> {
    fn drop(&mut self) {
        self.activity.finish(self.authenticated, Instant::now());
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct ConnectionSlot(Arc<AtomicUsize>);

impl ConnectionSlot {
    fn reserve(counter: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < limit).then_some(count + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(counter)))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Run the broker server. Blocks until the idle-timeout watchdog terminates
/// the process. The caller must launch this process elevated and supply a
/// freshly-generated `auth_token` (the secret that authenticates every
/// request) and a `pipe_nonce` (a public CSPRNG value that names the pipe).
pub fn run_server(
    owner_sid: &str,
    pipe_nonce: &str,
    idle_timeout_secs: u64,
    auth_token: &str,
) -> Result<()> {
    // Refuse to run with a weak token — it is the authorization boundary.
    validate_auth_token(auth_token)?;
    // The nonce is interpolated into the pipe name; reject a weak or unsafe
    // one before it gets there.
    validate_pipe_nonce(pipe_nonce)?;
    // Reject a malformed SID before it reaches the pipe name or the SDDL.
    validate_owner_sid(owner_sid)?;

    // The pipe name is derived from the public nonce, never from the secret
    // token, so the named-pipe namespace exposes nothing about the token.
    let pipe_name = pipe_name_for(owner_sid, pipe_nonce);
    let sddl = build_sddl(owner_sid);

    let state = Arc::new(ServerState::new(auth_token));
    spawn_idle_watchdog(Arc::clone(&state), idle_timeout_secs)?;

    let mut first = true;
    loop {
        let handle = match create_pipe_instance(&pipe_name, &sddl, first) {
            Ok(h) => h,
            Err(e) if first => {
                // The first instance uses FILE_FLAG_FIRST_PIPE_INSTANCE; if
                // that fails the name may be squatted — refuse to start.
                return Err(e);
            }
            Err(e) => {
                // A later instance failed (e.g. a transient resource
                // shortage). Do not let that tear the broker down and drop
                // every connected client — back off briefly and retry.
                eprintln!("[broker] pipe instance create failed: {e} — retrying");
                thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        first = false;

        // ERROR_PIPE_CONNECTED means a client connected in the window between
        // CreateNamedPipe and ConnectNamedPipe — that is a *successful*
        // connection, not a fatal error.
        if let Err(e) = connect_pipe(&handle) {
            eprintln!("[broker] ConnectNamedPipe failed: {e}");
            continue;
        }

        let (busy, slot) =
            match ConnectionSlot::reserve(&state.active_connections, MAX_CONCURRENT_CONNECTIONS) {
                Some(slot) => (false, slot),
                None => {
                    match ConnectionSlot::reserve(&state.busy_connections, MAX_BUSY_CONNECTIONS) {
                        Some(slot) => (true, slot),
                        None => {
                            eprintln!("[broker] all worker and busy-response slots occupied");
                            disconnect_pipe(HANDLE(handle.as_raw_handle()));
                            continue;
                        }
                    }
                }
            };
        let worker_state = Arc::clone(&state);
        if let Err(e) = thread::Builder::new()
            .name("ngsm-broker-connection".into())
            .spawn(move || {
                let _slot = slot;
                if busy {
                    let limits = ConnectionLimits {
                        io_timeout: Duration::from_secs(2),
                        ..ConnectionLimits::default()
                    };
                    if let Err(e) = reject_busy(handle, &worker_state, limits) {
                        eprintln!("[broker] busy response failed: {e}");
                    }
                } else {
                    handle_connection(handle, &worker_state, ConnectionLimits::default());
                }
            })
        {
            eprintln!("[broker] could not start connection worker: {e}");
        }
    }
}

/// Reject a malformed `owner_sid` before it is interpolated into the pipe
/// name and the security descriptor. A string that `ConvertStringSidToSidW`
/// accepts is a well-formed SID (digits and hyphens only), which also rules
/// out SDDL-injection metacharacters.
fn validate_owner_sid(owner_sid: &str) -> Result<()> {
    let wide: Vec<u16> = owner_sid.encode_utf16().chain(std::iter::once(0)).collect();
    let mut psid = PSID::default();
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer that outlives the call;
    // `&mut psid` receives a `LocalAlloc`'d SID that we free immediately.
    unsafe {
        ConvertStringSidToSidW(PCWSTR::from_raw(wide.as_ptr()), &mut psid)
            .map_err(|e| Error::other(format!("invalid owner SID '{owner_sid}': {e}")))?;
        if !psid.is_invalid() {
            let _ = LocalFree(Some(HLOCAL(psid.0)));
        }
    }
    Ok(())
}

/// Reject a capability token too weak to be the broker's authorization
/// boundary. The broker does not generate the token (its launcher does), but
/// it refuses to run with one that is obviously not a high-entropy secret.
fn validate_auth_token(token: &str) -> Result<()> {
    let len = token.chars().count();
    if len < MIN_TOKEN_LEN {
        return Err(Error::other(format!(
            "broker capability token is too short ({len} chars) — at least \
             {MIN_TOKEN_LEN} characters of CSPRNG-generated entropy are required"
        )));
    }
    if token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::other(
            "broker capability token must not contain whitespace or control characters",
        ));
    }
    let distinct = token
        .chars()
        .collect::<std::collections::HashSet<_>>()
        .len();
    if distinct < MIN_TOKEN_DISTINCT {
        return Err(Error::other(format!(
            "broker capability token has only {distinct} distinct characters — \
             it does not look like a randomly-generated secret"
        )));
    }
    Ok(())
}

/// Reject a pipe nonce that is too short or contains characters unsafe to
/// interpolate into a pipe name. The nonce is public (not a secret), but it
/// must be unguessable and free of path separators / metacharacters.
fn validate_pipe_nonce(nonce: &str) -> Result<()> {
    let len = nonce.chars().count();
    if len < MIN_PIPE_NONCE_LEN {
        return Err(Error::other(format!(
            "broker pipe nonce is too short ({len} chars) — at least \
             {MIN_PIPE_NONCE_LEN} characters are required"
        )));
    }
    if !nonce
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::other(
            "broker pipe nonce must contain only ASCII letters, digits, '-' or '_'",
        ));
    }
    Ok(())
}

/// Connect a freshly-created pipe instance, tolerating the
/// `ERROR_PIPE_CONNECTED` race where a client beat us to it.
fn connect_pipe(handle: &OwnedHandle) -> Result<()> {
    // SAFETY: `handle` owns a live named-pipe instance; `ConnectNamedPipe`
    // with no overlapped structure blocks until a client connects.
    let result = unsafe { ConnectNamedPipe(HANDLE(handle.as_raw_handle()), None) };
    match result {
        Ok(()) => Ok(()),
        Err(e) if WIN32_ERROR::from_error(&e) == Some(ERROR_PIPE_CONNECTED) => Ok(()),
        Err(e) => Err(Error::other(format!("ConnectNamedPipe: {e}"))),
    }
}

fn reject_busy(pipe: OwnedHandle, state: &ServerState, limits: ConnectionLimits) -> Result<()> {
    let Some(_work) = state.activity.admit(false) else {
        disconnect_pipe(HANDLE(pipe.as_raw_handle()));
        return Ok(());
    };
    let mut connection = Connection::new(pipe, limits)?;
    connection
        .send(&Response::err(None, "broker is busy"), true)
        .map_err(|e| Error::other(format!("send busy response: {e}")))
}

trait AsRawHandlePtr {
    fn as_raw_handle(&self) -> *mut core::ffi::c_void;
}

impl AsRawHandlePtr for OwnedHandle {
    fn as_raw_handle(&self) -> *mut core::ffi::c_void {
        use std::os::windows::io::AsRawHandle;
        <Self as AsRawHandle>::as_raw_handle(self) as *mut _
    }
}

/// Duplicate a pipe handle so the watchdog owns its own kernel reference to
/// the pipe instance. Without this, the watchdog would only carry the raw
/// handle *value* — and Windows reuses handle values within a process, so if
/// the worker closed its `OwnedHandle` between the watchdog reading `done`
/// and issuing `CancelIoEx`/`DisconnectNamedPipe`, those calls would land on
/// an unrelated object that happened to inherit the recycled value.
///
/// With a duplicate, the watchdog's handle keeps the original pipe instance
/// alive and identifiable until its independently owned handle is dropped.
fn duplicate_pipe_handle(source: *mut core::ffi::c_void) -> Result<OwnedHandle> {
    let mut dup = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that is always
    // valid; `source` is a live pipe handle the worker currently owns;
    // `dup` is a stack slot that receives the duplicated handle.
    unsafe {
        let proc = GetCurrentProcess();
        DuplicateHandle(
            proc,
            HANDLE(source),
            proc,
            &mut dup,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
        .map_err(|e| Error::other(format!("DuplicateHandle: {e}")))?;
    }
    // SAFETY: DuplicateHandle returned a fresh handle owned by this call.
    Ok(unsafe { OwnedHandle::from_raw_handle(dup.0) })
}

struct IoWatch {
    started: Instant,
    state: Mutex<IoWatchState>,
    changed: Condvar,
}

struct IoWatchState {
    waiting_since: Option<Instant>,
    done: bool,
    timed_out: bool,
}

impl IoWatch {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            state: Mutex::new(IoWatchState {
                waiting_since: None,
                done: false,
                timed_out: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn begin_io(&self) -> std::io::Result<IoGuard<'_>> {
        let mut state = lock_unpoisoned(&self.state);
        if state.timed_out {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "broker connection I/O or lifetime limit exceeded",
            ));
        }
        state.waiting_since = Some(Instant::now());
        self.changed.notify_one();
        Ok(IoGuard(self))
    }
}

struct IoGuard<'a>(&'a IoWatch);

impl Drop for IoGuard<'_> {
    fn drop(&mut self) {
        lock_unpoisoned(&self.0.state).waiting_since = None;
        self.0.changed.notify_one();
    }
}

fn connection_watchdog(handle: OwnedHandle, watch: &IoWatch, limits: ConnectionLimits) {
    let mut state = lock_unpoisoned(&watch.state);
    loop {
        if state.done {
            return;
        }
        let now = Instant::now();
        let io_stalled = state
            .waiting_since
            .is_some_and(|since| now.duration_since(since) >= limits.io_timeout);
        if io_stalled || now.duration_since(watch.started) >= limits.lifetime {
            state.timed_out = true;
            drop(state);
            let handle = HANDLE(handle.as_raw_handle());
            // Both synchronous reads/writes and FlushFileBuffers are
            // cancellable on this pipe instance. Disconnect also closes the
            // race where the worker has not submitted its I/O yet.
            match unsafe { CancelIoEx(handle, None) } {
                Err(e) if WIN32_ERROR::from_error(&e) != Some(ERROR_NOT_FOUND) => {
                    eprintln!("[broker] cancelling timed-out pipe I/O failed: {e}");
                }
                _ => {}
            }
            disconnect_pipe(handle);
            return;
        }
        state = watch
            .changed
            .wait_timeout(state, limits.watchdog_tick)
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0;
    }
}

struct Connection {
    io: std::fs::File,
    watch: Arc<IoWatch>,
    watchdog: Option<thread::JoinHandle<()>>,
}

impl Connection {
    fn new(pipe: OwnedHandle, limits: ConnectionLimits) -> Result<Self> {
        let handle = duplicate_pipe_handle(pipe.as_raw_handle())?;
        let watch = Arc::new(IoWatch::new());
        let worker_watch = Arc::clone(&watch);
        let watchdog = thread::Builder::new()
            .name("ngsm-pipe-watchdog".into())
            .spawn(move || connection_watchdog(handle, &worker_watch, limits))
            .map_err(|e| Error::other(format!("start pipe watchdog: {e}")))?;
        Ok(Self {
            io: std::fs::File::from(pipe),
            watch,
            watchdog: Some(watchdog),
        })
    }

    fn read(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let _waiting = self.watch.begin_io()?;
        read_frame(&mut self.io)
    }

    fn send(&mut self, response: &Response, terminal: bool) -> std::io::Result<()> {
        let body = serde_json::to_vec(response).map_err(std::io::Error::other)?;
        let _waiting = self.watch.begin_io()?;
        write_frame(&mut self.io, &body)?;
        if terminal {
            // File::flush does not drain a Windows pipe. Keep the same I/O
            // watchdog armed across the write and this native peer-drain.
            unsafe { FlushFileBuffers(self.raw_handle()) }
                .map_err(|e| std::io::Error::other(format!("FlushFileBuffers: {e}")))?;
        }
        Ok(())
    }

    fn raw_handle(&self) -> HANDLE {
        use std::os::windows::io::AsRawHandle;
        HANDLE(self.io.as_raw_handle())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        lock_unpoisoned(&self.watch.state).done = true;
        self.watch.changed.notify_one();
        disconnect_pipe(self.raw_handle());
        if let Some(watchdog) = self.watchdog.take() {
            if watchdog.join().is_err() {
                eprintln!("[broker] pipe watchdog panicked");
            }
        }
    }
}

fn disconnect_pipe(handle: HANDLE) {
    // SAFETY: callers own the original or duplicated live pipe handle.
    match unsafe { DisconnectNamedPipe(handle) } {
        Err(e)
            if !matches!(
                WIN32_ERROR::from_error(&e),
                Some(ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA)
            ) =>
        {
            eprintln!("[broker] DisconnectNamedPipe failed: {e}");
        }
        _ => {}
    }
}

fn handle_connection(pipe: OwnedHandle, state: &ServerState, limits: ConnectionLimits) {
    let mut connection = match Connection::new(pipe, limits) {
        Ok(connection) => connection,
        Err(e) => {
            eprintln!("[broker] cannot serve connection: {e}");
            return;
        }
    };
    loop {
        match connection.read() {
            Ok(Some(buf)) => {
                let Some(prepared) = process_request(&buf, state) else {
                    break;
                };
                let terminal = matches!(prepared.outcome, FrameOutcome::Rejected);
                if let Err(e) = connection.send(&prepared.response, terminal) {
                    eprintln!("[broker] response write/drain failed: {e}");
                    break;
                }
                if terminal {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("[broker] dropping connection after frame error: {e}");
                break;
            }
        }
    }
}

/// Replace control characters with the replacement character, and cap the
/// length, so a user-controlled request field cannot forge extra audit log
/// lines, hide the real trail, or bloat the log — even before the request
/// is authenticated.
fn sanitize_log(s: &str) -> String {
    // Cap on a single audit field; bounds the log line a (possibly
    // unauthenticated) caller can produce.
    const MAX_FIELD: usize = 256;
    let mut out: String = s
        .chars()
        .take(MAX_FIELD)
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect();
    if s.chars().count() > MAX_FIELD {
        out.push('…');
    }
    out
}

/// Build a broker audit record as a single JSON object. JSON encoding quotes
/// and escapes every field, so a user-controlled `op`/`target`/`error` —
/// even one containing spaces, quotes, `=`, or a literal `result=ok` — is
/// fully contained and cannot forge extra `key=value` pairs or a second
/// record.
fn audit_line(op: &str, target: &str, result: &str, error: Option<&str>) -> String {
    let mut record = serde_json::json!({
        "op": op,
        "target": target,
        "result": result,
    });
    if let Some(e) = error {
        record["error"] = serde_json::Value::String(e.to_string());
    }
    record.to_string()
}

/// Whether a processed frame came from an authenticated client (the
/// connection may serve more) or must terminate the connection.
enum FrameOutcome {
    /// The request carried a valid capability token. Even if the dispatched
    /// operation itself failed, the client is legitimate and the connection
    /// stays open.
    Authenticated,
    /// A malformed frame or an invalid token — terminal. The single error
    /// response has been built; the caller sends it and closes the
    /// connection.
    Rejected,
}

struct PreparedResponse<'a> {
    response: Response,
    outcome: FrameOutcome,
    _work: WorkGuard<'a>,
}

/// Parse a request frame, enforce the capability token, dispatch it, and
/// emit an audit line with control characters in user-supplied fields
/// neutralized.
fn process_request<'a>(buf: &[u8], state: &'a ServerState) -> Option<PreparedResponse<'a>> {
    let req: Request = match serde_json::from_slice(buf) {
        Ok(req) => req,
        Err(e) => {
            return Some(PreparedResponse {
                response: Response::err(None, format!("invalid request: {e}")),
                outcome: FrameOutcome::Rejected,
                _work: state.activity.admit(false)?,
            })
        }
    };
    let id = req.id.clone();
    let op = sanitize_log(&req.op);
    let target = sanitize_log(req.args.get("name").and_then(|v| v.as_str()).unwrap_or("-"));

    if !token_matches(&state.auth_token, req.token.as_deref()) {
        let work = state.activity.admit(false)?;
        eprintln!(
            "[broker] AUDIT {}",
            audit_line(&op, &target, "rejected", Some("invalid capability token"))
        );
        // A small delay throttles brute-force attempts. The caller-supplied
        // `id` is deliberately *not* echoed back: an unauthenticated peer
        // must not get to choose response content.
        thread::sleep(Duration::from_millis(200));
        return Some(PreparedResponse {
            response: Response::err(None, "unauthorized: invalid capability token"),
            outcome: FrameOutcome::Rejected,
            _work: work,
        });
    }

    let work = state.activity.admit(true)?;
    let dispatched = handlers::dispatch(&req);

    let response = match dispatched {
        Ok(value) => {
            eprintln!("[broker] AUDIT {}", audit_line(&op, &target, "ok", None));
            Response::ok(id, value)
        }
        Err(msg) => {
            eprintln!(
                "[broker] AUDIT {}",
                audit_line(&op, &target, "error", Some(&sanitize_log(&msg)))
            );
            Response::err(id, msg)
        }
    };
    Some(PreparedResponse {
        response,
        outcome: FrameOutcome::Authenticated,
        _work: work,
    })
}

/// Build the SDDL granting the broker identity and the owner SID their
/// respective access.
///
/// - `BA` (the elevated broker — an admin, high-integrity process) gets
///   `0x12019F` (`FILE_GENERIC_READ | FILE_GENERIC_WRITE`), which on a named
///   pipe includes `FILE_CREATE_PIPE_INSTANCE` so it can create the server
///   instances.
/// - The unelevated owner SID gets `0x12019B` — the same client read/write
///   access *minus* `0x0004` `FILE_CREATE_PIPE_INSTANCE` — so a same-user
///   process can connect as a client but cannot stand up a rogue server
///   instance of the pipe to intercept connections.
///
/// Neither mask includes `WRITE_DAC`/`WRITE_OWNER`, and the leading `P`
/// protects the DACL from inherited ACEs.
fn build_sddl(owner_sid: &str) -> String {
    format!("D:P(A;;0x12019f;;;BA)(A;;0x12019b;;;{owner_sid})")
}

fn create_pipe_instance(pipe_name: &str, sddl: &str, first: bool) -> Result<OwnedHandle> {
    let wide_name: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide_sddl` is a NUL-terminated UTF-16 buffer that outlives the
    // call; `&mut sd` receives a locally-allocated security descriptor that
    // we free below once the kernel has copied it into the pipe object.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(wide_sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
        .map_err(|e| Error::other(format!("ConvertStringSecurityDescriptor: {e}")))?;
    }
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };

    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }

    // SAFETY: `wide_name` is NUL-terminated and outlives the call; `sa`
    // points at a valid SECURITY_ATTRIBUTES whose descriptor stays alive
    // until after this call returns.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR::from_raw(wide_name.as_ptr()),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            MAX_PIPE_INSTANCES,
            OUT_BUFFER,
            IN_BUFFER,
            0,
            Some(&mut sa as *const SECURITY_ATTRIBUTES),
        )
    };

    // The kernel keeps its own reference to the SD, so we free our copy
    // immediately. This avoids tying SD lifetime to the pipe handle.
    // SAFETY: `sd.0` was allocated by the conversion call above and is freed
    // exactly once here.
    unsafe {
        if !sd.0.is_null() {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
    }

    if handle.is_invalid() {
        // SAFETY: reading the thread's last-error code; always sound.
        let err = unsafe { GetLastError() };
        if first {
            // `FILE_FLAG_FIRST_PIPE_INSTANCE` fails the first create if the
            // name is already held. Treat that as a high-signal security
            // event: another process may be squatting the pipe, and starting
            // anyway could let clients connect to an impostor.
            return Err(Error::other(format!(
                "CreateNamedPipe({pipe_name}) failed (WIN32_ERROR {}) — the pipe name \
                 may already be held by another process; refusing to start",
                err.0
            )));
        }
        return Err(Error::other(format!(
            "CreateNamedPipe({pipe_name}) returned an invalid handle (WIN32_ERROR {})",
            err.0
        )));
    }
    // SAFETY: `handle` is a valid, non-invalid handle we now exclusively own.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle.0 as _) })
}

fn read_frame(io: &mut std::fs::File) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match io.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::UnexpectedEof
                || e.kind() == std::io::ErrorKind::BrokenPipe =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Ok(Some(Vec::new()));
    }
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame too large: {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len];
    io.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_frame(io: &mut std::fs::File, body: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response frame is too large",
        )
    })?;
    let len_buf = len.to_be_bytes();
    io.write_all(&len_buf)?;
    io.write_all(body)?;
    Ok(())
}

#[cfg(test)]
fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn exit_if_idle(activity: &Activity, now: Instant, timeout: Duration, exit: impl FnOnce()) -> bool {
    if activity.claim_idle_shutdown(now, timeout) {
        exit();
        true
    } else {
        false
    }
}

/// Admission and shutdown use the same state lock. Already-admitted work
/// retains its guard through response serialization, writing and draining.
fn spawn_idle_watchdog(state: Arc<ServerState>, idle_timeout_secs: u64) -> Result<()> {
    if idle_timeout_secs == 0 {
        return Ok(());
    }
    thread::Builder::new()
        .name("ngsm-broker-idle".into())
        .spawn(move || {
            let timeout = Duration::from_secs(idle_timeout_secs);
            loop {
                thread::sleep(Duration::from_secs(5));
                if exit_if_idle(&state.activity, Instant::now(), timeout, || {
                    std::process::exit(0)
                }) {
                    break;
                }
            }
        })
        .map(|_| ())
        .map_err(|e| Error::other(format!("start broker idle watchdog: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Barrier};
    use windows::Win32::System::Pipes::PeekNamedPipe;

    const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn test_limits() -> ConnectionLimits {
        ConnectionLimits {
            io_timeout: Duration::from_secs(2),
            lifetime: Duration::from_secs(5),
            watchdog_tick: Duration::from_millis(10),
        }
    }

    fn test_pipe_pair() -> (OwnedHandle, std::fs::File) {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let name = format!(
            "\\\\.\\pipe\\NGSM-broker-test-ops-{}-{}-{}",
            std::process::id(),
            now_epoch_ms(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: this test owns a unique pipe; the default DACL admits its
        // same-process client. No filesystem or service configuration is used.
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR::from_raw(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                OUT_BUFFER,
                IN_BUFFER,
                0,
                None,
            )
        };
        assert!(!handle.is_invalid(), "CreateNamedPipeW failed");
        let server = unsafe { OwnedHandle::from_raw_handle(handle.0) };
        let client = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name)
            .expect("open same-process named pipe client");
        connect_pipe(&server).unwrap();
        (server, client)
    }

    fn wait_for_buffered_response(client: &std::fs::File, expected_bytes: u32) {
        use std::os::windows::io::AsRawHandle;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut available = 0;
            unsafe {
                PeekNamedPipe(
                    HANDLE(client.as_raw_handle()),
                    None,
                    0,
                    None,
                    Some(&mut available),
                    None,
                )
            }
            .expect("server must not disconnect before buffered response is consumed");
            if available >= expected_bytes {
                return;
            }
            assert!(Instant::now() < deadline, "response never became available");
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn read_fragmented_response(client: &mut std::fs::File) -> serde_json::Value {
        let mut length = [0; 4];
        for byte in &mut length {
            client.read_exact(std::slice::from_mut(byte)).unwrap();
        }
        let mut body = vec![0; u32::from_be_bytes(length) as usize];
        for fragment in body.chunks_mut(3) {
            client.read_exact(fragment).unwrap();
            thread::sleep(Duration::from_millis(1));
        }
        serde_json::from_slice(&body).unwrap()
    }

    fn ping_frame(id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "op": "ping",
            "token": TEST_TOKEN,
        }))
        .unwrap()
    }

    #[test]
    fn admitted_requests_protect_dispatch_and_prepared_responses_from_idle_exit() {
        let state = ServerState::new(TEST_TOKEN);
        for op in ["ping", "unknown-op"] {
            let frame = serde_json::to_vec(&serde_json::json!({
                "op": op, "token": TEST_TOKEN
            }))
            .unwrap();
            let prepared = process_request(&frame, &state).unwrap();
            assert!(!exit_if_idle(
                &state.activity,
                Instant::now() + Duration::from_secs(100),
                Duration::from_secs(1),
                || panic!("admitted response is still active")
            ));
            drop(prepared);
            assert_eq!(lock_unpoisoned(&state.activity.state).active_work, 0);
            assert!(!state.activity.claim_idle_shutdown(
                Instant::now() + Duration::from_millis(100),
                Duration::from_secs(1)
            ));
        }
    }

    #[test]
    fn shutdown_claim_prevents_new_dispatch_even_before_terminal_action_runs() {
        let mut state = ServerState::new(TEST_TOKEN);
        state.activity = Activity::new(Instant::now() - Duration::from_secs(10));
        let entered = Barrier::new(2);
        let release = Barrier::new(2);
        thread::scope(|scope| {
            let watchdog = scope.spawn(|| {
                exit_if_idle(
                    &state.activity,
                    Instant::now(),
                    Duration::from_secs(1),
                    || {
                        entered.wait();
                        release.wait();
                    },
                )
            });
            entered.wait();
            assert!(process_request(&ping_frame("late"), &state).is_none());
            release.wait();
            assert!(watchdog.join().unwrap());
        });
    }

    #[test]
    fn admission_before_shutdown_and_completion_heartbeat_are_atomic() {
        for _ in 0..16 {
            let stale = Instant::now() - Duration::from_secs(10);
            let activity = Activity::new(stale);
            let work = activity.admit_at(true, stale).unwrap();
            assert!(!activity.claim_idle_shutdown(Instant::now(), Duration::from_secs(1)));

            let start = Barrier::new(3);
            thread::scope(|scope| {
                let state_lock = lock_unpoisoned(&activity.state);
                let completion = scope.spawn(|| {
                    start.wait();
                    drop(work);
                });
                let watchdog = scope.spawn(|| {
                    start.wait();
                    activity.claim_idle_shutdown(Instant::now(), Duration::from_secs(1))
                });
                start.wait();
                drop(state_lock);
                completion.join().unwrap();
                assert!(!watchdog.join().unwrap());
            });
            let state = lock_unpoisoned(&activity.state);
            assert_eq!(state.active_work, 0);
            assert_eq!(state.authenticated_work, 0);
            assert!(!state.shutdown_claimed);
        }
    }

    #[test]
    fn work_and_connection_slots_release_on_unwind() {
        let activity = Activity::new(Instant::now() - Duration::from_secs(10));
        let counter = Arc::new(AtomicUsize::new(0));
        let result = std::panic::catch_unwind(|| {
            let _work = activity.admit(true).unwrap();
            let _slot = ConnectionSlot::reserve(&counter, 1).unwrap();
            panic!("injected handler panic");
        });
        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert_eq!(lock_unpoisoned(&activity.state).active_work, 0);
        assert!(!activity.claim_idle_shutdown(Instant::now(), Duration::from_secs(1)));
    }

    #[test]
    fn idle_expiration_drains_existing_error_responses_but_rejects_new_work() {
        let now = Instant::now();
        let activity = Activity::new(now);
        let timeout = Duration::from_secs(1);
        assert!(!activity.claim_idle_shutdown(now + Duration::from_millis(999), timeout));
        let response = activity.admit(false).unwrap();
        assert!(!activity.claim_idle_shutdown(now + timeout, timeout));
        assert!(activity.admit(false).is_none());
        assert!(activity.admit(true).is_none());
        drop(response);
        let exits = AtomicUsize::new(0);
        assert!(exit_if_idle(&activity, now + timeout, timeout, || {
            exits.fetch_add(1, Ordering::Relaxed);
        }));
        assert!(!exit_if_idle(&activity, now + timeout, timeout, || {
            exits.fetch_add(1, Ordering::Relaxed);
        }));
        assert_eq!(exits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn busy_response_is_drained_before_disconnect_with_delayed_fragmented_reads() {
        let (server, mut client) = test_pipe_pair();
        let state = ServerState::new(TEST_TOKEN);
        let response = Response::err(None, "broker is busy");
        let expected_bytes = serde_json::to_vec(&response).unwrap().len() as u32 + 4;
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            done_tx
                .send(reject_busy(server, &state, test_limits()))
                .unwrap();
        });
        wait_for_buffered_response(&client, expected_bytes);
        assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
        thread::sleep(Duration::from_millis(25));
        let response = read_fragmented_response(&mut client);
        assert_eq!(response["status"], "error");
        assert_eq!(response["error"], "broker is busy");
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        drop(client);
        worker.join().unwrap();
    }

    #[test]
    fn malformed_and_unauthorized_responses_survive_terminal_disconnect() {
        for (frame, error) in [
            (b"not-json".to_vec(), "invalid request"),
            (
                br#"{"op":"ping","id":"untrusted","token":"wrong"}"#.to_vec(),
                "unauthorized",
            ),
        ] {
            let (server, mut client) = test_pipe_pair();
            let worker = thread::spawn(move || {
                handle_connection(server, &ServerState::new(TEST_TOKEN), test_limits());
            });
            write_frame(&mut client, &frame).unwrap();
            wait_for_buffered_response(&client, 4);
            thread::sleep(Duration::from_millis(25));
            let response = read_fragmented_response(&mut client);
            assert_eq!(response["status"], "error");
            assert!(response["id"].is_null());
            assert!(response["error"].as_str().unwrap().contains(error));
            drop(client);
            worker.join().unwrap();
        }
    }

    #[test]
    fn native_terminal_drain_is_cancelled_when_a_peer_never_reads() {
        let (server, client) = test_pipe_pair();
        let limits = ConnectionLimits {
            io_timeout: Duration::from_millis(80),
            ..test_limits()
        };
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            done_tx
                .send(reject_busy(server, &ServerState::new(TEST_TOKEN), limits))
                .unwrap();
        });
        let result = done_rx.recv_timeout(Duration::from_secs(2));
        // Closing the peer also releases a broken, uncancelled drain, so a
        // failed regression does not strand the test process or pipe handle.
        drop(client);
        worker.join().unwrap();
        let error = result
            .expect("watchdog must release a non-reading pipe within its deadline")
            .expect_err("a timed-out drain must not report success")
            .to_string();
        assert!(
            error.contains("FlushFileBuffers") || error.contains("limit exceeded"),
            "{error}"
        );
    }

    #[test]
    fn terminal_drain_holds_activity_until_delivery_or_cancellation() {
        let (server, mut client) = test_pipe_pair();
        let state = Arc::new(ServerState::new(TEST_TOKEN));
        lock_unpoisoned(&state.activity.state).last_activity =
            Instant::now() - Duration::from_secs(10);
        let worker_state = Arc::clone(&state);
        let limits = ConnectionLimits {
            io_timeout: Duration::from_millis(500),
            ..test_limits()
        };
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            handle_connection(server, &worker_state, limits);
            done_tx.send(()).unwrap();
        });
        write_frame(&mut client, b"invalid-json").unwrap();
        wait_for_buffered_response(&client, 4);
        assert!(!state
            .activity
            .claim_idle_shutdown(Instant::now(), Duration::from_secs(1)));
        assert!(process_request(&ping_frame("too-late"), &state).is_none());
        let completed = done_rx.recv_timeout(Duration::from_secs(2));
        drop(client);
        worker.join().unwrap();
        completed.expect("terminal response must time out without a reader");
        assert_eq!(lock_unpoisoned(&state.activity.state).active_work, 0);
        assert!(state
            .activity
            .claim_idle_shutdown(Instant::now(), Duration::from_secs(1)));
    }

    #[test]
    fn authenticated_connection_supports_multiple_frames_and_operation_errors() {
        let (server, mut client) = test_pipe_pair();
        let worker = thread::spawn(move || {
            handle_connection(server, &ServerState::new(TEST_TOKEN), test_limits());
        });
        for (id, op, status) in [
            ("1", "ping", "ok"),
            ("2", "unknown-op", "error"),
            ("3", "ping", "ok"),
        ] {
            let frame = serde_json::to_vec(&serde_json::json!({
                "id": id, "op": op, "token": TEST_TOKEN
            }))
            .unwrap();
            write_frame(&mut client, &frame).unwrap();
            let response: serde_json::Value =
                serde_json::from_slice(&read_frame(&mut client).unwrap().unwrap()).unwrap();
            assert_eq!(response["id"], id);
            assert_eq!(response["status"], status);
        }
        drop(client);
        worker.join().unwrap();
    }

    #[test]
    fn stalled_read_and_connection_lifetime_cancel_real_pipe_io() {
        for limits in [
            ConnectionLimits {
                io_timeout: Duration::from_millis(80),
                ..test_limits()
            },
            ConnectionLimits {
                lifetime: Duration::from_millis(80),
                ..test_limits()
            },
        ] {
            let (server, client) = test_pipe_pair();
            let (done_tx, done_rx) = mpsc::channel();
            let worker = thread::spawn(move || {
                let mut connection = Connection::new(server, limits).unwrap();
                let result = connection.read();
                assert!(connection.send(&Response::err(None, "late"), true).is_err());
                done_tx.send(result.is_err()).unwrap();
            });
            let result = done_rx.recv_timeout(Duration::from_secs(2));
            drop(client);
            worker.join().unwrap();
            assert!(result.expect("watchdog must cancel a blocked read"));
        }
    }

    #[test]
    fn normal_and_busy_connection_slots_are_bounded() {
        let normal = Arc::new(AtomicUsize::new(0));
        let busy = Arc::new(AtomicUsize::new(0));
        let workers: Vec<_> = (0..MAX_CONCURRENT_CONNECTIONS)
            .map(|_| ConnectionSlot::reserve(&normal, MAX_CONCURRENT_CONNECTIONS).unwrap())
            .collect();
        let busy_worker = ConnectionSlot::reserve(&busy, MAX_BUSY_CONNECTIONS).unwrap();
        assert!(ConnectionSlot::reserve(&normal, MAX_CONCURRENT_CONNECTIONS).is_none());
        assert!(ConnectionSlot::reserve(&busy, MAX_BUSY_CONNECTIONS).is_none());
        drop(workers);
        drop(busy_worker);
        assert_eq!(normal.load(Ordering::Relaxed), 0);
        assert_eq!(busy.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn audit_line_contains_forgery_attempts_safely() {
        // Fields laced with spaces, quotes, '=', and a literal `result=ok`.
        // The whole record stays valid JSON and every field is contained —
        // none of the injected text escapes into a forged key=value pair.
        let line = audit_line(
            "list result=ok x",
            "a\"b c=d",
            "rejected",
            Some("e=1 \"q\""),
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&line).expect("audit line must be valid JSON");
        assert_eq!(parsed["op"], "list result=ok x");
        assert_eq!(parsed["target"], "a\"b c=d");
        assert_eq!(parsed["result"], "rejected");
        assert_eq!(parsed["error"], "e=1 \"q\"");

        // No `error` field is emitted when none is supplied.
        let ok = audit_line("ping", "-", "ok", None);
        let parsed: serde_json::Value = serde_json::from_str(&ok).unwrap();
        assert!(parsed.get("error").is_none());
    }

    #[test]
    fn pipe_nonce_validation() {
        assert!(validate_pipe_nonce("abcdef0123456789").is_ok());
        assert!(validate_pipe_nonce("short").is_err());
        // Path separators / metacharacters are rejected.
        assert!(validate_pipe_nonce("bad\\nonce\\injection").is_err());
        assert!(validate_pipe_nonce("has space in it!").is_err());
    }

    /// Regression test for H-03: the watchdog must hold its *own* kernel
    /// handle to the pipe instance, not just a copy of the worker's raw
    /// handle value. Closing one handle must not invalidate the other,
    /// and the two raw values must be distinct (a duplicate gets a fresh
    /// handle-table slot, not the source's slot back).
    #[test]
    fn duplicate_pipe_handle_is_independent_of_source() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use windows::Win32::Security::SECURITY_ATTRIBUTES;

        // A unique pipe name so concurrent test runs do not collide.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nonce = now_epoch_ms()
            .wrapping_add(SEQ.fetch_add(1, Ordering::Relaxed))
            .wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let name = format!("\\\\.\\pipe\\NGSM-broker-test-h03-{nonce:x}");
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        // Create a pipe instance — no SDDL needed for a same-process test.
        // SAFETY: `wide` outlives the call; passing `None` for the security
        // attributes uses the default DACL, which is fine for a handle that
        // never leaves this process.
        let server = unsafe {
            CreateNamedPipeW(
                PCWSTR::from_raw(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                None::<*const SECURITY_ATTRIBUTES>,
            )
        };
        assert!(!server.is_invalid(), "CreateNamedPipeW failed");

        let dup = duplicate_pipe_handle(server.0).expect("duplicate succeeds");

        // The duplicated handle must occupy a *distinct* handle-table slot,
        // not the same value the source already owns. This is the core
        // property the H-03 fix relies on: each thread cancels/disconnects
        // through its own kernel reference, so neither can land on a
        // recycled-but-unrelated object after the other closes.
        assert_ne!(
            server.0 as usize,
            dup.as_raw_handle() as usize,
            "duplicate must have a distinct raw value from the source"
        );

        // SAFETY: the test exclusively owns the original raw handle.
        unsafe {
            windows::Win32::Foundation::CloseHandle(server).expect("close source");
        }
        let second_duplicate = duplicate_pipe_handle(dup.as_raw_handle())
            .expect("duplicate remains valid after source closed");
        drop(second_duplicate);
        drop(dup);
    }
}
