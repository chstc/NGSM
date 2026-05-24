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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use servicemanager_core::{Error, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, LocalFree, DUPLICATE_SAME_ACCESS,
    ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
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
/// Cap on the number of pipe instances the OS keeps for us. A finite value
/// (instead of `PIPE_UNLIMITED_INSTANCES`) bounds kernel pipe-buffer use.
/// Deliberately one *more* than [`MAX_CONCURRENT_CONNECTIONS`]: with every
/// worker slot full the accept loop must still be able to create a fresh
/// listener instance so it can reach the busy-rejection path, rather than
/// failing the create and tearing the broker down.
const MAX_PIPE_INSTANCES: u32 = MAX_CONCURRENT_CONNECTIONS as u32 + 1;
/// A frame body larger than this is rejected outright. A frame is fully
/// read and JSON-parsed *before* its token is authenticated, so this is
/// deliberately modest — broker requests are small JSON objects, and a
/// generous-but-bounded cap limits the pre-auth work an unauthenticated
/// peer can force.
const MAX_FRAME_BYTES: usize = 256 * 1024;
/// How often the per-connection watchdog re-checks a connection.
const WATCHDOG_TICK: Duration = Duration::from_secs(2);
/// A connection that completes no frame within this window is treated as
/// stuck — this covers both an unauthenticated client that never sends a
/// request and an authenticated client that stalls partway through a frame.
const CONN_IDLE_LIMIT_MS: u64 = 30_000;
/// Hard cap on any single connection's total lifetime.
const CONN_MAX_LIFETIME_MS: u64 = 600_000;
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
    last_activity: AtomicU64,
    active_connections: AtomicUsize,
    /// Count of authenticated requests currently being dispatched. The idle
    /// watchdog must not exit the broker while this is non-zero.
    active_requests: AtomicUsize,
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

    let state = Arc::new(ServerState {
        auth_token: auth_token.to_string(),
        last_activity: AtomicU64::new(now_epoch_ms()),
        active_connections: AtomicUsize::new(0),
        active_requests: AtomicUsize::new(0),
    });
    spawn_idle_watchdog(Arc::clone(&state), idle_timeout_secs);

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

        if state.active_connections.load(Ordering::Relaxed) >= MAX_CONCURRENT_CONNECTIONS {
            eprintln!("[broker] connection limit reached — rejecting client");
            reject_busy(handle);
            continue;
        }

        state.active_connections.fetch_add(1, Ordering::Relaxed);
        let worker_state = Arc::clone(&state);
        thread::spawn(move || {
            handle_connection(handle, &worker_state);
            worker_state
                .active_connections
                .fetch_sub(1, Ordering::Relaxed);
        });
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
            let _ = LocalFree(HLOCAL(psid.0));
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

/// Send a single "server busy" frame and drop the connection.
fn reject_busy(pipe: OwnedHandle) {
    let raw = pipe.as_raw_handle();
    let mut io = std::fs::File::from(pipe);
    let body = serde_json::to_vec(&Response::err(None, "broker is busy")).unwrap_or_default();
    let _ = write_frame(&mut io, &body);
    // SAFETY: `raw` is the handle still backing `io`; disconnecting before
    // the `File` drop closes it is the documented teardown order.
    unsafe {
        let _ = DisconnectNamedPipe(HANDLE(raw));
    }
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
/// alive (and identifiable) for as long as the watchdog holds it, regardless
/// of when the worker drops its own. The watchdog must `CloseHandle` its
/// duplicate when it exits.
fn duplicate_pipe_handle(source: *mut core::ffi::c_void) -> Result<HANDLE> {
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
    Ok(dup)
}

/// Spawn the per-connection watchdog. It cancels the worker's pipe I/O once
/// the worker has been blocked in a single read or write for longer than
/// [`CONN_IDLE_LIMIT_MS`], or once the connection exceeds
/// [`CONN_MAX_LIFETIME_MS`]. `io_waiting_since` is the epoch-ms the current
/// read/write began, or `0` while a request handler is running — so a long
/// (but bounded) handler neither trips the idle timeout nor disarms the
/// watchdog. The watchdog keeps looping rather than exiting after one shot,
/// so coverage never lapses; `done` stops it when the connection tears down.
///
/// `watchdog_handle` is an *independent* duplicate of the pipe handle (see
/// [`duplicate_pipe_handle`]). The worker owns the original `OwnedHandle`;
/// the watchdog owns this duplicate. Both refer to the same kernel pipe
/// instance, but each thread closes its own handle on teardown — so there
/// is no race where one thread frees a handle value the other is about to
/// use. The watchdog closes its duplicate before returning.
fn spawn_connection_watchdog(
    watchdog_handle: HANDLE,
    done: Arc<AtomicBool>,
    io_waiting_since: Arc<AtomicU64>,
) {
    // `HANDLE` wraps `*mut c_void`, which is not `Send`; pass the handle
    // value as a `usize` and rebuild it inside the worker thread.
    let raw = watchdog_handle.0 as usize;
    let started = now_epoch_ms();
    thread::spawn(move || {
        // SAFETY: `raw` came from `DuplicateHandle` above and is owned by
        // this thread for the rest of its lifetime; no other thread closes
        // or otherwise invalidates it.
        let h = HANDLE(raw as *mut core::ffi::c_void);
        loop {
            thread::sleep(WATCHDOG_TICK);
            if done.load(Ordering::Relaxed) {
                break;
            }
            let now = now_epoch_ms();
            let waiting = io_waiting_since.load(Ordering::Relaxed);
            let io_stalled = waiting != 0 && now.saturating_sub(waiting) >= CONN_IDLE_LIMIT_MS;
            let lifetime_exceeded = now.saturating_sub(started) >= CONN_MAX_LIFETIME_MS;
            if io_stalled || lifetime_exceeded {
                // The watchdog's duplicate keeps the pipe instance alive
                // and unambiguously identifies it, even if the worker has
                // since closed its own handle. `CancelIoEx` cancels any
                // in-flight blocking read/write on the instance;
                // `DisconnectNamedPipe` is the forceful, reliable backstop
                // — it severs the connection so synchronous I/O on this
                // instance returns an error even if the cancel did not
                // interrupt the blocking call as expected.
                // SAFETY: `h` is our duplicate, still owned by this thread.
                unsafe {
                    let _ = CancelIoEx(h, None);
                    let _ = DisconnectNamedPipe(h);
                }
            }
        }
        // Release our duplicate. The original is owned by the worker.
        // SAFETY: `h` is the duplicated handle we have owned exclusively
        // for the lifetime of this thread; it has not been closed.
        unsafe {
            let _ = CloseHandle(h);
        }
    });
}

fn handle_connection(pipe: OwnedHandle, state: &ServerState) {
    let raw = pipe.as_raw_handle();
    // `done` disarms the watchdog once the connection ends, so it never
    // operates on a stale duplicate. `io_waiting_since` is the epoch-ms the
    // worker began its current pipe read/write, or 0 while a request handler
    // runs — the watchdog times out *I/O* stalls only, never (bounded)
    // handler execution.
    let done = Arc::new(AtomicBool::new(false));
    let io_waiting_since = Arc::new(AtomicU64::new(now_epoch_ms()));
    // Hand the watchdog its own kernel reference to the pipe so it cannot
    // wind up operating on a recycled handle value after the worker has
    // closed its `OwnedHandle`. If the duplication fails we drop the
    // connection rather than serve it without a watchdog.
    let watchdog_handle = match duplicate_pipe_handle(raw) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[broker] failed to duplicate pipe handle for watchdog: {e}");
            // SAFETY: `raw` still backs `pipe`, which we then drop to close.
            unsafe {
                let _ = DisconnectNamedPipe(HANDLE(raw));
            }
            return;
        }
    };
    spawn_connection_watchdog(
        watchdog_handle,
        Arc::clone(&done),
        Arc::clone(&io_waiting_since),
    );

    let mut io = std::fs::File::from(pipe);
    loop {
        io_waiting_since.store(now_epoch_ms(), Ordering::Relaxed);
        let frame = read_frame(&mut io);
        // A handler runs next (or the connection ends) — not I/O-bound.
        io_waiting_since.store(0, Ordering::Relaxed);
        match frame {
            Ok(Some(buf)) => {
                let (response, outcome) = process_request(&buf, state);
                let body = serde_json::to_vec(&response).unwrap_or_else(|e| {
                    let fallback = Response::err(None, format!("serialize: {e}"));
                    serde_json::to_vec(&fallback).unwrap_or_default()
                });
                io_waiting_since.store(now_epoch_ms(), Ordering::Relaxed);
                let written = write_frame(&mut io, &body);
                io_waiting_since.store(0, Ordering::Relaxed);
                if let Err(e) = written {
                    eprintln!("[broker] write failed, closing connection: {e}");
                    break;
                }
                // A malformed frame or an invalid token is a terminal
                // authentication failure: one error response is sent, then
                // the connection is dropped so a bad peer cannot keep a
                // worker slot occupied frame after frame.
                if matches!(outcome, FrameOutcome::Rejected) {
                    eprintln!("[broker] closing connection after a rejected frame");
                    break;
                }
            }
            Ok(None) => break, // client disconnected cleanly
            Err(e) => {
                eprintln!("[broker] dropping connection after frame error: {e}");
                break;
            }
        }
    }
    // Disarm the watchdog before the handle closes.
    done.store(true, Ordering::Relaxed);
    // SAFETY: `raw` is the handle still backing `io`; disconnecting before
    // the `File` drop closes it is the documented teardown order.
    unsafe {
        let _ = DisconnectNamedPipe(HANDLE(raw));
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

/// Parse a request frame, enforce the capability token, dispatch it, and
/// emit an audit line with control characters in user-supplied fields
/// neutralized.
fn process_request(buf: &[u8], state: &ServerState) -> (Response, FrameOutcome) {
    let req: Request = match serde_json::from_slice(buf) {
        Ok(req) => req,
        Err(e) => {
            return (
                Response::err(None, format!("invalid request: {e}")),
                FrameOutcome::Rejected,
            )
        }
    };
    let id = req.id.clone();
    let op = sanitize_log(&req.op);
    let target = sanitize_log(req.args.get("name").and_then(|v| v.as_str()).unwrap_or("-"));

    if !token_matches(&state.auth_token, req.token.as_deref()) {
        eprintln!(
            "[broker] AUDIT {}",
            audit_line(&op, &target, "rejected", Some("invalid capability token"))
        );
        // A small delay throttles brute-force attempts. The caller-supplied
        // `id` is deliberately *not* echoed back: an unauthenticated peer
        // must not get to choose response content.
        thread::sleep(Duration::from_millis(200));
        return (
            Response::err(None, "unauthorized: invalid capability token"),
            FrameOutcome::Rejected,
        );
    }

    // Authenticated. Mark activity *now* — before the handler runs — and
    // count the request as in-flight, so the idle watchdog cannot exit the
    // broker during a long privileged operation. The post-dispatch update is
    // a completion heartbeat.
    state.last_activity.store(now_epoch_ms(), Ordering::Relaxed);
    state.active_requests.fetch_add(1, Ordering::Relaxed);
    let dispatched = handlers::dispatch(&req);
    state.active_requests.fetch_sub(1, Ordering::Relaxed);
    state.last_activity.store(now_epoch_ms(), Ordering::Relaxed);

    match dispatched {
        Ok(value) => {
            eprintln!("[broker] AUDIT {}", audit_line(&op, &target, "ok", None));
            (Response::ok(id, value), FrameOutcome::Authenticated)
        }
        Err(msg) => {
            eprintln!(
                "[broker] AUDIT {}",
                audit_line(&op, &target, "error", Some(&sanitize_log(&msg)))
            );
            (Response::err(id, msg), FrameOutcome::Authenticated)
        }
    }
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
            let _ = LocalFree(HLOCAL(sd.0));
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
    let len_buf = (body.len() as u32).to_be_bytes();
    io.write_all(&len_buf)?;
    io.write_all(body)?;
    io.flush()?;
    Ok(())
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Process-level watchdog: exits the broker after `idle_timeout_secs` of no
/// authenticated request activity. It never exits while a request is still
/// being handled, so it cannot terminate the broker mid-operation.
fn spawn_idle_watchdog(state: Arc<ServerState>, idle_timeout_secs: u64) {
    if idle_timeout_secs == 0 {
        return;
    }
    thread::spawn(move || {
        // `saturating_mul` so a very large configured value cannot overflow
        // the conversion to milliseconds.
        let timeout_ms = idle_timeout_secs.saturating_mul(1000);
        loop {
            thread::sleep(Duration::from_secs(5));
            // Authenticated work is in flight — not idle, regardless of the
            // last-activity timestamp.
            if state.active_requests.load(Ordering::Relaxed) > 0 {
                continue;
            }
            let last = state.last_activity.load(Ordering::Relaxed);
            let elapsed = now_epoch_ms().saturating_sub(last);
            if elapsed >= timeout_ms {
                std::process::exit(0);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

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
            server.0 as usize, dup.0 as usize,
            "duplicate must have a distinct raw value from the source"
        );

        // Closing the source must not invalidate the duplicate. If
        // `CloseHandle(dup)` errors after the source close, the duplicate
        // never really held an independent reference.
        // SAFETY: both handles were created/duplicated above and are owned
        // exclusively by this test thread.
        unsafe {
            CloseHandle(server).expect("close source");
            CloseHandle(dup).expect("close duplicate after source was closed");
        }
    }
}
