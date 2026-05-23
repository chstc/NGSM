//! Windows service runtime glue.
//!
//! [`run_service_dispatcher`] is intended to be called by `main` when the
//! process was launched by the SCM. It owns the C trampoline functions
//! required by `StartServiceCtrlDispatcherW` and exposes a safe
//! [`ServiceContext`] handle to the supplied service closure.

use std::ffi::c_void;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Mutex, OnceLock};

use servicemanager_core::{Error, Result};
use windows::core::{Error as WinError, PCWSTR, PWSTR};
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_PAUSE_CONTINUE, SERVICE_ACCEPT_POWEREVENT, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_CONTINUE_PENDING, SERVICE_CONTROL_CONTINUE,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_POWEREVENT,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_PAUSED, SERVICE_PAUSE_PENDING,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use crate::handles::{map_win_error, to_wide};

/// Accepts bitmask we advertise while the service is Running or Paused.
const ACCEPTS_WHEN_LIVE: u32 = SERVICE_ACCEPT_STOP
    | SERVICE_ACCEPT_SHUTDOWN
    | SERVICE_ACCEPT_PAUSE_CONTINUE
    | SERVICE_ACCEPT_POWEREVENT;

/// Controls dispatched by the SCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceControl {
    Stop,
    Shutdown,
    Pause,
    Continue,
    Interrogate,
    /// `SERVICE_CONTROL_POWEREVENT`. The payload is the `dwEventType`
    /// (`PBT_*`) indicating what kind of power transition happened.
    PowerEvent(u32),
    Other(u32),
}

impl ServiceControl {
    fn from_win32(code: u32, event_type: u32) -> Self {
        match code {
            SERVICE_CONTROL_STOP => ServiceControl::Stop,
            SERVICE_CONTROL_SHUTDOWN => ServiceControl::Shutdown,
            SERVICE_CONTROL_PAUSE => ServiceControl::Pause,
            SERVICE_CONTROL_CONTINUE => ServiceControl::Continue,
            SERVICE_CONTROL_INTERROGATE => ServiceControl::Interrogate,
            SERVICE_CONTROL_POWEREVENT => ServiceControl::PowerEvent(event_type),
            other => ServiceControl::Other(other),
        }
    }
}

/// User-facing trait that the service main loop implements.
pub trait ServiceLifecycle: Send + 'static {
    /// Called once on the dispatcher thread after the control handler has been
    /// registered. The implementor is expected to:
    ///
    /// - call [`ServiceContext::report_running`] when ready to accept controls,
    /// - block until a stop arrives via [`ServiceContext::controls`],
    /// - report `STOPPED` via [`ServiceContext::report_stopped`] before
    ///   returning.
    ///
    /// The dispatcher does *not* report `STOPPED` on the implementor's
    /// behalf — it has no exit code to report — so an implementation that
    /// returns without calling `report_stopped` leaves the SCM with stale
    /// state.
    fn run(self: Box<Self>, ctx: ServiceContext);
}

impl<F> ServiceLifecycle for F
where
    F: FnOnce(ServiceContext) + Send + 'static,
{
    fn run(self: Box<Self>, ctx: ServiceContext) {
        (*self)(ctx);
    }
}

/// Mutable state shared between the service main thread and the SCM control
/// handler. Allocated on the heap once per service and kept alive for the
/// rest of the process so the control handler can never dereference freed
/// memory.
struct ContextInner {
    status_handle: SERVICE_STATUS_HANDLE,
    name: String,
    controls_tx: SyncSender<ServiceControl>,
    checkpoint: Mutex<u32>,
}

// SAFETY: `SERVICE_STATUS_HANDLE` is an opaque SCM-managed token used only as
// an argument to `SetServiceStatus`; the SCM itself is thread-safe for that
// call. `Sender<ServiceControl>` is already `Send + Sync` and `Mutex<u32>`
// needs no special justification, so the entire `ContextInner` is sound to
// share across threads.
unsafe impl Send for ContextInner {}
// SAFETY: Same reasoning as Send above — all fields are independently
// thread-safe and no field is mutated without synchronisation.
unsafe impl Sync for ContextInner {}

/// Safe handle to the per-service status reporting + control-event stream.
pub struct ServiceContext {
    inner: &'static ContextInner,
    controls_rx: Receiver<ServiceControl>,
}

impl ServiceContext {
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn controls(&self) -> &Receiver<ServiceControl> {
        &self.controls_rx
    }

    pub fn report_start_pending(&self, wait_hint_ms: u32) -> Result<()> {
        let cp = self.bump_checkpoint();
        self.set_status(SERVICE_START_PENDING.0, 0, 0, cp, wait_hint_ms)
    }

    pub fn report_running(&self) -> Result<()> {
        self.reset_checkpoint();
        self.set_status(SERVICE_RUNNING.0, ACCEPTS_WHEN_LIVE, 0, 0, 0)
    }

    pub fn report_paused(&self) -> Result<()> {
        self.reset_checkpoint();
        self.set_status(SERVICE_PAUSED.0, ACCEPTS_WHEN_LIVE, 0, 0, 0)
    }

    /// Report `PAUSE_PENDING` while a pause is being carried out, advancing
    /// the checkpoint so SCM treats a slow (but progressing) pause as live
    /// rather than hung.
    pub fn report_pause_pending(&self, wait_hint_ms: u32) -> Result<()> {
        let cp = self.bump_checkpoint();
        self.set_status(SERVICE_PAUSE_PENDING.0, 0, 0, cp, wait_hint_ms)
    }

    /// Report `CONTINUE_PENDING` while a resume is being carried out.
    pub fn report_continue_pending(&self, wait_hint_ms: u32) -> Result<()> {
        let cp = self.bump_checkpoint();
        self.set_status(SERVICE_CONTINUE_PENDING.0, 0, 0, cp, wait_hint_ms)
    }

    pub fn report_stop_pending(&self, wait_hint_ms: u32) -> Result<()> {
        let cp = self.bump_checkpoint();
        self.set_status(SERVICE_STOP_PENDING.0, 0, 0, cp, wait_hint_ms)
    }

    pub fn report_stopped(&self, exit_code: u32) -> Result<()> {
        self.reset_checkpoint();
        self.set_status(SERVICE_STOPPED.0, 0, exit_code, 0, 0)
    }

    fn set_status(
        &self,
        state: u32,
        controls_accepted: u32,
        exit_code: u32,
        checkpoint: u32,
        wait_hint_ms: u32,
    ) -> Result<()> {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE(state),
            dwControlsAccepted: controls_accepted,
            dwWin32ExitCode: exit_code,
            dwCheckPoint: checkpoint,
            dwWaitHint: wait_hint_ms,
            ..Default::default()
        };
        // SAFETY: `status_handle` was obtained from `RegisterServiceCtrlHandlerExW`
        // and is valid for the process lifetime; `status` is a local struct on the
        // stack whose pointer is only used for the duration of this call.
        unsafe {
            SetServiceStatus(self.inner.status_handle, &status as *const SERVICE_STATUS)
                .map_err(|e: WinError| map_win_error("SetServiceStatus", e))
        }
    }

    fn bump_checkpoint(&self) -> u32 {
        let mut guard = self
            .inner
            .checkpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        *guard = guard.saturating_add(1);
        *guard
    }

    fn reset_checkpoint(&self) {
        *self
            .inner
            .checkpoint
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = 0;
    }
}

/// Storage for the service callback supplied by the caller. We need a static
/// because the C trampoline cannot capture state.
type LifecycleSlot = Mutex<Option<Box<dyn ServiceLifecycle>>>;
static LIFECYCLE: OnceLock<LifecycleSlot> = OnceLock::new();
static SERVICE_NAME: OnceLock<Mutex<Vec<u16>>> = OnceLock::new();
/// Pointer to the `'static` `ContextInner` allocated in the service main
/// thunk. Stored only to keep ownership rooted; the value is never freed.
static CONTEXT_PTR: OnceLock<usize> = OnceLock::new();

/// Run the SCM dispatcher for the named service. Blocks until the service
/// stops. Must be called once per process.
pub fn run_service_dispatcher<L: ServiceLifecycle>(service_name: &str, lifecycle: L) -> Result<()> {
    let slot = LIFECYCLE.get_or_init(|| Mutex::new(None));
    {
        let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_some() {
            return Err(Error::other(
                "run_service_dispatcher must only be called once per process",
            ));
        }
        *guard = Some(Box::new(lifecycle));
    }

    let mut name_wide = to_wide(service_name);
    SERVICE_NAME
        .set(Mutex::new(name_wide.clone()))
        .map_err(|_| Error::other("service name slot already initialized"))?;

    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR::from_raw(name_wide.as_mut_ptr()),
            lpServiceProc: Some(service_main_thunk),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR::null(),
            lpServiceProc: None,
        },
    ];

    // SAFETY: `table` is a valid null-terminated `SERVICE_TABLE_ENTRYW` array;
    // `name_wide` stays alive until this call returns (it is on the stack above
    // and we call `clone()` before any move). The SCM dispatcher owns the thread
    // until the service stops.
    unsafe {
        StartServiceCtrlDispatcherW(table.as_ptr())
            .map_err(|e| map_win_error("StartServiceCtrlDispatcher", e))?;
    }
    Ok(())
}

extern "system" fn service_main_thunk(_argc: u32, _argv: *mut PWSTR) {
    let lifecycle = match LIFECYCLE
        .get()
        .and_then(|slot| slot.lock().ok().and_then(|mut g| g.take()))
    {
        Some(l) => l,
        None => return,
    };

    let name_wide = match SERVICE_NAME.get() {
        Some(m) => m.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        None => return,
    };
    let name = String::from_utf16_lossy(strip_trailing_nul(&name_wide));

    // Capacity of 8 is generous for SCM controls (Stop/Pause/Continue are
    // rare and sent one at a time by the SCM). The bounded channel prevents
    // unbounded accumulation if the service loop stalls.
    let (tx, rx) = sync_channel(8);
    // Leak the inner state so the control handler can dereference it for the
    // remainder of the process lifetime. `Box::leak` returns a `&'static mut`,
    // which we downgrade to a shared `&'static` reference.
    let inner: &'static mut ContextInner = Box::leak(Box::new(ContextInner {
        status_handle: SERVICE_STATUS_HANDLE::default(),
        name,
        controls_tx: tx,
        checkpoint: Mutex::new(0),
    }));
    let inner_ptr = inner as *mut ContextInner;
    let _ = CONTEXT_PTR.set(inner_ptr as usize);

    // SAFETY: `name_wide` is a null-terminated wide string alive for this call;
    // `control_handler_thunk` has the correct `extern "system"` signature required
    // by the API; `inner_ptr` points to the `'static` Box-leaked ContextInner so
    // the pointer remains valid for the entire process lifetime.
    let status_handle = unsafe {
        match RegisterServiceCtrlHandlerExW(
            PCWSTR::from_raw(name_wide.as_ptr()),
            Some(control_handler_thunk),
            Some(inner_ptr as *const c_void),
        ) {
            Ok(h) => h,
            Err(_) => return,
        }
    };

    // Backfill the SCM-issued handle so future status reports go to SCM.
    inner.status_handle = status_handle;
    let inner: &'static ContextInner = inner;

    let ctx = ServiceContext {
        inner,
        controls_rx: rx,
    };

    let _ = ctx.report_start_pending(3000);
    lifecycle.run(ctx);
}

extern "system" fn control_handler_thunk(
    dwcontrol: u32,
    dwevttype: u32,
    _lpevtdata: *mut c_void,
    lpcontext: *mut c_void,
) -> u32 {
    let inner = lpcontext as *const ContextInner;
    if inner.is_null() {
        return 0;
    }
    // SAFETY: `lpcontext` was set to `inner_ptr` (a Box-leaked ContextInner) in
    // `service_main_thunk` and that pointer is valid for the process lifetime.
    // We checked above that it is non-null. No mutable alias exists: the only
    // mutation (status_handle backfill) completed before `lifecycle.run()`.
    let inner = unsafe { &*inner };
    let control = ServiceControl::from_win32(dwcontrol, dwevttype);
    match inner.controls_tx.try_send(control) {
        Ok(()) => {}
        Err(std::sync::mpsc::TrySendError::Full(c)) => {
            // The service loop has stalled with 8 pending controls — extremely
            // unlikely. Log and drop; the SCM callback cannot propagate errors.
            eprintln!("[runtime] dropped SCM control {:?} — channel full", c);
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
            eprintln!("[runtime] dropped SCM control — receiver gone");
        }
    }
    0
}

fn strip_trailing_nul(buf: &[u16]) -> &[u16] {
    match buf.iter().position(|&c| c == 0) {
        Some(end) => &buf[..end],
        None => buf,
    }
}
