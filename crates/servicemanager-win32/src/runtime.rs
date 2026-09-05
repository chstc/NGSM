//! Windows service runtime glue.
//!
//! [`run_service_dispatcher`] is intended to be called by `main` when the
//! process was launched by the SCM. It owns the C trampoline functions
//! required by `StartServiceCtrlDispatcherW` and exposes a safe
//! [`ServiceContext`] handle to the supplied service closure.

use std::cell::RefCell;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use servicemanager_core::{validate_service_name, Error, Result};
use windows::core::{Error as WinError, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_RETRY, ERROR_SERVICE_NOT_ACTIVE};
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
    status_handle: OnceLock<SERVICE_STATUS_HANDLE>,
    name: String,
    controls_tx: ControlSender,
    checkpoint: Mutex<u32>,
}

// SAFETY: `SERVICE_STATUS_HANDLE` is an opaque SCM-managed token used only as
// an argument to `SetServiceStatus`; the SCM itself is thread-safe for that
// call. OnceLock publishes that handle, ControlSender holds a synchronized
// channel/atomic state, and checkpoint updates are protected by Mutex.
unsafe impl Send for ContextInner {}
// SAFETY: Same reasoning as Send above — all fields are independently
// thread-safe and no field is mutated without synchronisation.
unsafe impl Sync for ContextInner {}

/// Safe handle to the per-service status reporting + control-event stream.
pub struct ServiceContext {
    inner: &'static ContextInner,
    controls_rx: ServiceControlReceiver,
}

enum ControlMessage {
    Ordinary(ServiceControl),
    Wake,
}

const STOP_REQUESTED: u8 = 1;
const TERMINAL_COMMITTED: u8 = 2;

struct ControlPending {
    terminal: AtomicU8,
    decision: AtomicU8,
    alive: AtomicBool,
}

struct ControlSender {
    tx: SyncSender<ControlMessage>,
    pending: Arc<ControlPending>,
}

/// Bounded ordinary controls plus a coalesced, higher-priority Stop/Shutdown.
/// The receive methods retain the std::mpsc receiver's signatures.
pub struct ServiceControlReceiver {
    rx: Receiver<ControlMessage>,
    pending: Arc<ControlPending>,
    deferred: RefCell<Option<ServiceControl>>,
}

fn control_channel() -> (ControlSender, ServiceControlReceiver) {
    let (tx, rx) = sync_channel(8);
    let pending = Arc::new(ControlPending {
        terminal: AtomicU8::new(0),
        decision: AtomicU8::new(0),
        alive: AtomicBool::new(true),
    });
    (
        ControlSender {
            tx,
            pending: pending.clone(),
        },
        ServiceControlReceiver {
            rx,
            pending,
            deferred: RefCell::new(None),
        },
    )
}

impl Drop for ServiceControlReceiver {
    fn drop(&mut self) {
        self.pending.alive.store(false, Ordering::Release);
    }
}

impl ServiceControlReceiver {
    fn stop_requested(&self) -> bool {
        self.pending.decision.load(Ordering::Acquire) & STOP_REQUESTED != 0
    }

    fn claim_terminal(&self) -> bool {
        self.pending
            .decision
            .fetch_or(TERMINAL_COMMITTED, Ordering::AcqRel)
            & STOP_REQUESTED
            != 0
    }

    fn terminal(&self) -> Option<ServiceControl> {
        match self.pending.terminal.swap(0, Ordering::AcqRel) {
            0 => None,
            bits if bits & 2 != 0 => Some(ServiceControl::Shutdown),
            _ => Some(ServiceControl::Stop),
        }
    }

    fn ready(&self) -> Option<ServiceControl> {
        self.terminal()
            .or_else(|| self.deferred.borrow_mut().take())
    }

    fn deliver(&self, control: ServiceControl) -> ServiceControl {
        if let Some(terminal) = self.terminal() {
            *self.deferred.borrow_mut() = Some(control);
            terminal
        } else {
            control
        }
    }

    pub fn recv(&self) -> std::result::Result<ServiceControl, std::sync::mpsc::RecvError> {
        loop {
            if let Some(control) = self.ready() {
                return Ok(control);
            }
            match self.rx.recv() {
                Ok(ControlMessage::Ordinary(control)) => return Ok(self.deliver(control)),
                Ok(ControlMessage::Wake) => {}
                Err(error) => return self.terminal().ok_or(error),
            }
        }
    }

    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> std::result::Result<ServiceControl, std::sync::mpsc::RecvTimeoutError> {
        let started = Instant::now();
        loop {
            if let Some(control) = self.ready() {
                return Ok(control);
            }
            match self
                .rx
                .recv_timeout(timeout.saturating_sub(started.elapsed()))
            {
                Ok(ControlMessage::Ordinary(control)) => return Ok(self.deliver(control)),
                Ok(ControlMessage::Wake) => {}
                Err(error) => return self.terminal().ok_or(error),
            }
        }
    }

    pub fn try_recv(&self) -> std::result::Result<ServiceControl, std::sync::mpsc::TryRecvError> {
        loop {
            if let Some(control) = self.ready() {
                return Ok(control);
            }
            match self.rx.try_recv() {
                Ok(ControlMessage::Ordinary(control)) => return Ok(self.deliver(control)),
                Ok(ControlMessage::Wake) => {}
                Err(error) => return self.terminal().ok_or(error),
            }
        }
    }
}

fn dispatch_control(sender: &ControlSender, control: ServiceControl) -> u32 {
    use std::sync::mpsc::TrySendError;
    if control == ServiceControl::Interrogate {
        return 0;
    }
    if !sender.pending.alive.load(Ordering::Acquire)
        || sender.pending.decision.load(Ordering::Acquire) & TERMINAL_COMMITTED != 0
    {
        return ERROR_SERVICE_NOT_ACTIVE.0;
    }
    let message = match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // This CAS and claim_terminal share one linearization point: a
            // successful terminal claim must never be followed by an accepted
            // Stop, while a Stop that wins forces a clean terminal outcome.
            if sender
                .pending
                .decision
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| {
                    (state & TERMINAL_COMMITTED == 0).then_some(state | STOP_REQUESTED)
                })
                .is_err()
            {
                return ERROR_SERVICE_NOT_ACTIVE.0;
            }
            sender.pending.terminal.fetch_or(
                if control == ServiceControl::Shutdown {
                    2
                } else {
                    1
                },
                Ordering::Release,
            );
            ControlMessage::Wake
        }
        other => ControlMessage::Ordinary(other),
    };
    match sender.tx.try_send(message) {
        Ok(()) | Err(TrySendError::Full(ControlMessage::Wake)) => 0,
        Err(TrySendError::Full(_)) => ERROR_RETRY.0,
        Err(TrySendError::Disconnected(_)) => ERROR_SERVICE_NOT_ACTIVE.0,
    }
}

impl ServiceContext {
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn controls(&self) -> &ServiceControlReceiver {
        &self.controls_rx
    }

    /// Whether Stop/Shutdown has won acceptance for this lifecycle.
    /// Published before control delivery and success acknowledgement, and
    /// never cleared by receiving/coalescing controls. Use at terminal policy
    /// decisions instead of inferring stop intent from an emptied queue.
    pub fn stop_requested(&self) -> bool {
        self.controls_rx.stop_requested()
    }

    /// Atomically commit to completing this lifecycle. Returns true if an
    /// accepted Stop/Shutdown won the race, requiring a clean stop rather than
    /// crash-style recovery. Otherwise commits completion before any later
    /// Stop/Shutdown can be accepted; HandlerEx rejects those requests.
    ///
    /// Call only at the irreversible terminal-policy boundary, not to poll.
    /// Repeated calls return the same result. Interrogate remains a no-op.
    pub fn claim_terminal(&self) -> bool {
        self.controls_rx.claim_terminal()
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
            let handle = self
                .inner
                .status_handle
                .get()
                .ok_or_else(|| Error::Scm("service status handle is not initialized".into()))?;
            SetServiceStatus(*handle, &status as *const SERVICE_STATUS)
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
    validate_service_name(service_name)?;
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
    let (tx, rx) = control_channel();
    // Leak the inner state so the control handler can dereference it for the
    // remainder of the process lifetime. `Box::leak` returns a `&'static mut`,
    // which we downgrade to a shared `&'static` reference.
    let inner: &'static ContextInner = Box::leak(Box::new(ContextInner {
        status_handle: OnceLock::new(),
        name,
        controls_tx: tx,
        checkpoint: Mutex::new(0),
    }));
    let inner_ptr = inner as *const ContextInner;
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
            Err(e) => {
                eprintln!(
                    "[runtime] RegisterServiceCtrlHandlerExW failed: {}",
                    std::io::Error::from_raw_os_error(e.code().0)
                );
                return;
            }
        }
    };

    // Backfill the SCM-issued handle so future status reports go to SCM.
    let _ = inner.status_handle.set(status_handle);

    let ctx = ServiceContext {
        inner,
        controls_rx: rx,
    };

    // Report START_PENDING so SCM knows we are initialising. A failure here
    // is non-fatal: the wait hint is advisory and startup may still succeed;
    // log it for post-mortem diagnostics and continue.
    if let Err(e) = ctx.report_start_pending(3000) {
        eprintln!("[runtime] could not report START_PENDING to SCM: {e}");
    }
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
        return ERROR_SERVICE_NOT_ACTIVE.0;
    }
    // SAFETY: `lpcontext` was set to `inner_ptr` (a Box-leaked ContextInner) in
    // `service_main_thunk` and that pointer is valid for the process lifetime.
    // We checked above that it is non-null. Initialization and pending controls
    // use synchronized state; registration never exposes a mutable alias.
    let inner = unsafe { &*inner };
    let control = ServiceControl::from_win32(dwcontrol, dwevttype);
    dispatch_control(&inner.controls_tx, control)
}

fn strip_trailing_nul(buf: &[u16]) -> &[u16] {
    match buf.iter().position(|&c| c == 0) {
        Some(end) => &buf[..end],
        None => buf,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_claim_rejects_later_stop_and_shutdown() {
        let (tx, rx) = control_channel();
        assert!(!rx.claim_terminal());
        for control in [
            ServiceControl::Stop,
            ServiceControl::Shutdown,
            ServiceControl::Pause,
        ] {
            assert_eq!(dispatch_control(&tx, control), ERROR_SERVICE_NOT_ACTIVE.0);
        }
        assert_eq!(dispatch_control(&tx, ServiceControl::Interrogate), 0);
        assert!(!rx.stop_requested());
        assert!(!rx.claim_terminal());
        assert!(matches!(
            rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn accepted_stop_wins_terminal_claim_even_after_delivery() {
        for control in [ServiceControl::Stop, ServiceControl::Shutdown] {
            let (tx, rx) = control_channel();
            assert_eq!(dispatch_control(&tx, control), 0);
            assert_eq!(rx.recv().unwrap(), control);
            assert!(rx.claim_terminal());
            assert!(rx.claim_terminal());
            assert!(rx.stop_requested());
            assert_eq!(
                dispatch_control(&tx, ServiceControl::Stop),
                ERROR_SERVICE_NOT_ACTIVE.0
            );
        }
    }

    #[test]
    fn terminal_claim_and_stop_acceptance_have_one_atomic_winner() {
        for iteration in 0..32 {
            let (tx, rx) = control_channel();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let sender_barrier = barrier.clone();
            let sender = std::thread::spawn(move || {
                sender_barrier.wait();
                dispatch_control(
                    &tx,
                    if iteration % 2 == 0 {
                        ServiceControl::Stop
                    } else {
                        ServiceControl::Shutdown
                    },
                )
            });
            barrier.wait();
            let stopped = rx.claim_terminal();
            let result = sender.join().unwrap();
            assert_eq!(result == 0, stopped);
            assert_eq!(rx.stop_requested(), stopped);
            assert_eq!(rx.claim_terminal(), stopped);
        }
    }

    #[test]
    fn stop_intent_survives_full_queue_delivery_and_drain() {
        for terminal in [ServiceControl::Stop, ServiceControl::Shutdown] {
            let (tx, rx) = control_channel();
            assert!(!rx.stop_requested());
            for _ in 0..8 {
                assert_eq!(dispatch_control(&tx, ServiceControl::Other(174)), 0);
            }
            assert!(!rx.stop_requested());
            assert_eq!(dispatch_control(&tx, terminal), 0);
            assert!(rx.stop_requested());
            assert_eq!(rx.recv_timeout(Duration::ZERO).unwrap(), terminal);
            for _ in 0..8 {
                assert_eq!(rx.try_recv().unwrap(), ServiceControl::Other(174));
            }
            assert!(matches!(
                rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            assert!(rx.stop_requested());
        }
    }

    #[test]
    fn ordinary_and_disconnected_controls_do_not_publish_stop_intent() {
        let (tx, rx) = control_channel();
        for control in [
            ServiceControl::Pause,
            ServiceControl::Continue,
            ServiceControl::Interrogate,
        ] {
            assert_eq!(dispatch_control(&tx, control), 0);
            assert!(!rx.stop_requested());
        }
        drop(rx);
        assert_eq!(
            dispatch_control(&tx, ServiceControl::Stop),
            ERROR_SERVICE_NOT_ACTIVE.0
        );
        assert_eq!(
            tx.pending.decision.load(Ordering::Acquire) & STOP_REQUESTED,
            0
        );
    }

    #[test]
    fn waiting_receiver_observes_stop_intent_before_returning_the_control() {
        let (tx, rx) = control_channel();
        let waiter = std::thread::spawn(move || {
            let control = rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(rx.stop_requested());
            control
        });
        assert_eq!(dispatch_control(&tx, ServiceControl::Shutdown), 0);
        assert_eq!(waiter.join().unwrap(), ServiceControl::Shutdown);
    }

    #[test]
    fn dispatcher_rejects_invalid_names_before_registering_global_state() {
        for name in ["", "bad\0name", "bad\\name"] {
            assert!(matches!(
                run_service_dispatcher(name, |_: ServiceContext| {}),
                Err(Error::InvalidConfig(_))
            ));
        }
    }
    #[test]
    fn terminal_racing_dequeued_control_preserves_the_ordinary_control() {
        let (tx, rx) = control_channel();
        assert_eq!(dispatch_control(&tx, ServiceControl::Stop), 0);
        assert_eq!(rx.deliver(ServiceControl::Pause), ServiceControl::Stop);
        assert_eq!(rx.try_recv().unwrap(), ServiceControl::Pause);
        assert!(matches!(
            rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn terminal_controls_survive_a_full_ordinary_queue() {
        for terminal in [ServiceControl::Stop, ServiceControl::Shutdown] {
            let (tx, rx) = control_channel();
            for _ in 0..8 {
                assert_eq!(dispatch_control(&tx, ServiceControl::Other(174)), 0);
            }
            assert_eq!(dispatch_control(&tx, ServiceControl::Pause), ERROR_RETRY.0);
            for _ in 0..100 {
                assert_eq!(dispatch_control(&tx, terminal), 0);
            }
            assert_eq!(rx.recv_timeout(Duration::ZERO).unwrap(), terminal);
            for _ in 0..8 {
                assert_eq!(rx.try_recv().unwrap(), ServiceControl::Other(174));
            }
            assert!(matches!(
                rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
        }
    }

    #[test]
    fn shutdown_coalesces_stop_and_wakes_a_waiting_receiver() {
        let (tx, rx) = control_channel();
        assert_eq!(dispatch_control(&tx, ServiceControl::Stop), 0);
        assert_eq!(dispatch_control(&tx, ServiceControl::Shutdown), 0);
        assert_eq!(rx.recv().unwrap(), ServiceControl::Shutdown);
        let waiter = std::thread::spawn(move || rx.recv_timeout(Duration::from_secs(2)).unwrap());
        assert_eq!(dispatch_control(&tx, ServiceControl::Stop), 0);
        assert_eq!(waiter.join().unwrap(), ServiceControl::Stop);
    }

    #[test]
    fn interrogate_uses_no_capacity_and_disconnected_controls_fail() {
        let (tx, rx) = control_channel();
        for _ in 0..100 {
            assert_eq!(dispatch_control(&tx, ServiceControl::Interrogate), 0);
        }
        assert!(matches!(
            rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        drop(rx);
        for control in [
            ServiceControl::Stop,
            ServiceControl::Shutdown,
            ServiceControl::Pause,
            ServiceControl::Other(174),
        ] {
            assert_eq!(dispatch_control(&tx, control), ERROR_SERVICE_NOT_ACTIVE.0);
        }
    }
}
