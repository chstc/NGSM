//! Cancellation and completion share a lock. A cancelled queued control cannot
//! begin executing later; an executing control has a definitive pending outcome.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionOutcome {
    Applied,
    Cancelled,
    Rejected(String),
    Degraded(String),
}

enum Phase {
    Queued,
    Executing,
    Finished(TransitionOutcome),
}

struct State {
    phase: Mutex<Phase>,
    changed: Condvar,
    cancelled: AtomicBool,
}

#[derive(Clone)]
pub struct Transition {
    state: Arc<State>,
}

impl Transition {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(State {
                phase: Mutex::new(Phase::Queued),
                changed: Condvar::new(),
                cancelled: AtomicBool::new(false),
            }),
        }
    }

    pub fn outcome(&self) -> Option<TransitionOutcome> {
        match &*self.state.phase.lock().unwrap_or_else(|e| e.into_inner()) {
            Phase::Finished(outcome) => Some(outcome.clone()),
            _ => None,
        }
    }

    /// Some is a definitive outcome. None means execution has already begun:
    /// keep the transition pending until rollback or completion is confirmed.
    pub fn cancel(&self) -> Option<TransitionOutcome> {
        let mut phase = self.state.phase.lock().unwrap_or_else(|e| e.into_inner());
        self.state.cancelled.store(true, Ordering::Release);
        if matches!(*phase, Phase::Queued) {
            *phase = Phase::Finished(TransitionOutcome::Cancelled);
            self.state.changed.notify_all();
        }
        match &*phase {
            Phase::Finished(outcome) => Some(outcome.clone()),
            _ => None,
        }
    }

    pub(crate) fn execute(
        &self,
        operation: impl FnOnce(&AtomicBool) -> TransitionOutcome,
    ) -> TransitionOutcome {
        {
            let mut phase = self.state.phase.lock().unwrap_or_else(|e| e.into_inner());
            match &*phase {
                Phase::Queued => *phase = Phase::Executing,
                Phase::Finished(outcome) => return outcome.clone(),
                Phase::Executing => {
                    return TransitionOutcome::Degraded("control executed twice".into());
                }
            }
        }
        struct Completion<'a>(&'a Transition);
        impl Drop for Completion<'_> {
            fn drop(&mut self) {
                let mut phase = self.0.state.phase.lock().unwrap_or_else(|e| e.into_inner());
                if matches!(*phase, Phase::Executing) {
                    *phase = Phase::Finished(TransitionOutcome::Degraded(
                        "supervisor abandoned an executing control".into(),
                    ));
                    self.0.state.changed.notify_all();
                }
            }
        }
        let _completion = Completion(self);
        let outcome = operation(&self.state.cancelled);
        *self.state.phase.lock().unwrap_or_else(|e| e.into_inner()) =
            Phase::Finished(outcome.clone());
        self.state.changed.notify_all();
        outcome
    }

    pub(crate) fn reject(&self, message: &str) {
        self.execute(|_| TransitionOutcome::Rejected(message.into()));
    }

    pub(crate) fn wait(&self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let hard_deadline = deadline + Duration::from_secs(5);
        loop {
            if let Some(outcome) = self.outcome() {
                return match outcome {
                    TransitionOutcome::Applied => Ok(()),
                    TransitionOutcome::Cancelled => Err("control cancelled before commit".into()),
                    TransitionOutcome::Rejected(message) | TransitionOutcome::Degraded(message) => {
                        Err(message)
                    }
                };
            }
            if Instant::now() >= deadline {
                // Execution may have won the race. Do not return a guessed old state.
                self.cancel();
            }
            if Instant::now() >= hard_deadline {
                return Err(
                    "control cancellation remains pending; no stable state was confirmed".into(),
                );
            }
            let phase = self.state.phase.lock().unwrap_or_else(|e| e.into_inner());
            let _ = self
                .state
                .changed
                .wait_timeout(phase, Duration::from_millis(25));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn cancelled_queued_transition_never_executes_late() {
        let request = Transition::new();
        assert_eq!(request.cancel(), Some(TransitionOutcome::Cancelled));
        assert_eq!(
            request.execute(|_| panic!("abandoned operation must not run")),
            TransitionOutcome::Cancelled
        );
    }

    #[test]
    fn cancellation_racing_execution_stays_pending_until_definitive_completion() {
        let request = Transition::new();
        let worker_request = request.clone();
        let (started, ready) = mpsc::channel();
        let (release, proceed) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            worker_request.execute(|cancelled| {
                started.send(()).unwrap();
                proceed.recv().unwrap();
                assert!(cancelled.load(Ordering::Acquire));
                TransitionOutcome::Cancelled
            })
        });
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(request.cancel(), None);
        assert_eq!(request.outcome(), None);
        release.send(()).unwrap();
        assert_eq!(worker.join().unwrap(), TransitionOutcome::Cancelled);
        assert_eq!(request.outcome(), Some(TransitionOutcome::Cancelled));
    }

    #[test]
    fn completion_winning_timeout_is_not_reported_as_cancelled() {
        let request = Transition::new();
        request.execute(|_| TransitionOutcome::Applied);
        assert_eq!(request.cancel(), Some(TransitionOutcome::Applied));
    }
}
