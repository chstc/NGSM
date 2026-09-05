use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::transition::TransitionOutcome;

const TRANSITION_BUDGET: Duration = Duration::from_secs(3);
const MAX_MEMBER_PASSES: usize = 16;

pub(crate) trait Member: Send + Sync {
    fn id(&self) -> u32;
    fn running(&self) -> Result<bool, String>;
    fn suspend(&self) -> Result<bool, String>;
    fn resume(&self) -> Result<bool, String>;
}

#[cfg(windows)]
impl Member for servicemanager_win32::process_tree::PinnedProcess {
    fn id(&self) -> u32 {
        self.id()
    }
    fn running(&self) -> Result<bool, String> {
        self.is_running().map_err(|e| e.to_string())
    }
    fn suspend(&self) -> Result<bool, String> {
        self.suspend().map_err(|e| e.to_string())
    }
    fn resume(&self) -> Result<bool, String> {
        self.resume().map_err(|e| e.to_string())
    }
}

#[derive(Default)]
pub(crate) struct PauseState {
    pub(crate) paused: bool,
    owned: Vec<Arc<dyn Member>>,
}

impl PauseState {
    pub(crate) fn change(
        &mut self,
        pause: bool,
        mut members: impl FnMut() -> Result<Vec<Arc<dyn Member>>, String>,
        cancelled: impl Fn() -> bool,
    ) -> TransitionOutcome {
        if cancelled() {
            return TransitionOutcome::Cancelled;
        }
        if self.paused == pause {
            return TransitionOutcome::Applied;
        }
        if !pause {
            return self.resume_owned(members, cancelled);
        }
        let mut changed: Vec<Arc<dyn Member>> = Vec::new();
        let deadline = Instant::now() + TRANSITION_BUDGET;
        let mut stable = false;
        let attempt = (|| -> Result<(), String> {
            for _ in 0..MAX_MEMBER_PASSES {
                if cancelled() {
                    return Err("control cancelled".into());
                }
                if Instant::now() >= deadline {
                    return Err("process membership did not stabilize before the deadline".into());
                }
                let snapshot = members()?;
                if Instant::now() >= deadline {
                    return Err("process membership exceeded the transition deadline".into());
                }
                let mut added = false;
                for process in snapshot {
                    if cancelled() {
                        return Err("control cancelled".into());
                    }
                    if Instant::now() >= deadline {
                        return Err("process membership exceeded the transition deadline".into());
                    }
                    if changed.iter().any(|p| p.id() == process.id()) {
                        continue;
                    }
                    if process.suspend()? {
                        changed.push(process);
                        added = true;
                    }
                }
                if !added {
                    stable = true;
                    break;
                }
            }
            if !stable {
                return Err("process membership exceeded the bounded stable-member passes".into());
            }
            if cancelled() {
                return Err("control cancelled".into());
            }
            Ok(())
        })();
        if let Err(error) = attempt {
            return failure(error, rollback(&changed, false), cancelled());
        }
        self.owned = changed;
        self.paused = true;
        TransitionOutcome::Applied
    }

    fn resume_owned(
        &mut self,
        mut members: impl FnMut() -> Result<Vec<Arc<dyn Member>>, String>,
        cancelled: impl Fn() -> bool,
    ) -> TransitionOutcome {
        let mut resumed = Vec::new();
        let deadline = Instant::now() + TRANSITION_BUDGET;
        let attempt = (|| -> Result<(), String> {
            for process in self.owned.iter().rev() {
                if cancelled() {
                    return Err("control cancelled".into());
                }
                if Instant::now() >= deadline {
                    return Err("resume exceeded the transition deadline".into());
                }
                if process.resume()? {
                    resumed.push(Arc::clone(process));
                }
            }
            if cancelled() {
                return Err("control cancelled".into());
            }
            if Instant::now() >= deadline {
                return Err("resume exceeded the transition deadline".into());
            }
            Ok(())
        })();
        if let Err(error) = attempt {
            // Cancellation cannot skip restoration: resumed processes may already
            // have produced children. Restore the invariant within one bounded
            // recovery budget, or let the caller fail-stop the contained job.
            let recovery_deadline = Instant::now() + TRANSITION_BUDGET;
            let restored = rollback_until(&resumed, true, recovery_deadline)
                .and_then(|()| self.restore_paused_members(&mut members, recovery_deadline));
            return failure(error, restored, cancelled());
        }
        self.owned.clear();
        self.paused = false;
        TransitionOutcome::Applied
    }

    fn restore_paused_members(
        &mut self,
        members: &mut impl FnMut() -> Result<Vec<Arc<dyn Member>>, String>,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut stable_passes = 0;
        for _ in 0..MAX_MEMBER_PASSES {
            if Instant::now() >= deadline {
                return Err("paused membership recovery exceeded its deadline".into());
            }
            let snapshot = members()?;
            if Instant::now() >= deadline {
                return Err("paused membership recovery exceeded its deadline".into());
            }
            let mut added = false;
            for process in snapshot {
                if Instant::now() >= deadline {
                    return Err("paused membership recovery exceeded its deadline".into());
                }
                if self.owned.iter().any(|owned| owned.id() == process.id()) {
                    continue;
                }
                if process.suspend()? {
                    // Retain exactly our one increment and its pinned identity
                    // so a later Continue includes this newly discovered member.
                    self.owned.push(process);
                    added = true;
                }
            }
            stable_passes = if added { 0 } else { stable_passes + 1 };
            if stable_passes == 2 {
                return Ok(());
            }
        }
        Err("paused membership did not stabilize within the bounded recovery passes".into())
    }

    pub(crate) fn clear_generation(&mut self) {
        // Intent survives a child exit; only per-process increments are discarded.
        self.owned.clear();
    }
}

fn rollback(processes: &[Arc<dyn Member>], suspend: bool) -> Result<(), String> {
    rollback_until(processes, suspend, Instant::now() + TRANSITION_BUDGET)
}

fn rollback_until(
    processes: &[Arc<dyn Member>],
    suspend: bool,
    deadline: Instant,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for process in processes.iter().rev() {
        if Instant::now() >= deadline {
            errors.push("suspension rollback exceeded its deadline".into());
            break;
        }
        if matches!(process.running(), Ok(false)) {
            continue;
        }
        let result = if suspend {
            process.suspend()
        } else {
            process.resume()
        };
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn failure(error: String, rollback: Result<(), String>, cancelled: bool) -> TransitionOutcome {
    match rollback {
        Err(rollback) => {
            TransitionOutcome::Degraded(format!("{error}; rollback failed: {rollback}"))
        }
        Ok(()) if cancelled => TransitionOutcome::Cancelled,
        Ok(()) => TransitionOutcome::Rejected(error),
    }
}

#[cfg(all(test, windows))]
#[path = "process_control_tests.rs"]
mod tests;
