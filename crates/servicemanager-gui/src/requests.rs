//! UI-thread request lifecycles. These reducers own acceptance, invalidation
//! and completion decisions; the controller only renders their effects.

use std::fmt;

use servicemanager_core::Result as CoreResult;

use crate::data::RecoverySpec;
use crate::recovery::RecoveryForm;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request<T> {
    pub id: u64,
    pub target: T,
}

#[derive(Default)]
pub struct RequestSequence {
    next_id: u64,
}

impl RequestSequence {
    pub fn issue<T>(&mut self, target: T) -> Request<T> {
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("request identifier exhausted");
        Request {
            id: self.next_id,
            target,
        }
    }
}

pub struct Pending<T> {
    sequence: RequestSequence,
    current: Option<Request<T>>,
}

#[derive(Default)]
pub struct RefreshState {
    pub retry: bool,
}

impl RefreshState {
    pub fn request<E>(&mut self, send: impl FnOnce() -> Result<(), E>) -> Result<(), E> {
        self.retry = true;
        send()?;
        self.retry = false;
        Ok(())
    }
}

impl<T> Default for Pending<T> {
    fn default() -> Self {
        Self {
            sequence: RequestSequence::default(),
            current: None,
        }
    }
}

impl<T: Clone + PartialEq> Pending<T> {
    pub fn busy(&self) -> bool {
        self.current.is_some()
    }

    pub fn invalidate(&mut self) {
        self.current = None;
    }

    pub fn submit<E>(
        &mut self,
        target: T,
        send: impl FnOnce(Request<T>) -> Result<(), E>,
    ) -> Result<Request<T>, E> {
        self.invalidate();
        let request = self.sequence.issue(target);
        send(request.clone())?;
        self.current = Some(request.clone());
        Ok(request)
    }

    pub fn finish(&mut self, request: &Request<T>) -> bool {
        if self.current.as_ref() != Some(request) {
            return false;
        }
        self.current = None;
        true
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(i32)]
pub enum ModalKind {
    #[default]
    Closed = 0,
    Install = 1,
    Edit = 2,
    Remove = 3,
    Processes = 4,
    Warnings = 5,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModalTarget {
    pub kind: ModalKind,
    pub service: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SubmitError<E> {
    Busy,
    Inactive,
    Send(E),
}

impl<E: fmt::Display> fmt::Display for SubmitError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => f.write_str("An operation is already in progress."),
            Self::Inactive => f.write_str("This editor is no longer active."),
            Self::Send(e) => write!(f, "Background worker unavailable: {e}. Please retry."),
        }
    }
}

#[derive(Default)]
pub struct ModalState {
    pub kind: ModalKind,
    pub generation: u64,
    pending: Pending<ModalTarget>,
}

impl ModalState {
    pub fn busy(&self) -> bool {
        self.pending.busy()
    }

    pub fn replace(&mut self, kind: ModalKind) -> bool {
        if self.busy() && matches!(self.kind, ModalKind::Install | ModalKind::Edit) {
            return false;
        }
        self.pending.invalidate();
        self.generation = self
            .generation
            .checked_add(1)
            .expect("modal generation exhausted");
        self.kind = kind;
        true
    }

    pub fn submit<E>(
        &mut self,
        service: String,
        send: impl FnOnce(Request<ModalTarget>) -> Result<(), E>,
    ) -> Result<Request<ModalTarget>, SubmitError<E>> {
        if self.busy() {
            return Err(SubmitError::Busy);
        }
        if !matches!(
            self.kind,
            ModalKind::Install | ModalKind::Edit | ModalKind::Processes
        ) {
            return Err(SubmitError::Inactive);
        }
        self.pending
            .submit(
                ModalTarget {
                    kind: self.kind,
                    service,
                },
                send,
            )
            .map_err(SubmitError::Send)
    }

    pub fn finish(&mut self, request: &Request<ModalTarget>) -> bool {
        self.pending.finish(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogTarget {
    pub service: String,
    pub stderr: bool,
}

#[derive(Default)]
pub struct LogViewState {
    pending: Pending<LogTarget>,
    pub target: Option<LogTarget>,
    pub status: String,
    pub lines: Vec<String>,
}

impl LogViewState {
    pub fn leave(&mut self) {
        self.pending.invalidate();
    }

    pub fn request<E: fmt::Display>(
        &mut self,
        target: Option<LogTarget>,
        send: impl FnOnce(Request<LogTarget>) -> Result<(), E>,
    ) {
        self.pending.invalidate();
        self.lines.clear();
        self.target = target.clone();
        let Some(target) = target else {
            self.status = "Select a service in the Services view to view its log.".into();
            return;
        };
        self.status = "Loading…".into();
        if let Err(e) = self.pending.submit(target, send) {
            self.status = format!("Log request not queued: {e}. Please retry.");
        }
    }

    pub fn received(
        &mut self,
        request: &Request<LogTarget>,
        status: String,
        lines: Vec<String>,
    ) -> bool {
        if !self.pending.finish(request) {
            return false;
        }
        self.status = status;
        self.lines = lines;
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryWork {
    Read,
    Save,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryTarget {
    pub service: String,
    pub generation: u64,
    pub work: RecoveryWork,
}

#[derive(Default)]
pub struct RecoveryEditor {
    pub draft: Option<RecoveryForm>,
    service: Option<String>,
    generation: u64,
    pending: Pending<RecoveryTarget>,
}

impl RecoveryEditor {
    pub fn busy(&self) -> bool {
        self.pending.busy()
    }

    pub fn active(&self) -> bool {
        self.service.is_some()
    }

    pub fn editable_draft(&mut self) -> Option<&mut RecoveryForm> {
        if !self.active() || self.busy() {
            return None;
        }
        self.draft.as_mut()
    }

    pub fn leave(&mut self) {
        self.pending.invalidate();
        self.service = None;
    }

    pub fn activate(&mut self, service: String) {
        self.leave();
        self.generation = self
            .generation
            .checked_add(1)
            .expect("form generation exhausted");
        if self
            .draft
            .as_ref()
            .is_some_and(|form| form.service != service)
        {
            self.draft = None;
        }
        self.service = Some(service);
    }

    pub fn submit<E>(
        &mut self,
        work: RecoveryWork,
        send: impl FnOnce(Request<RecoveryTarget>) -> Result<(), E>,
    ) -> Result<Request<RecoveryTarget>, SubmitError<E>> {
        if self.busy() {
            return Err(SubmitError::Busy);
        }
        let Some(service) = self.service.clone() else {
            return Err(SubmitError::Inactive);
        };
        self.pending
            .submit(
                RecoveryTarget {
                    service,
                    generation: self.generation,
                    work,
                },
                send,
            )
            .map_err(SubmitError::Send)
    }

    pub fn finish(&mut self, request: &Request<RecoveryTarget>) -> bool {
        self.pending.finish(request)
    }

    pub fn loaded(
        &mut self,
        request: &Request<RecoveryTarget>,
        result: CoreResult<RecoverySpec>,
    ) -> Option<Result<(), String>> {
        if !self.finish(request) {
            return None;
        }
        Some(match result {
            Ok(spec) if spec.name == request.target.service => {
                self.draft = Some(RecoveryForm::from_spec(&spec));
                Ok(())
            }
            Ok(_) => Err("Recovery response did not match the requested service.".into()),
            Err(e) => Err(e.to_string()),
        })
    }
}

pub struct MutationOutcome {
    pub apply_local: bool,
    pub refresh: bool,
    pub error: Option<String>,
    pub message: String,
}

pub fn mutation_outcome(
    apply_local: bool,
    operation: &str,
    result: CoreResult<String>,
) -> MutationOutcome {
    match result {
        Ok(message) => MutationOutcome {
            apply_local,
            refresh: true,
            error: None,
            message,
        },
        Err(e) => {
            let error = e.to_string();
            MutationOutcome {
                apply_local,
                // A failed restart, for example, may already have stopped the
                // service. Reconcile accepted work even when it reports failure.
                refresh: true,
                message: format!("{operation}: {error}"),
                error: Some(error),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationId {
    Action(u64),
    Modal(u64),
    Recovery(u64),
}

#[derive(Default)]
pub struct StatusState {
    scan: String,
    outcome: Option<String>,
    pending: std::collections::VecDeque<(OperationId, String)>,
}

impl StatusState {
    pub fn scan(&mut self, text: String) {
        self.scan = text;
    }

    pub fn operation(&mut self, text: String) {
        self.outcome = Some(text);
    }

    pub fn begin(&mut self, id: OperationId, text: String) {
        self.outcome = None;
        self.pending.retain(|(key, _)| *key != id);
        // The worker queue has 16 slots. Keep notification bookkeeping bounded
        // even if a burst of callbacks delays result draining.
        if self.pending.len() == 32 {
            self.pending.pop_front();
        }
        self.pending.push_back((id, text));
    }

    pub fn finish(&mut self, id: OperationId, text: String) {
        self.pending.retain(|(key, _)| *key != id);
        self.outcome = Some(text);
    }

    pub fn text(&self) -> String {
        let mut parts: Vec<String> = self.outcome.iter().cloned().collect();
        if let Some((_, pending)) = self.pending.back() {
            parts.push(if self.pending.len() == 1 {
                pending.clone()
            } else {
                format!("{pending} (+{} other pending)", self.pending.len() - 1)
            });
        }
        if !self.scan.is_empty() {
            parts.push(self.scan.clone());
        }
        parts.join("  |  ")
    }

    pub fn details(&self) -> Vec<String> {
        self.outcome
            .iter()
            .cloned()
            .chain(self.pending.iter().map(|(_, message)| message.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use servicemanager_core::Error;

    fn sent<T>(_: Request<T>) -> Result<(), &'static str> {
        Ok(())
    }

    #[test]
    fn late_process_success_or_error_cannot_replace_any_new_modal() {
        for next in [
            ModalKind::Closed,
            ModalKind::Install,
            ModalKind::Edit,
            ModalKind::Remove,
            ModalKind::Processes,
            ModalKind::Warnings,
        ] {
            for _is_error in [false, true] {
                let mut modal = ModalState::default();
                assert!(modal.replace(ModalKind::Processes));
                let old = modal.submit("A".into(), sent).unwrap();
                assert!(modal.replace(next));
                assert!(!modal.finish(&old));
                assert_eq!(modal.kind, next);
            }
        }
    }

    #[test]
    fn accepted_mutation_blocks_cancel_replacement_and_duplicate_submission() {
        for kind in [ModalKind::Install, ModalKind::Edit] {
            let mut modal = ModalState::default();
            modal.replace(kind);
            let accepted = modal.submit("A".into(), sent).unwrap();
            for replacement in [ModalKind::Closed, ModalKind::Processes, ModalKind::Install] {
                assert!(!modal.replace(replacement));
            }
            assert_eq!(modal.submit("A".into(), sent), Err(SubmitError::Busy));
            assert!(modal.busy());
            assert!(modal.finish(&accepted));
            assert!(modal.replace(ModalKind::Closed));
        }
    }

    #[test]
    fn rejected_requests_have_no_active_token_and_can_retry() {
        for failure in ["full", "disconnected"] {
            let mut modal = ModalState::default();
            modal.replace(ModalKind::Edit);
            assert_eq!(
                modal.submit("A".into(), |_| Err(failure)),
                Err(SubmitError::Send(failure))
            );
            assert!(!modal.busy());
            let request = modal.submit("A".into(), sent).unwrap();
            assert!(modal.finish(&request));
        }
    }

    #[test]
    fn unrelated_queue_failure_does_not_unlock_an_accepted_mutation() {
        let mut modal = ModalState::default();
        modal.replace(ModalKind::Install);
        let accepted = modal.submit("A".into(), sent).unwrap();
        let mut logs = Pending::default();
        assert!(logs.submit("B", |_| Err("full")).is_err());
        assert!(!logs.busy());
        assert!(modal.busy());
        assert!(modal.finish(&accepted));
    }

    #[test]
    fn log_aba_and_stream_switch_only_accept_newest_request() {
        let mut logs = Pending::default();
        let a = LogTarget {
            service: "A".into(),
            stderr: false,
        };
        let old = logs.submit(a.clone(), sent).unwrap();
        let b = logs
            .submit(
                LogTarget {
                    service: "B".into(),
                    stderr: true,
                },
                sent,
            )
            .unwrap();
        let new = logs.submit(a, sent).unwrap();
        assert!(!logs.finish(&old));
        assert!(!logs.finish(&b));
        assert!(logs.finish(&new));
        assert!(!logs.finish(&new));
    }

    #[test]
    fn failed_superseding_log_request_does_not_resurrect_old_content() {
        let mut logs = Pending::default();
        let old = logs.submit("A", sent).unwrap();
        assert!(logs.submit("B", |_| Err("full")).is_err());
        assert!(!logs.finish(&old));
        assert!(!logs.busy());
    }

    fn policy(service: &str, delay: u32) -> RecoverySpec {
        RecoverySpec {
            name: service.into(),
            restart_delay_ms: Some(delay),
            throttle_delay_ms: None,
            default_action: servicemanager_core::ExitAction::Restart,
            exit_actions: Default::default(),
        }
    }

    #[test]
    fn recovery_reload_uses_backend_result_and_failure_preserves_the_draft() {
        let mut editor = RecoveryEditor {
            draft: Some(RecoveryForm::from_spec(&policy("A", 100))),
            ..Default::default()
        };
        editor.activate("A".into());
        let request = editor.submit(RecoveryWork::Read, sent).unwrap();
        assert!(editor
            .loaded(&request, Ok(policy("A", 200)))
            .unwrap()
            .is_ok());
        assert_eq!(editor.draft.as_ref().unwrap().restart_delay, "200");
        editor.activate("A".into());
        let request = editor.submit(RecoveryWork::Read, sent).unwrap();
        assert!(editor
            .loaded(&request, Err(Error::other("read failed")))
            .unwrap()
            .is_err());
        assert_eq!(editor.draft.as_ref().unwrap().restart_delay, "200");
        assert!(!editor.busy());
    }

    #[test]
    fn recovery_service_and_form_generations_isolate_reads_and_saves() {
        let mut editor = RecoveryEditor::default();
        editor.activate("A".into());
        let read = editor.submit(RecoveryWork::Read, sent).unwrap();
        editor.leave();
        editor.activate("B".into());
        assert!(editor.loaded(&read, Ok(policy("A", 1))).is_none());
        editor.activate("A".into());
        let new = editor.submit(RecoveryWork::Read, sent).unwrap();
        assert!(editor
            .loaded(&read, Err(Error::other("old read")))
            .is_none());
        assert!(editor.loaded(&new, Ok(policy("A", 2))).unwrap().is_ok());
        let save = editor.submit(RecoveryWork::Save, sent).unwrap();
        assert_eq!(
            editor.submit(RecoveryWork::Save, sent),
            Err(SubmitError::Busy)
        );
        editor.leave();
        editor.activate("B".into());
        assert!(!editor.finish(&save));
        assert!(editor.draft.is_none());
    }

    #[test]
    fn recovery_enqueue_failure_clears_busy_and_retains_existing_draft() {
        let mut editor = RecoveryEditor {
            draft: Some(RecoveryForm::from_spec(&policy("A", 100))),
            ..Default::default()
        };
        editor.activate("A".into());
        for work in [RecoveryWork::Read, RecoveryWork::Save] {
            assert!(editor.submit(work, |_| Err("disconnected")).is_err());
            assert!(!editor.busy());
            assert_eq!(editor.draft.as_ref().unwrap().restart_delay, "100");
        }
    }

    #[test]
    fn stale_mutations_keep_attributable_outcomes_and_success_refreshes() {
        for current in [false, true] {
            let success = mutation_outcome(current, "Install A", Ok("Installed A".into()));
            assert_eq!(success.apply_local, current);
            assert!(success.refresh);
            assert_eq!(success.message, "Installed A");
            let failure = mutation_outcome(current, "Save A", Err(Error::other("denied")));
            assert_eq!(failure.apply_local, current);
            assert!(failure.refresh);
            assert!(failure.message.contains("Save A"));
            assert!(failure.error.unwrap().contains("denied"));
        }
    }

    #[test]
    fn scan_results_do_not_erase_pending_success_or_failure_status() {
        let mut status = StatusState::default();
        for outcome in ["Restarting A", "A: access denied", "Installed B"] {
            status.operation(outcome.into());
            for scan in ["4 services", "4 services — 1 warning", "Refresh failed"] {
                status.scan(scan.into());
                assert!(status.text().contains(outcome));
                assert!(status.text().contains(scan));
            }
        }
        status.operation("Starting C".into());
        assert!(!status.text().contains("Installed B"));
    }

    #[test]
    fn log_view_never_labels_old_content_as_a_different_service_or_stream() {
        for target in [
            LogTarget {
                service: "B".into(),
                stderr: false,
            },
            LogTarget {
                service: "A".into(),
                stderr: true,
            },
        ] {
            let mut view = LogViewState::default();
            let a = LogTarget {
                service: "A".into(),
                stderr: false,
            };
            let mut request = None;
            view.request(Some(a.clone()), |r| {
                request = Some(r);
                Ok::<_, &str>(())
            });
            let old = request.take().unwrap();
            assert!(view.received(&old, "loaded A".into(), vec!["A stdout".into()]));
            view.request(Some(target.clone()), |_| Err("full"));
            assert_eq!(view.target, Some(target));
            assert!(view.lines.is_empty());
            assert!(view.status.contains("retry"));
            assert!(!view.status.contains("Loading"));
            assert!(!view.received(&old, "old A".into(), vec!["stale".into()]));
            view.request(Some(a), |r| {
                request = Some(r);
                Ok::<_, &str>(())
            });
            assert!(view.lines.is_empty());
            assert!(!view.received(&old, "old A".into(), vec!["stale".into()]));
            assert!(view.received(&request.unwrap(), "fresh A".into(), vec!["fresh".into()]));
            assert_eq!(view.lines, ["fresh"]);
            view.request(None, sent);
            assert!(view.target.is_none());
            assert!(view.lines.is_empty());
        }
    }

    #[test]
    fn recovery_draft_is_frozen_during_reads_and_saves_and_inactive_after_leaving() {
        let mut editor = RecoveryEditor {
            draft: Some(RecoveryForm::from_spec(&policy("A", 100))),
            ..Default::default()
        };
        editor.activate("A".into());
        editor.editable_draft().unwrap().restart_delay = "333".into();
        for work in [RecoveryWork::Read, RecoveryWork::Save] {
            let request = editor.submit(work, sent).unwrap();
            assert!(editor.editable_draft().is_none());
            assert!(editor.finish(&request));
            assert_eq!(editor.editable_draft().unwrap().restart_delay, "333");
        }
        editor.leave();
        assert!(editor.editable_draft().is_none());
    }

    #[test]
    fn older_completion_keeps_newer_operation_progress_and_outcome_attributable() {
        let mut status = StatusState::default();
        status.begin(OperationId::Action(1), "Restarting A".into());
        status.begin(OperationId::Modal(1), "Installing B".into());
        status.finish(OperationId::Action(1), "Restart A failed".into());
        status.scan("4 services".into());
        assert!(status.text().contains("Restart A failed"));
        assert!(status.text().contains("Installing B"));
        status.finish(OperationId::Modal(1), "Installed B".into());
        assert!(!status.text().contains("Installing B"));
        assert!(status.text().contains("Installed B"));
        for id in 0..100 {
            status.begin(OperationId::Action(id), format!("Pending {id}"));
        }
        assert_eq!(status.pending.len(), 32);
    }

    #[test]
    fn post_mutation_refresh_is_retried_after_backpressure_clears() {
        let mut refresh = RefreshState::default();
        for error in ["full", "disconnected"] {
            assert_eq!(refresh.request(|| Err(error)), Err(error));
            assert!(refresh.retry);
        }
        refresh.request(|| Ok::<_, &str>(())).unwrap();
        assert!(!refresh.retry);
    }
}
