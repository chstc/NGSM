use std::collections::BTreeMap;

use servicemanager_core::{ExitAction, ExitActionPolicy};

use crate::error::{message_error, OpResult, Result};
use crate::specs::RecoverySpec;

/// Validate a per-exit-code action map key.
///
/// The supervisor matches each child exit code against entries in
/// `AppExit\<code>`, parsed as `i32`; any other shape would never fire
/// at runtime but would persist in the registry, silently broken.
///
/// `"default"` is rejected explicitly: the default exit action is a
/// separate field (`RestartPolicy::default_action` / the unnamed
/// `AppExit` registry value) and accepting it in the per-code map
/// would create two competing sources of truth for the same setting.
///
/// Whitespace, `=`, NUL, and other control characters are rejected
/// because the CLI's `CODE=ACTION` parser is line-oriented and would
/// produce nonsense splits, and because such characters cannot round-
/// trip cleanly through the registry as a value name.
pub fn validate_exit_action_key(s: &str) -> Result<()> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(message_error("exit-action key must not be empty"));
    }
    if trimmed.eq_ignore_ascii_case("default") {
        return Err(message_error(
            "'default' is not a per-exit-code key; set the default action separately",
        ));
    }
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(message_error(
            "exit-action key must not contain whitespace or control characters",
        ));
    }
    if s.contains('=') {
        return Err(message_error("exit-action key must not contain '='"));
    }
    if s.contains('\0') {
        return Err(message_error("exit-action key must not contain NUL"));
    }
    if s.parse::<i32>().is_err() {
        return Err(message_error(
            "exit-action key must be an i32 exit code (e.g. -1, 0, 1, 2147483647)",
        ));
    }
    Ok(())
}

/// Save a restart-policy and exit-action configuration for a managed service.
///
/// Re-reads the managed config from the registry (never trusting a
/// possibly-stale caller snapshot, exactly as `edit` does), applies the
/// restart-policy and exit-action fields, and writes it all back.
pub fn save_recovery(spec: RecoverySpec) -> OpResult {
    // Validate every per-exit-code key up front. `save_recovery` is the
    // single source of truth that every caller (CLI, broker, GUI) ends
    // up funneling through, so an out-of-spec key cannot reach the
    // registry no matter which surface produced it.
    for code in spec.exit_actions.keys() {
        validate_exit_action_key(code)
            .map_err(|e| message_error(format!("exit-action code '{code}': {e}")))?;
    }
    let Some(mut managed) = servicemanager_registry::read_managed_config(&spec.name)? else {
        return Err(message_error(format!(
            "'{}' is not an NGSM-managed service — refusing to edit its recovery policy",
            spec.name
        )));
    };
    managed.restart.restart_delay_ms = spec.restart_delay_ms;
    managed.restart.throttle_delay_ms = spec.throttle_delay_ms;
    // The editor always writes an explicit default action; a service that
    // previously had no explicit default is promoted to one (semantically
    // equivalent at runtime, since the supervisor's implicit fallback is Restart).
    managed.restart.default_action = Some(spec.default_action);
    managed.exit_actions = spec
        .exit_actions
        .iter()
        .map(|(code, action)| (code.clone(), ExitActionPolicy { action: *action }))
        .collect();
    servicemanager_registry::write_managed_config(&spec.name, &managed)?;
    Ok(format!("Saved recovery policy for '{}'.", spec.name))
}

/// Read the current recovery policy for a managed service. Returns an
/// `Err` if the service is not NGSM-managed or its config is unreadable.
pub fn read_recovery(name: &str) -> Result<RecoverySpec> {
    let Some(managed) = servicemanager_registry::read_managed_config(name)? else {
        return Err(message_error(format!(
            "'{}' is not an NGSM-managed service",
            name
        )));
    };
    // The registry pseudo-key "default" mirrors restart.default_action;
    // filter it out so the returned spec only contains per-exit-code
    // entries (matches what the GUI's RecoveryForm does).
    let exit_actions: BTreeMap<String, ExitAction> = managed
        .exit_actions
        .iter()
        .filter(|(code, _)| code.as_str() != "default")
        .map(|(code, policy)| (code.clone(), policy.action))
        .collect();
    Ok(RecoverySpec {
        name: name.to_string(),
        restart_delay_ms: managed.restart.restart_delay_ms,
        throttle_delay_ms: managed.restart.throttle_delay_ms,
        default_action: managed
            .restart
            .default_action
            .unwrap_or(ExitAction::Restart),
        exit_actions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_recovery_for_unknown_service_returns_error_mentioning_managed() {
        let err = read_recovery("__definitely_does_not_exist_zzz")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not an NGSM-managed service") || err.contains("not"),
            "error should mention not-managed: {err}"
        );
    }

    #[test]
    fn validate_exit_action_key_accepts_negative_and_zero_and_large() {
        // Every valid signed-32 exit code is acceptable. The supervisor
        // matches arbitrary i32 codes, so the validator must too.
        assert!(validate_exit_action_key("-1").is_ok());
        assert!(validate_exit_action_key("0").is_ok());
        assert!(validate_exit_action_key("1").is_ok());
        assert!(validate_exit_action_key("2147483647").is_ok());
        assert!(validate_exit_action_key("-2147483648").is_ok());
    }

    #[test]
    fn validate_exit_action_key_rejects_default_and_empty() {
        // "default" belongs in `RestartPolicy::default_action`, not the
        // per-code map — accepting it here would silently shadow that
        // separate field at write time.
        assert!(validate_exit_action_key("default").is_err());
        assert!(validate_exit_action_key("Default").is_err());
        assert!(validate_exit_action_key("DEFAULT").is_err());
        assert!(validate_exit_action_key("").is_err());
        assert!(validate_exit_action_key("   ").is_err());
    }

    #[test]
    fn validate_exit_action_key_rejects_garbage() {
        // `=` would have been split off by the CLI's CODE=ACTION parser,
        // so anything that still contains `=` here is malformed input.
        assert!(validate_exit_action_key("=ignore").is_err());
        // Non-numeric: would never match a real exit code at runtime.
        assert!(validate_exit_action_key("abc").is_err());
        assert!(validate_exit_action_key("1=foo").is_err());
        // Embedded NUL: cannot round-trip as a registry value name.
        assert!(validate_exit_action_key("1\0").is_err());
        // Trailing space: i32::parse rejects, so the key would never
        // match anything (yet would persist in the registry).
        assert!(validate_exit_action_key("1 ").is_err());
        // Whitespace in the middle: same.
        assert!(validate_exit_action_key("1\t2").is_err());
        // Out-of-range integers are rejected by i32::parse.
        assert!(validate_exit_action_key("2147483648").is_err());
        assert!(validate_exit_action_key("-2147483649").is_err());
    }
}
