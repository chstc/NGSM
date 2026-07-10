use servicemanager_core::{HookConfig, Result};

/// Supervisor-supported `(event, action)` hook points.
///
/// Mirrors `servicemanager-supervisor::hooks::HookPoint` exactly. If the
/// supervisor grows a new point, add it here too — anything not in this
/// list is silently dropped at runtime, so the CLI rejects it up front
/// rather than persisting a hook that will never fire.
const SUPPORTED_HOOK_POINTS: &[(&str, &str)] = &[
    ("Start", "Pre"),
    ("Start", "Post"),
    ("Stop", "Pre"),
    ("Exit", "Post"),
    ("Rotate", "Pre"),
    ("Rotate", "Post"),
    ("Power", "Change"),
    ("Power", "Resume"),
];

fn supported_hook_points_pretty() -> String {
    SUPPORTED_HOOK_POINTS
        .iter()
        .map(|(e, a)| format!("{e}/{a}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parse a `EVENT/ACTION=command` spec from `--hook`.
pub(crate) fn parse_hook_spec(raw: &str) -> Result<HookConfig> {
    let (lhs, command) = raw.split_once('=').ok_or_else(|| {
        servicemanager_core::Error::InvalidConfig(format!(
            "hook spec '{raw}' must be EVENT/ACTION=command"
        ))
    })?;
    let (event, action) = lhs.split_once('/').ok_or_else(|| {
        servicemanager_core::Error::InvalidConfig(format!(
            "hook spec '{raw}' must be EVENT/ACTION=command"
        ))
    })?;
    let event = event.trim();
    let action = action.trim();
    let command = command.trim();
    // Reject hook names that cannot be used as registry subkey / value names.
    servicemanager_core::validate_hook_component(event, "event")?;
    servicemanager_core::validate_hook_component(action, "action")?;
    // Reject `(event, action)` pairs the supervisor does not understand —
    // matched case-insensitively, since the registry layer is case-insensitive
    // and silently accepting `Foo/Bar=cmd` would install a hook that never
    // fires.
    if !SUPPORTED_HOOK_POINTS
        .iter()
        .any(|(e, a)| event.eq_ignore_ascii_case(e) && action.eq_ignore_ascii_case(a))
    {
        return Err(servicemanager_core::Error::InvalidConfig(format!(
            "hook spec '{raw}' uses unsupported event/action '{event}/{action}'; \
             supported points are: {}",
            supported_hook_points_pretty()
        )));
    }
    // An empty command would install a hook the supervisor cannot execute.
    if command.is_empty() {
        return Err(servicemanager_core::Error::InvalidConfig(format!(
            "hook spec '{raw}' has an empty command — provide a command to run"
        )));
    }
    Ok(HookConfig {
        event: event.to_string(),
        action: action.to_string(),
        command: command.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_spec_parses_event_action_command() {
        let h = parse_hook_spec("Start/Pre=C:\\warmup.cmd").unwrap();
        assert_eq!(h.event, "Start");
        assert_eq!(h.action, "Pre");
        assert_eq!(h.command, "C:\\warmup.cmd");
    }

    #[test]
    fn hook_spec_rejects_malformed_input() {
        assert!(parse_hook_spec("no-equals-sign").is_err());
        assert!(parse_hook_spec("NoSlash=command").is_err());
    }

    #[test]
    fn parse_hook_spec_accepts_supported_points() {
        // Every supervisor-supported (event, action) pair round-trips.
        for (event, action) in SUPPORTED_HOOK_POINTS {
            let raw = format!("{event}/{action}=C:\\hook.cmd");
            let h = parse_hook_spec(&raw)
                .unwrap_or_else(|e| panic!("expected {event}/{action} to be accepted, got {e:?}"));
            assert_eq!(h.event, *event);
            assert_eq!(h.action, *action);
            assert_eq!(h.command, "C:\\hook.cmd");
        }
    }

    #[test]
    fn parse_hook_spec_rejects_unsupported_pair() {
        // Unrecognized event/action pairs would install a hook the
        // supervisor silently ignores at runtime — reject up front.
        let err = parse_hook_spec("Foo/Bar=cmd").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported") && msg.contains("Foo/Bar"),
            "expected unsupported-pair message, got {msg:?}"
        );
        // Also lists the supported set so the user can fix it.
        assert!(
            msg.contains("Start/Pre"),
            "expected supported list in {msg:?}"
        );
        // Almost-supported variants (wrong action under a real event) are
        // still rejected.
        assert!(parse_hook_spec("Start/Resume=cmd").is_err());
        assert!(parse_hook_spec("Power/Pre=cmd").is_err());
    }

    #[test]
    fn parse_hook_spec_rejects_empty_command() {
        let err = parse_hook_spec("Start/Pre=").unwrap_err();
        assert!(
            err.to_string().contains("empty command"),
            "expected empty-command message, got {err:?}"
        );
        // Whitespace-only command is also empty after trim.
        assert!(parse_hook_spec("Start/Pre=   ").is_err());
    }
}
