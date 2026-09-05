use crate::{Error, ManagedApplicationConfig, Result};

impl ManagedApplicationConfig {
    /// Resolve only strings marked as REG_EXPAND_SZ into a separate effective
    /// configuration. Call this in the service, using its effective environment;
    /// never persist the returned copy over the raw configuration.
    ///
    /// `lookup` must implement Windows' case-insensitive environment lookup.
    /// Expansion is single-pass: substituted values are not recursively expanded.
    /// Unknown variables and unmatched percent signs remain literal, like
    /// ExpandEnvironmentStringsW. NULs and oversized results are rejected.
    pub fn resolve_expandable_strings(
        &self,
        mut lookup: impl FnMut(&str) -> Option<String>,
    ) -> Result<Self> {
        let mut effective = self.clone();
        for (name, value) in [
            ("Application", &mut effective.application),
            ("AppParameters", &mut effective.app_parameters),
            ("AppDirectory", &mut effective.app_directory),
            ("AppAffinity", &mut effective.affinity),
        ] {
            if self.is_expandable_string(name) {
                if let Some(text) = value {
                    *text = expand(name, text, &mut lookup)?;
                }
            }
        }
        for (name, stream) in [
            ("AppStdin", &mut effective.io.stdin),
            ("AppStdout", &mut effective.io.stdout),
            ("AppStderr", &mut effective.io.stderr),
        ] {
            if self.is_expandable_string(name) {
                if let Some(stream) = stream {
                    stream.path = expand(name, &stream.path, &mut lookup)?;
                }
            }
        }
        for hook in &mut effective.hooks {
            let key = Self::hook_expansion_key(&hook.event, &hook.action);
            if self.is_expandable_string(&key) {
                hook.command = expand(&key, &hook.command, &mut lookup)?;
            }
        }
        effective.expandable_strings.clear();
        Ok(effective)
    }

    pub fn is_expandable_string(&self, name: &str) -> bool {
        self.expandable_strings
            .iter()
            .any(|marked| marked.eq_ignore_ascii_case(name))
    }

    pub fn hook_expansion_key(event: &str, action: &str) -> String {
        format!("AppEvents\\{event}\\{action}")
    }
}

fn expand(
    field: &str,
    text: &str,
    lookup: &mut impl FnMut(&str) -> Option<String>,
) -> Result<String> {
    let mut out = String::new();
    let mut units = 0;
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        append_expanded(field, &mut out, &mut units, &rest[..start])?;
        let candidate = &rest[start + 1..];
        let Some(end) = candidate.find('%') else {
            append_expanded(field, &mut out, &mut units, &rest[start..])?;
            rest = "";
            break;
        };
        let name = &candidate[..end];
        match (!name.is_empty()).then(|| lookup(name)).flatten() {
            Some(value) => append_expanded(field, &mut out, &mut units, &value)?,
            None => append_expanded(field, &mut out, &mut units, &rest[start..start + end + 2])?,
        }
        rest = &candidate[end + 1..];
    }
    append_expanded(field, &mut out, &mut units, rest)?;
    Ok(out)
}

fn append_expanded(field: &str, out: &mut String, units: &mut usize, value: &str) -> Result<()> {
    if value.contains('\0') {
        return Err(Error::InvalidConfig(format!(
            "{field} expands to a string containing NUL"
        )));
    }
    *units = units.saturating_add(value.encode_utf16().count());
    if *units >= 32_767 {
        return Err(Error::InvalidConfig(format!(
            "{field} exceeds the Windows expanded-string limit"
        )));
    }
    out.push_str(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HookConfig, IoStream};

    #[test]
    fn expansion_uses_only_marked_fields_and_leaves_raw_config_unchanged() {
        let cfg = ManagedApplicationConfig {
            application: Some(r"%Root%\app.exe".into()),
            app_parameters: Some("%ROOT%".into()),
            affinity: Some("%CPU%".into()),
            hooks: vec![HookConfig {
                event: "Start".into(),
                action: "Pre".into(),
                command: "%ROOT%\\hook.exe".into(),
            }],
            expandable_strings: [
                "Application".into(),
                "AppAffinity".into(),
                ManagedApplicationConfig::hook_expansion_key("Start", "Pre"),
            ]
            .into(),
            ..Default::default()
        };
        let effective = cfg
            .resolve_expandable_strings(|name| match name.to_ascii_uppercase().as_str() {
                "ROOT" => Some(r"C:\ServiceProfile".into()),
                "CPU" => Some("3".into()),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            effective.application.as_deref(),
            Some(r"C:\ServiceProfile\app.exe")
        );
        assert_eq!(effective.app_parameters.as_deref(), Some("%ROOT%"));
        assert_eq!(effective.affinity.as_deref(), Some("3"));
        assert_eq!(effective.hooks[0].command, r"C:\ServiceProfile\hook.exe");
        assert!(effective.expandable_strings.is_empty());
        assert_eq!(cfg.application.as_deref(), Some(r"%Root%\app.exe"));
        assert_eq!(cfg.expandable_strings.len(), 3);
    }

    #[test]
    fn expansion_matches_single_pass_windows_percent_rules() {
        let mut lookup = |name: &str| (name == "A").then(|| "%B%".into());
        assert_eq!(
            expand("x", "%A%:%MISSING%:%%:%tail", &mut lookup).unwrap(),
            "%B%:%MISSING%:%%:%tail"
        );
        assert!(expand("x", "%A%", &mut |_| Some("bad\0value".into())).is_err());
        assert!(expand("x", "%A%", &mut |_| Some("x".repeat(32_767))).is_err());
    }

    #[test]
    fn expansion_covers_stdio_and_old_json_has_no_metadata() {
        let mut cfg: ManagedApplicationConfig =
            serde_json::from_str(r#"{"application":"C:\\app.exe"}"#).unwrap();
        assert!(cfg.expandable_strings.is_empty());
        assert!(!serde_json::to_string(&cfg)
            .unwrap()
            .contains("expandable_strings"));
        cfg.io.stdout = Some(IoStream {
            path: "%LOG%\\out.log".into(),
            share_mode: None,
            creation_disposition: None,
            flags_and_attributes: None,
            copy_and_truncate: None,
        });
        cfg.expandable_strings.insert("AppStdout".into());
        let effective = cfg
            .resolve_expandable_strings(|_| Some(r"D:\Logs".into()))
            .unwrap();
        assert_eq!(effective.io.stdout.unwrap().path, r"D:\Logs\out.log");
    }
}
