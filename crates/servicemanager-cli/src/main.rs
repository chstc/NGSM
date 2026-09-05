use std::collections::BTreeMap;
use std::io::{self, BufRead};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use servicemanager_core::{
    ExitAction, LogRotationConfig, ManagementKind, Result, ServiceDefinition, ServiceState,
};
use servicemanager_ops::{EditSpec, InstallSpec, RecoverySpec};
use servicemanager_win32::{
    control_service, enumerate_descendants, query_service, start_service, update_native_config,
    InstallStartType, ServiceControlSignal, ServiceDependencies,
};

mod hooks;
use hooks::parse_hook_spec;

// NGSM is a Windows service manager: it drives the Windows SCM and registry
// and has no meaning on other platforms. The build is intentionally
// Windows-only — fail fast and clearly rather than with unresolved-import
// errors from the Windows-only crates this binary depends on.
#[cfg(not(windows))]
compile_error!("NGSM builds only for Windows targets — it manages Windows services.");

#[derive(Parser, Debug)]
#[command(name = "ngsm", version, about = "Manage Windows services")]
struct Cli {
    /// Emit JSON instead of human-readable output.
    #[arg(long, global = true)]
    json: bool,

    /// When omitted (e.g. double-click from Explorer), the desktop UI
    /// launches. Pass a subcommand to use the CLI instead.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List Windows services and indicate which are NGSM-managed.
    List {
        /// Which services to include.
        #[arg(long, value_enum, default_value_t = ListFilter::Managed)]
        filter: ListFilter,
    },
    /// Dump a full service definition.
    Dump {
        /// Service name.
        name: String,
    },
    /// Show whether a service exists and its high-level state.
    Status {
        /// Service name.
        name: String,
    },
    /// Install a new managed service.
    Install(InstallArgs),
    /// Remove a managed service (and its NSSM-compatible config).
    Remove {
        /// Service name.
        name: String,
        /// Unsupported: SCM deletion removes the whole service registry subtree.
        /// This flag is rejected; export or back up the configuration first.
        #[arg(long)]
        no_purge_config: bool,
        /// Allow removing a service that is NOT NGSM/NSSM-managed. Without
        /// this flag `remove` refuses to delete native Windows services.
        #[arg(long, default_value_t = false)]
        force_native: bool,
    },
    /// Start a service.
    Start {
        /// Service name.
        name: String,
        /// Allow the operation on a service that is NOT NGSM/NSSM-managed.
        #[arg(long, default_value_t = false)]
        force_native: bool,
    },
    /// Stop a service.
    Stop {
        /// Service name.
        name: String,
        /// Allow the operation on a service that is NOT NGSM/NSSM-managed.
        #[arg(long, default_value_t = false)]
        force_native: bool,
    },
    /// Pause a running service (SCM pause control).
    Pause {
        /// Service name.
        name: String,
        /// Allow the operation on a service that is NOT NGSM/NSSM-managed.
        #[arg(long, default_value_t = false)]
        force_native: bool,
    },
    /// Resume a paused service (SCM continue control).
    Continue {
        /// Service name.
        name: String,
        /// Allow the operation on a service that is NOT NGSM/NSSM-managed.
        #[arg(long, default_value_t = false)]
        force_native: bool,
    },
    /// Stop the service, wait for it to reach the Stopped state, then start
    /// it again.
    Restart {
        /// Service name.
        name: String,
        /// How long to wait for the stop step in milliseconds.
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u32,
        /// Allow the operation on a service that is NOT NGSM/NSSM-managed.
        #[arg(long, default_value_t = false)]
        force_native: bool,
    },
    /// Read a single NSSM-compatible parameter value.
    Get {
        /// Service name.
        name: String,
        /// NSSM value name, e.g. `AppParameters`.
        param: String,
    },
    /// Write a single NSSM-compatible parameter value.
    Set {
        /// Service name.
        name: String,
        /// NSSM value name, e.g. `AppParameters`.
        param: String,
        /// New value (for multi-string params, separate entries with `,`).
        ///
        /// Values starting with `-` are accepted without needing `--`.
        #[arg(allow_hyphen_values = true)]
        value: String,
    },
    /// Delete a single NSSM-compatible parameter value.
    Unset {
        /// Service name.
        name: String,
        /// NSSM value name to delete.
        param: String,
    },
    /// Reset a single NSSM-compatible parameter value to its default.
    Reset {
        /// Service name.
        name: String,
        /// NSSM value name to reset.
        param: String,
    },
    /// Print the service state and exit with the raw SCM state code.
    #[command(name = "statuscode")]
    StatusCode {
        /// Service name.
        name: String,
    },
    /// Edit an installed service. Only the supplied fields are changed.
    Edit(EditArgs),
    /// Repair a managed service's NGSM runner ImagePath and service type.
    Repair {
        /// Service name.
        name: String,
    },
    /// Force the supervisor to rotate the service's logs now. Requires the
    /// service to be running.
    Rotate {
        /// Service name.
        name: String,
    },
    /// Show or update the recovery (restart) policy for a managed service.
    Recovery(RecoveryArgs),
    /// List every process belonging to a running service (the runner plus
    /// every descendant the Toolhelp32 walk can find).
    Processes {
        /// Service name.
        name: String,
    },
    /// Internal: run this binary as the named service. Invoked by SCM.
    #[command(name = "run-service", hide = true)]
    RunService {
        /// Service name (matches the registry key).
        name: String,
    },
    /// Internal: run as the elevated broker for headless automation.
    /// Only compiled when this binary is built with `--features broker`.
    #[cfg(feature = "broker")]
    #[command(name = "broker", hide = true)]
    Broker {
        /// Owner user's SID (as a string, e.g. `S-1-5-21-...`).
        #[arg(long)]
        owner_sid: String,
        /// Public, CSPRNG-generated nonce that names the per-launch pipe. The
        /// launcher must give the same value to any client. It is not a
        /// secret, so unlike the token it is a normal argument.
        #[arg(long)]
        pipe_nonce: String,
        /// Exit after this many seconds with no client activity.
        #[arg(long, default_value_t = 300)]
        idle_timeout_secs: u64,
        // The per-launch capability token is read from stdin, never a
        // command-line argument — argv is observable by other same-user
        // processes, stdin (an inherited handle) is not.
    },
    /// Launch the desktop UI.
    Gui,
}

#[derive(Args, Debug)]
struct EditArgs {
    /// Service name.
    name: String,
    /// Replace the managed application path.
    #[arg(long)]
    application: Option<String>,
    /// Replace AppParameters.
    #[arg(long)]
    app_parameters: Option<String>,
    /// Replace AppDirectory.
    #[arg(long)]
    app_directory: Option<String>,
    /// Replace the SCM display name.
    #[arg(long)]
    display: Option<String>,
    /// Replace the SCM description. Pass an empty string to clear it.
    #[arg(long)]
    description: Option<String>,
    /// Replace the SCM start type.
    #[arg(long, value_enum)]
    start: Option<StartTypeArg>,
    /// Replace SCM service dependencies with the supplied service name. May be repeated.
    #[arg(long = "depend-service")]
    depend_service: Vec<String>,
    /// Replace SCM service dependencies with the supplied load-order group. May be repeated.
    #[arg(long = "depend-group")]
    depend_group: Vec<String>,
    /// Clear all SCM dependencies.
    #[arg(
        long = "clear-dependencies",
        conflicts_with_all = ["depend_service", "depend_group"]
    )]
    clear_dependencies: bool,
    /// Replace the SCM service account.
    #[arg(long)]
    account: Option<String>,
    /// Read the service account password from one stdin line.
    #[arg(long)]
    password_stdin: bool,
    /// Replace the stdout log path.
    #[arg(long)]
    stdout: Option<String>,
    /// Replace the stderr log path.
    #[arg(long)]
    stderr: Option<String>,
    /// Allow changing native SCM fields (`--display`, `--start`) on a service
    /// that is NOT NGSM-managed. Without this flag `edit` refuses native-only
    /// changes to native Windows services.
    #[arg(long, default_value_t = false)]
    force_native: bool,
}

#[derive(Args, Debug)]
struct InstallArgs {
    /// Service name (the registry key under `CurrentControlSet\Services`).
    name: String,
    /// Path to the executable to run as the service.
    application: String,
    /// Arguments to pass to the application as a single quoted string.
    #[arg(long)]
    app_parameters: Option<String>,
    /// Working directory for the application.
    #[arg(long)]
    app_directory: Option<String>,
    /// Display name shown in services.msc.
    #[arg(long)]
    display: Option<String>,
    /// Description shown in services.msc.
    #[arg(long)]
    description: Option<String>,
    /// SCM start type.
    #[arg(long, value_enum, default_value_t = StartTypeArg::Manual)]
    start: StartTypeArg,
    /// Add a service dependency by service name. May be repeated.
    #[arg(long = "depend-service")]
    depend_service: Vec<String>,
    /// Add a load-order group dependency. May be repeated.
    #[arg(long = "depend-group")]
    depend_group: Vec<String>,
    /// SCM service account.
    #[arg(long)]
    account: Option<String>,
    /// Read the service account password from one stdin line.
    #[arg(long)]
    password_stdin: bool,
    /// File path to receive the child's stdout.
    #[arg(long)]
    stdout: Option<String>,
    /// File path to receive the child's stderr.
    #[arg(long)]
    stderr: Option<String>,
    /// Rotate the log files when they exceed this byte threshold (also
    /// enables rotation).
    #[arg(long)]
    rotate_bytes: Option<u64>,
    /// Rotate the log files when they are older than this many seconds
    /// (also enables rotation).
    #[arg(long)]
    rotate_seconds: Option<u32>,
    /// Rotation mode. `offline` (default) only rotates on each spawn;
    /// `online` lets the supervisor rotate mid-flight.
    #[arg(long, value_enum, default_value_t = RotateOnlineArg::Offline)]
    rotate_online: RotateOnlineArg,
    /// Add a lifecycle hook. Use `EVENT/ACTION=command`, e.g.
    /// `--hook Start/Pre="C:\\scripts\\warmup.cmd"`. May be repeated.
    #[arg(long)]
    hook: Vec<String>,
}

#[derive(Args, Debug)]
struct RecoveryArgs {
    /// Service name.
    name: String,

    /// Show the current policy as JSON instead of human-readable text.
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    action: Option<RecoveryAction>,
}

#[derive(Subcommand, Debug)]
enum RecoveryAction {
    /// Update the recovery policy for the service.
    Set(RecoverySetArgs),
}

#[derive(Args, Debug)]
struct RecoverySetArgs {
    /// Default action when a process exit code has no explicit mapping.
    /// Optional: when omitted, the existing default_action on the service is
    /// preserved so other fields (delays, exit_actions) can be updated alone.
    #[arg(long, value_enum)]
    default_action: Option<ExitActionArg>,

    /// Milliseconds to delay before restarting the service.
    #[arg(long)]
    restart_delay_ms: Option<u32>,

    /// Clear any restart delay (set to None).
    #[arg(long, conflicts_with = "restart_delay_ms")]
    no_restart_delay: bool,

    /// Milliseconds of throttle delay between restarts when the service
    /// is cycling too quickly.
    #[arg(long)]
    throttle_delay_ms: Option<u32>,

    /// Clear any throttle delay (set to None).
    #[arg(long, conflicts_with = "throttle_delay_ms")]
    no_throttle_delay: bool,

    /// Per-exit-code action. Format: `<code>=<action>`, e.g. `0=ignore`.
    /// May be repeated.
    #[arg(long = "exit-action", allow_hyphen_values = true)]
    exit_actions: Vec<String>,

    /// Drop all existing per-exit-code entries before applying
    /// `--exit-action` entries (replaces rather than merging).
    #[arg(long)]
    clear_exit_actions: bool,
}

/// CLI-visible exit action names; maps onto [`ExitAction`].
#[derive(Copy, Clone, Debug, ValueEnum)]
enum ExitActionArg {
    Restart,
    Ignore,
    Exit,
    Suicide,
}

impl From<ExitActionArg> for ExitAction {
    fn from(a: ExitActionArg) -> Self {
        match a {
            ExitActionArg::Restart => ExitAction::Restart,
            ExitActionArg::Ignore => ExitAction::Ignore,
            ExitActionArg::Exit => ExitAction::Exit,
            ExitActionArg::Suicide => ExitAction::Suicide,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum StartTypeArg {
    Manual,
    Automatic,
    Disabled,
}

#[derive(Copy, Clone, Debug, ValueEnum, PartialEq, Eq)]
enum RotateOnlineArg {
    Offline,
    Online,
    OnlineAsap,
}

impl RotateOnlineArg {
    fn as_nssm_value(self) -> u32 {
        match self {
            RotateOnlineArg::Offline => 0,
            RotateOnlineArg::Online => 1,
            RotateOnlineArg::OnlineAsap => 2,
        }
    }
}

impl From<StartTypeArg> for InstallStartType {
    fn from(value: StartTypeArg) -> Self {
        match value {
            StartTypeArg::Manual => InstallStartType::Manual,
            StartTypeArg::Automatic => InstallStartType::Automatic,
            StartTypeArg::Disabled => InstallStartType::Disabled,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ListFilter {
    /// Only services we recognize as NGSM/NSSM-managed.
    Managed,
    /// Native and managed.
    All,
}

fn main() -> ExitCode {
    // If we were launched standalone (no parent shell — typically a
    // double-click from Explorer), hide the auto-allocated console window
    // immediately so the user sees only our GUI. CLI usage from a terminal
    // shares its console with us and is unaffected.
    detach_console_if_standalone();

    // Bare double-click (or any invocation with no subcommand) → GUI.
    if std::env::args().len() == 1 {
        return match servicemanager_gui::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("gui: {e}");
                ExitCode::FAILURE
            }
        };
    }

    let cli = Cli::parse();
    if let Some(Command::StatusCode { name }) = &cli.command {
        return cmd_statuscode_exit(name, cli.json);
    }
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if cli.json {
                let payload = serde_json::json!({ "error": e.to_string() });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).unwrap_or_default()
                );
            } else {
                eprintln!("error: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

/// If our process is the *only* one attached to our console, we created
/// it ourselves — meaning we were launched standalone (a double-click,
/// not from a terminal). Hide it before the OS gets a chance to render
/// it, otherwise the user sees an unwanted flash of black before the GUI.
#[cfg(windows)]
fn detach_console_if_standalone() {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetConsoleProcessList(lpdwProcessList: *mut u32, dwProcessCount: u32) -> u32;
        fn FreeConsole() -> i32;
    }
    let mut buf = [0u32; 2];
    // SAFETY: `buf` has room for `buf.len()` process ids; `GetConsoleProcessList`
    // writes at most that many and returns the real count.
    let count = unsafe { GetConsoleProcessList(buf.as_mut_ptr(), buf.len() as u32) };
    // count == 1 means we own the console alone (Explorer-launch);
    // count > 1 means we share it with a parent shell.
    if count == 1 {
        // SAFETY: `FreeConsole` takes no arguments and only detaches this
        // process from its console; it is sound to call unconditionally.
        unsafe {
            let _ = FreeConsole();
        }
    }
}

#[cfg(not(windows))]
fn detach_console_if_standalone() {}

fn run(cli: &Cli) -> Result<()> {
    let Some(command) = cli.command.as_ref() else {
        // Subcommand omitted but other args were present (e.g. `--json`).
        // Same as a bare invocation: launch the GUI.
        return servicemanager_gui::run()
            .map_err(|e| servicemanager_core::Error::other(format!("gui: {e}")));
    };
    match command {
        Command::List { filter } => cmd_list(*filter, cli.json),
        Command::Dump { name } => cmd_dump(name, cli.json),
        Command::Status { name } => cmd_status(name, cli.json),
        Command::Install(args) => cmd_install(args, cli.json),
        Command::Remove {
            name,
            no_purge_config,
            force_native,
        } => cmd_remove(name, !no_purge_config, *force_native, cli.json),
        Command::Start { name, force_native } => {
            cmd_control(name, ServiceAction::Start, *force_native, cli.json)
        }
        Command::Stop { name, force_native } => {
            cmd_control(name, ServiceAction::Stop, *force_native, cli.json)
        }
        Command::Pause { name, force_native } => {
            cmd_control(name, ServiceAction::Pause, *force_native, cli.json)
        }
        Command::Continue { name, force_native } => {
            cmd_control(name, ServiceAction::Continue, *force_native, cli.json)
        }
        Command::Restart {
            name,
            timeout_ms,
            force_native,
        } => cmd_restart(name, *timeout_ms, *force_native, cli.json),
        Command::Get { name, param } => cmd_get(name, param, cli.json),
        Command::Set { name, param, value } => cmd_set(name, param, value, cli.json),
        Command::Unset { name, param } => cmd_unset(name, param, cli.json),
        Command::Reset { name, param } => cmd_reset(name, param, cli.json),
        Command::StatusCode { name } => {
            let _ = cmd_statuscode_exit(name, cli.json);
            Ok(())
        }
        Command::Edit(args) => cmd_edit(args, cli.json),
        Command::Repair { name } => cmd_repair(name, cli.json),
        Command::Rotate { name } => cmd_rotate(name, cli.json),
        Command::Recovery(args) => cmd_recovery(args, cli.json),
        Command::Processes { name } => cmd_processes(name, cli.json),
        Command::RunService { name } => servicemanager_runner::run(name),
        #[cfg(feature = "broker")]
        Command::Broker {
            owner_sid,
            pipe_nonce,
            idle_timeout_secs,
        } => {
            // Read the capability token from stdin (an inherited handle), so
            // it never appears in this process's command line.
            let mut token = String::new();
            std::io::stdin().read_line(&mut token).map_err(|e| {
                servicemanager_core::Error::other(format!("reading broker token from stdin: {e}"))
            })?;
            servicemanager_broker::run_server(
                owner_sid,
                pipe_nonce,
                *idle_timeout_secs,
                token.trim(),
            )
        }
        Command::Gui => servicemanager_gui::run()
            .map_err(|e| servicemanager_core::Error::other(format!("gui: {e}"))),
    }
}

enum ServiceAction {
    Start,
    Stop,
    Pause,
    Continue,
}

fn cmd_list(filter: ListFilter, json: bool) -> Result<()> {
    let (all_defs, warnings) = servicemanager_ops::list_services()?;

    // Apply the CLI's filter on top of the full list returned by ops.
    let definitions: Vec<ServiceDefinition> = all_defs
        .into_iter()
        .filter(|d| match filter {
            ListFilter::Managed => d.is_managed(),
            ListFilter::All => true,
        })
        .collect();

    // Surface unreadable managed config on stderr; the affected services are
    // still listed rather than silently misreported as native.
    for w in &warnings {
        eprintln!("warning: {w}");
    }

    if json {
        #[derive(Serialize)]
        struct ListView<'a> {
            services: &'a [ServiceDefinition],
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&ListView {
                services: &definitions
            })
            .map_err(|e| { servicemanager_core::Error::other(format!("serialize: {e}")) })?
        );
    } else {
        println!("{:<32} {:<10} {:<10} DISPLAY NAME", "NAME", "KIND", "STATE");
        for d in &definitions {
            let state = d
                .runtime
                .as_ref()
                .map(|r| format!("{:?}", r.state))
                .unwrap_or_else(|| "-".into());
            let kind = match d.management_kind() {
                ManagementKind::Managed => "managed",
                ManagementKind::Native => "native",
            };
            println!(
                "{:<32} {:<10} {:<10} {}",
                truncate(&d.native.name, 32),
                kind,
                truncate(&state, 10),
                d.native.display_name
            );
        }
    }
    Ok(())
}

fn cmd_dump(name: &str, json: bool) -> Result<()> {
    let native = query_service(name)?;
    let managed = servicemanager_registry::read_managed_config(name)?;
    let def = ServiceDefinition {
        native: native.config,
        managed,
        runtime: native.runtime,
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&def)
                .map_err(|e| servicemanager_core::Error::other(format!("serialize: {e}")))?
        );
    } else {
        print_human(&def);
    }
    Ok(())
}

fn cmd_status(name: &str, json: bool) -> Result<()> {
    let native = query_service(name)?;
    let runtime = native.runtime.as_ref();
    if json {
        let payload = serde_json::json!({
            "name": native.config.name,
            "state": runtime.map(|r| format!("{:?}", r.state)),
            "pid": runtime.and_then(|r| r.pid),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    } else {
        match runtime {
            Some(r) => println!("{}: {:?} (pid={:?})", native.config.name, r.state, r.pid),
            None => println!("{}: unknown", native.config.name),
        }
    }
    Ok(())
}

/// True when the user passed any `--rotate-*` flag — i.e. asked install to
/// configure log rotation. Centralised so the cmd_install dispatch, the
/// extended path, and the validator below agree on what "rotation requested"
/// means.
fn install_args_have_rotation(args: &InstallArgs) -> bool {
    args.rotate_bytes.is_some()
        || args.rotate_seconds.is_some()
        || args.rotate_online != RotateOnlineArg::Offline
}

/// Reject install configurations that ask for log rotation without a log
/// stream to rotate.
///
/// `ManagedApplicationConfig::has_online_rotation` (and the
/// supervisor's rotate request path) require at least one redirected
/// stdout/stderr stream; without one, the rotation config is inert and a
/// later `ngsm rotate` is silently refused. Catching this at the CLI
/// boundary surfaces the misconfiguration immediately, instead of
/// installing a service whose rotation flags do nothing.
pub(crate) fn validate_install_args(args: &InstallArgs) -> Result<()> {
    if install_args_have_rotation(args) && args.stdout.is_none() && args.stderr.is_none() {
        return Err(servicemanager_core::Error::InvalidConfig(
            "rotation flags (--rotate-bytes, --rotate-seconds, --rotate-online) \
             require --stdout and/or --stderr; rotation cannot operate without \
             a redirected log stream"
                .into(),
        ));
    }
    dependencies_from_cli(&args.depend_service, &args.depend_group)?;
    validate_password_stdin_usage(args.account.as_deref(), args.password_stdin)?;
    Ok(())
}

fn dependencies_from_cli(services: &[String], groups: &[String]) -> Result<ServiceDependencies> {
    let dependencies = ServiceDependencies {
        services: services.to_vec(),
        groups: groups.to_vec(),
    };
    dependencies.validate()?;
    Ok(dependencies)
}

fn edit_dependencies_from_cli(args: &EditArgs) -> Result<Option<ServiceDependencies>> {
    if args.clear_dependencies {
        return Ok(Some(ServiceDependencies::default()));
    }
    if args.depend_service.is_empty() && args.depend_group.is_empty() {
        return Ok(None);
    }
    Ok(Some(dependencies_from_cli(
        &args.depend_service,
        &args.depend_group,
    )?))
}

fn validate_password_stdin_usage(account: Option<&str>, password_stdin: bool) -> Result<()> {
    if password_stdin && account.is_none() {
        return Err(servicemanager_core::Error::InvalidConfig(
            "--password-stdin requires --account".into(),
        ));
    }
    Ok(())
}

fn read_password_stdin_line() -> Result<String> {
    let mut line = String::new();
    let bytes = io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| servicemanager_core::Error::other(format!("read password from stdin: {e}")))?;
    if bytes == 0 {
        return Err(servicemanager_core::Error::InvalidConfig(
            "--password-stdin was specified but stdin did not provide a line".into(),
        ));
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    if line.contains('\0') {
        return Err(servicemanager_core::Error::InvalidConfig(
            "password read from stdin contains an embedded NUL".into(),
        ));
    }
    Ok(line)
}

fn cmd_install(args: &InstallArgs, json: bool) -> Result<()> {
    // Reject rotation flags without a redirected log stream before any
    // SCM / registry side effect.
    validate_install_args(args)?;
    let dependencies = dependencies_from_cli(&args.depend_service, &args.depend_group)?;

    let rotation = if install_args_have_rotation(args) {
        LogRotationConfig {
            enabled: Some(true),
            online: Some(args.rotate_online.as_nssm_value()),
            seconds: args.rotate_seconds,
            bytes: args.rotate_bytes,
            delay_ms: None,
        }
    } else {
        LogRotationConfig::default()
    };
    let hooks = args
        .hook
        .iter()
        .map(|raw| parse_hook_spec(raw))
        .collect::<Result<Vec<_>>>()?;
    let password = if args.password_stdin {
        Some(read_password_stdin_line()?)
    } else {
        None
    };

    let spec = InstallSpec {
        name: args.name.clone(),
        display_name: args.display.clone(),
        description: args.description.clone(),
        application: args.application.clone(),
        app_parameters: args.app_parameters.clone(),
        app_directory: args.app_directory.clone(),
        stdout: args.stdout.clone(),
        stderr: args.stderr.clone(),
        rotation,
        hooks,
        start_type: args.start.into(),
        dependencies,
        account: args.account.clone(),
        password,
    };

    let msg = servicemanager_ops::install(spec)?;
    if json {
        println!("{}", serde_json::json!({ "installed": args.name }));
    } else {
        println!("{msg}");
    }
    Ok(())
}

fn cmd_remove(name: &str, purge_config: bool, force_native: bool, json: bool) -> Result<()> {
    let msg = servicemanager_ops::remove(name, force_native, purge_config)?;
    if json {
        println!("{}", serde_json::json!({ "removed": name }));
    } else {
        println!("{msg}");
    }
    Ok(())
}

fn cmd_control(name: &str, action: ServiceAction, force_native: bool, json: bool) -> Result<()> {
    if force_native {
        // Bypass the NGSM-managed check — call win32 directly.
        match action {
            ServiceAction::Start => {
                start_service(name)?;
                if json {
                    println!("{}", serde_json::json!({ "started": name }));
                } else {
                    println!("Start requested for '{name}'.");
                }
            }
            ServiceAction::Stop => {
                let state = control_service(name, ServiceControlSignal::Stop)?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "stopped": name, "state": format!("{:?}", state.state) })
                    );
                } else {
                    println!("Stop requested for '{name}' (state: {:?}).", state.state);
                }
            }
            ServiceAction::Pause => {
                let state = control_service(name, ServiceControlSignal::Pause)?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "paused": name, "state": format!("{:?}", state.state) })
                    );
                } else {
                    println!("Pause requested for '{name}' (state: {:?}).", state.state);
                }
            }
            ServiceAction::Continue => {
                let state = control_service(name, ServiceControlSignal::Continue)?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "continued": name, "state": format!("{:?}", state.state) })
                    );
                } else {
                    println!(
                        "Continue requested for '{name}' (state: {:?}).",
                        state.state
                    );
                }
            }
        }
        return Ok(());
    }

    // Delegate to ops — enforces NGSM-managed check internally.
    let (msg, json_key) = match action {
        ServiceAction::Start => (servicemanager_ops::start(name), "started"),
        ServiceAction::Stop => (servicemanager_ops::stop(name), "stopped"),
        ServiceAction::Pause => (servicemanager_ops::pause(name), "paused"),
        ServiceAction::Continue => (servicemanager_ops::continue_service(name), "continued"),
    };
    let msg = msg?;

    if json {
        println!("{}", serde_json::json!({ json_key: name }));
    } else {
        println!("{msg}");
    }
    Ok(())
}

fn cmd_restart(name: &str, timeout_ms: u32, force_native: bool, json: bool) -> Result<()> {
    let msg = servicemanager_ops::restart_with_options(name, timeout_ms as u64, force_native)?;
    if json {
        println!("{}", serde_json::json!({ "restarted": name }));
    } else {
        println!("{msg}");
    }
    Ok(())
}

fn cmd_get(name: &str, param: &str, json: bool) -> Result<()> {
    let record = servicemanager_registry::get_value(name, param)?;
    if json {
        let payload = match &record {
            Some(r) => serde_json::json!({
                "service": name,
                "param": param,
                "kind": format!("{:?}", r.kind),
                "value": r.value,
            }),
            None => serde_json::json!({
                "service": name,
                "param": param,
                "value": null,
            }),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        );
    } else {
        match record {
            Some(r) => println!("{}", r.value),
            None => println!("(unset)"),
        }
    }
    Ok(())
}

fn cmd_set(name: &str, param: &str, value: &str, json: bool) -> Result<()> {
    servicemanager_registry::set_value(name, param, value)?;
    if json {
        println!(
            "{}",
            serde_json::json!({ "service": name, "param": param, "value": value })
        );
    } else {
        println!("Set {param} for '{name}'.");
    }
    Ok(())
}

fn cmd_unset(name: &str, param: &str, json: bool) -> Result<()> {
    servicemanager_registry::unset_value(name, param)?;
    if json {
        println!("{}", serde_json::json!({ "service": name, "unset": param }));
    } else {
        println!("Unset {param} on '{name}'.");
    }
    Ok(())
}

fn cmd_reset(name: &str, param: &str, json: bool) -> Result<()> {
    servicemanager_registry::unset_value(name, param)?;
    if json {
        println!("{}", serde_json::json!({ "service": name, "reset": param }));
    } else {
        println!("Reset {param} on '{name}'.");
    }
    Ok(())
}

fn cmd_statuscode_exit(name: &str, json: bool) -> ExitCode {
    match query_service(name) {
        Ok(native) => {
            let state = native
                .runtime
                .as_ref()
                .map(|r| r.state)
                .unwrap_or(ServiceState::Unknown);
            let code = statuscode_exit_code(state);
            let text = statuscode_state_text(state);
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "service": name,
                        "state": text,
                        "code": code,
                    })
                );
            } else {
                println!("{text}");
            }
            ExitCode::from(code)
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "service": name,
                        "state": "SERVICE_UNKNOWN",
                        "code": 0,
                        "error": e.to_string(),
                    })
                );
            } else {
                eprintln!("error: {e}");
            }
            ExitCode::from(0)
        }
    }
}

fn statuscode_exit_code(state: ServiceState) -> u8 {
    match state {
        ServiceState::Stopped => 1,
        ServiceState::StartPending => 2,
        ServiceState::StopPending => 3,
        ServiceState::Running => 4,
        ServiceState::ContinuePending => 5,
        ServiceState::PausePending => 6,
        ServiceState::Paused => 7,
        ServiceState::Unknown => 0,
    }
}

fn statuscode_state_text(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Stopped => "SERVICE_STOPPED",
        ServiceState::StartPending => "SERVICE_START_PENDING",
        ServiceState::StopPending => "SERVICE_STOP_PENDING",
        ServiceState::Running => "SERVICE_RUNNING",
        ServiceState::ContinuePending => "SERVICE_CONTINUE_PENDING",
        ServiceState::PausePending => "SERVICE_PAUSE_PENDING",
        ServiceState::Paused => "SERVICE_PAUSED",
        ServiceState::Unknown => "SERVICE_UNKNOWN",
    }
}

/// Reject `ngsm edit <name>` invocations that supply no editable fields.
///
/// `EditArgs` is parseable with only the service name — but then `ops::edit`
/// reads the config, has nothing to change, and the CLI prints
/// `Edited '<name>'.` That is indistinguishable from a real edit and misleads
/// operators in scripts.
///
/// `force_native` is intentionally excluded: on its own it changes nothing
/// (it only relaxes a guard on the other flags).
fn validate_edit_args(args: &EditArgs) -> Result<()> {
    let nothing_to_change = args.application.is_none()
        && args.app_parameters.is_none()
        && args.app_directory.is_none()
        && args.display.is_none()
        && args.description.is_none()
        && args.start.is_none()
        && args.depend_service.is_empty()
        && args.depend_group.is_empty()
        && !args.clear_dependencies
        && args.account.is_none()
        && !args.password_stdin
        && args.stdout.is_none()
        && args.stderr.is_none();
    if nothing_to_change {
        return Err(servicemanager_core::Error::InvalidConfig(
            "no edit fields specified; try `ngsm edit --help` to see editable fields".into(),
        ));
    }
    edit_dependencies_from_cli(args)?;
    validate_password_stdin_usage(args.account.as_deref(), args.password_stdin)?;
    Ok(())
}

fn cmd_edit(args: &EditArgs, json: bool) -> Result<()> {
    // A bare `ngsm edit <service>` with no field flags would otherwise
    // succeed silently and print "Edited '<name>'." — surface that the
    // operator gave us nothing to do instead of pretending we changed
    // something.
    validate_edit_args(args)?;

    let dependencies = edit_dependencies_from_cli(args)?;
    let want_native = args.display.is_some()
        || args.description.is_some()
        || args.start.is_some()
        || dependencies.is_some()
        || args.account.is_some()
        || args.password_stdin;

    // Refuse to mix --force-native (which targets only native SCM metadata)
    // with managed-field flags. The operator's intent is ambiguous: a partial
    // success that updates only the native fields would silently swallow the
    // managed-field changes.
    if args.force_native {
        let any_managed = args.application.is_some()
            || args.app_parameters.is_some()
            || args.app_directory.is_some()
            || args.stdout.is_some()
            || args.stderr.is_some();
        if any_managed {
            return Err(servicemanager_core::Error::other(
                "--force-native cannot be combined with managed-field flags \
                 (--application, --app-parameters, --app-directory, --stdout, --stderr). \
                 Run two separate `ngsm edit` invocations — one with --force-native for \
                 native-only fields, and one without it for managed fields."
                    .to_string(),
            ));
        }
    }

    // When --force-native is set and only native SCM fields are being changed,
    // ops::edit is not usable (it always enforces NGSM-managed ownership).
    // Fall through to the direct SCM call for that narrow case.
    if args.force_native && want_native {
        let password = if args.password_stdin {
            Some(read_password_stdin_line()?)
        } else {
            None
        };
        update_native_config(
            &args.name,
            args.display.as_deref(),
            args.description.as_deref(),
            args.start.map(Into::into),
            dependencies.as_ref(),
            args.account.as_deref(),
            password.as_deref(),
        )?;
        if json {
            println!("{}", serde_json::json!({ "edited": args.name }));
        } else {
            println!("Edited '{}'.", args.name);
        }
        return Ok(());
    }

    // Delegate to ops — enforces NGSM-managed ownership internally.
    let password = if args.password_stdin {
        Some(read_password_stdin_line()?)
    } else {
        None
    };
    let spec = EditSpec {
        name: args.name.clone(),
        display_name: args.display.clone(),
        description: args.description.clone(),
        application: args.application.clone(),
        app_parameters: args.app_parameters.clone(),
        app_directory: args.app_directory.clone(),
        stdout: args.stdout.clone(),
        stderr: args.stderr.clone(),
        start_type: args.start.map(Into::into),
        dependencies,
        account: args.account.clone(),
        password,
    };
    let msg = servicemanager_ops::edit(spec)?;
    if json {
        println!("{}", serde_json::json!({ "edited": args.name }));
    } else {
        println!("{msg}");
    }
    Ok(())
}

fn cmd_repair(name: &str, json: bool) -> Result<()> {
    let msg = servicemanager_ops::repair_runner(name)?;
    if json {
        println!(
            "{}",
            serde_json::json!({ "repaired": name, "runner": true })
        );
    } else {
        println!("{msg}");
    }
    Ok(())
}

fn cmd_rotate(name: &str, json: bool) -> Result<()> {
    let msg = servicemanager_ops::rotate(name)?;
    if json {
        let state = query_service(name)
            .ok()
            .and_then(|s| s.runtime.map(|r| format!("{:?}", r.state)));
        println!(
            "{}",
            serde_json::json!({
                "rotated": name,
                "state": state,
            })
        );
    } else {
        println!("{msg}");
    }
    Ok(())
}

fn cmd_recovery(args: &RecoveryArgs, global_json: bool) -> Result<()> {
    // --json on the subcommand args takes precedence; global --json also works.
    let json = args.json || global_json;
    match &args.action {
        None => cmd_recovery_show(&args.name, json),
        Some(RecoveryAction::Set(set_args)) => cmd_recovery_set(&args.name, set_args, json),
    }
}

fn cmd_recovery_show(name: &str, json: bool) -> Result<()> {
    let spec = servicemanager_ops::read_recovery(name)?;
    if json {
        let exit_map: BTreeMap<&str, String> = spec
            .exit_actions
            .iter()
            .map(|(code, action)| (code.as_str(), format!("{:?}", action).to_ascii_lowercase()))
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "service": spec.name,
                "restart_delay_ms": spec.restart_delay_ms,
                "throttle_delay_ms": spec.throttle_delay_ms,
                "default_action": format!("{:?}", spec.default_action).to_ascii_lowercase(),
                "exit_actions": exit_map,
            }))
            .map_err(|e| servicemanager_core::Error::other(format!("serialize: {e}")))?
        );
    } else {
        println!("Recovery policy for '{}':", spec.name);
        match spec.restart_delay_ms {
            Some(ms) => println!("  Restart delay: {ms}ms"),
            None => println!("  Restart delay: (none)"),
        }
        match spec.throttle_delay_ms {
            Some(ms) => println!("  Throttle delay: {ms}ms"),
            None => println!("  Throttle delay: (none)"),
        }
        println!("  Default action: {:?}", spec.default_action);
        if spec.exit_actions.is_empty() {
            println!("  Per-exit-code: (none)");
        } else {
            println!("  Per-exit-code:");
            for (code, action) in &spec.exit_actions {
                println!("    AppExit\\{code} -> {action:?}");
            }
        }
    }
    Ok(())
}

fn cmd_recovery_set(name: &str, args: &RecoverySetArgs, json: bool) -> Result<()> {
    let msg = servicemanager_ops::update_recovery(name, |current| {
        merge_recovery_args(name, current, args)
    })?;
    if json {
        println!("{}", serde_json::json!({ "saved": name }));
    } else {
        println!("{msg}");
    }
    Ok(())
}

/// Merge a `RecoverySetArgs` payload onto the currently-persisted recovery
/// spec for `name`, returning the spec that should be written back.
///
/// Every field on `RecoverySetArgs` is optional — when a CLI flag is absent,
/// the matching field on `current` is preserved. This lets users update one
/// knob at a time (e.g. `recovery set foo --restart-delay-ms 5000`) without
/// restating the others.
///
/// Extracted as a free function so it can be unit-tested without touching the
/// registry (which `read_recovery`/`save_recovery` would require).
fn merge_recovery_args(
    name: &str,
    current: &RecoverySpec,
    args: &RecoverySetArgs,
) -> Result<RecoverySpec> {
    let restart_delay_ms = if args.no_restart_delay {
        None
    } else {
        args.restart_delay_ms.or(current.restart_delay_ms)
    };

    let throttle_delay_ms = if args.no_throttle_delay {
        None
    } else {
        args.throttle_delay_ms.or(current.throttle_delay_ms)
    };

    let mut exit_actions: BTreeMap<String, ExitAction> = if args.clear_exit_actions {
        BTreeMap::new()
    } else {
        current.exit_actions.clone()
    };

    // Parse and apply --exit-action CODE=ACTION entries.
    for raw in &args.exit_actions {
        let (code_str, action_str) = raw.split_once('=').ok_or_else(|| {
            servicemanager_core::Error::InvalidConfig(format!(
                "exit-action '{raw}' must be CODE=ACTION (e.g. 0=ignore)"
            ))
        })?;
        let action = parse_exit_action(action_str).map_err(|e| {
            servicemanager_core::Error::InvalidConfig(format!("exit-action '{raw}': {e}"))
        })?;
        let code = code_str.trim().to_string();
        // Reject keys the supervisor would never match (non-numeric, the
        // reserved "default", embedded whitespace/NUL, ...) up front, so
        // a bad value cannot be silently persisted in the registry.
        servicemanager_ops::validate_exit_action_key(&code).map_err(|e| {
            servicemanager_core::Error::InvalidConfig(format!("exit-action '{raw}': {e}"))
        })?;
        exit_actions.insert(code, action);
    }

    // default_action is optional on the CLI — preserve the existing value
    // when the flag is absent so partial updates do not force the operator
    // to restate it.
    let default_action = match args.default_action {
        Some(arg) => arg.into(),
        None => current.default_action,
    };

    Ok(RecoverySpec {
        name: name.to_string(),
        restart_delay_ms,
        throttle_delay_ms,
        default_action,
        exit_actions,
    })
}

/// Parse an exit-action string (case-insensitive).
fn parse_exit_action(s: &str) -> std::result::Result<ExitAction, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "restart" => Ok(ExitAction::Restart),
        "ignore" => Ok(ExitAction::Ignore),
        "exit" => Ok(ExitAction::Exit),
        "suicide" => Ok(ExitAction::Suicide),
        other => Err(format!(
            "unknown action '{other}'; expected restart, ignore, exit, or suicide"
        )),
    }
}

fn cmd_processes(name: &str, json: bool) -> Result<()> {
    let snapshot = query_service(name)?;
    let pid = snapshot
        .runtime
        .as_ref()
        .and_then(|r| r.pid)
        .ok_or_else(|| {
            servicemanager_core::Error::other(format!(
                "service '{name}' is not running (no PID reported)"
            ))
        })?;
    let descendants = enumerate_descendants(pid)?;
    if json {
        println!(
            "{}",
            serde_json::json!({ "service": name, "root_pid": pid, "processes": descendants })
        );
    } else {
        println!("{:<8} {:<8} IMAGE", "PID", "PPID");
        for p in &descendants {
            println!("{:<8} {:<8} {}", p.pid, p.parent_pid, p.image_name);
        }
        if descendants.len() == 1 {
            println!("(only the runner is visible — child has not been spawned yet)");
        }
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn print_human(def: &ServiceDefinition) {
    println!("Service:      {}", def.native.name);
    println!("Display:      {}", def.native.display_name);
    if let Some(d) = &def.native.description {
        println!("Description:  {d}");
    }
    println!("Startup:      {:?}", def.native.startup);
    println!("Type:         {:?}", def.native.service_type);
    println!("Image:        {}", def.native.image_path);
    if let Some(account) = &def.native.account {
        println!("Account:      {account}");
    }
    if let Some(rt) = &def.runtime {
        println!("State:        {:?} (pid={:?})", rt.state, rt.pid);
    }
    match &def.managed {
        Some(m) => {
            println!("--- Managed (NSSM-compatible) ---");
            if let Some(app) = &m.application {
                println!("Application:  {app}");
            }
            if let Some(p) = &m.app_parameters {
                println!("AppParameters: {p}");
            }
            if let Some(d) = &m.app_directory {
                println!("AppDirectory: {d}");
            }
            if !m.exit_actions.is_empty() {
                println!("ExitActions:");
                for (k, v) in &m.exit_actions {
                    println!("  {k} => {:?}", v.action);
                }
            }
        }
        None => println!("(no managed configuration detected)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_adds_ellipsis_past_limit() {
        assert_eq!(truncate("short", 10), "short");
        let t = truncate("abcdefghij", 5);
        assert_eq!(t.chars().count(), 5);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn parse_exit_action_accepts_all_variants_case_insensitive() {
        use servicemanager_core::ExitAction;
        assert_eq!(parse_exit_action("restart").unwrap(), ExitAction::Restart);
        assert_eq!(parse_exit_action("IGNORE").unwrap(), ExitAction::Ignore);
        assert_eq!(parse_exit_action("Exit").unwrap(), ExitAction::Exit);
        assert_eq!(parse_exit_action("suicide").unwrap(), ExitAction::Suicide);
    }

    #[test]
    fn parse_exit_action_rejects_unknown() {
        assert!(parse_exit_action("reboot").is_err());
        assert!(parse_exit_action("").is_err());
    }

    #[test]
    fn recovery_parses_negative_mapping_values_and_following_flags() {
        let cli = Cli::try_parse_from([
            "ngsm",
            "recovery",
            "TestSvc",
            "set",
            "--exit-action",
            "-1=exit",
            "--exit-action",
            "-2147483648=ignore",
            "--restart-delay-ms",
            "350",
            "--clear-exit-actions",
        ])
        .unwrap();
        let Some(Command::Recovery(RecoveryArgs {
            action: Some(RecoveryAction::Set(args)),
            ..
        })) = cli.command
        else {
            panic!("expected recovery set");
        };
        let merged = merge_recovery_args("TestSvc", &recovery_spec_baseline(), &args).unwrap();
        assert_eq!(merged.restart_delay_ms, Some(350));
        assert_eq!(merged.exit_actions.len(), 2);
        assert_eq!(merged.exit_actions["-1"], ExitAction::Exit);
        assert_eq!(merged.exit_actions["-2147483648"], ExitAction::Ignore);

        let cli = Cli::try_parse_from([
            "ngsm",
            "recovery",
            "TestSvc",
            "set",
            "--exit-action=-1=exit",
            "--exit-action=0=ignore",
        ])
        .unwrap();
        let Some(Command::Recovery(RecoveryArgs {
            action: Some(RecoveryAction::Set(args)),
            ..
        })) = cli.command
        else {
            panic!("expected recovery set");
        };
        let merged = merge_recovery_args("TestSvc", &recovery_spec_baseline(), &args).unwrap();
        assert_eq!(merged.exit_actions["-1"], ExitAction::Exit);
        assert_eq!(merged.exit_actions["0"], ExitAction::Ignore);
    }

    #[test]
    fn negative_mapping_syntax_does_not_bypass_semantic_validation() {
        for value in [
            "-2147483649=exit",
            "-1=unknown",
            "-1",
            "--clear-exit-actions",
        ] {
            let cli =
                Cli::try_parse_from(["ngsm", "recovery", "TestSvc", "set", "--exit-action", value])
                    .unwrap();
            let Some(Command::Recovery(RecoveryArgs {
                action: Some(RecoveryAction::Set(args)),
                ..
            })) = cli.command
            else {
                panic!("expected recovery set");
            };
            assert!(merge_recovery_args("TestSvc", &recovery_spec_baseline(), &args).is_err());
        }
    }

    #[test]
    fn restart_keeps_native_override_and_custom_timeout() {
        let cli = Cli::try_parse_from([
            "ngsm",
            "restart",
            "TestSvc",
            "--force-native",
            "--timeout-ms",
            "350",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Restart {
                timeout_ms: 350,
                force_native: true,
                ..
            })
        ));
    }

    #[test]
    fn statuscode_maps_service_states_to_scm_codes_and_names() {
        let cases = [
            (ServiceState::Stopped, 1, "SERVICE_STOPPED"),
            (ServiceState::StartPending, 2, "SERVICE_START_PENDING"),
            (ServiceState::StopPending, 3, "SERVICE_STOP_PENDING"),
            (ServiceState::Running, 4, "SERVICE_RUNNING"),
            (ServiceState::ContinuePending, 5, "SERVICE_CONTINUE_PENDING"),
            (ServiceState::PausePending, 6, "SERVICE_PAUSE_PENDING"),
            (ServiceState::Paused, 7, "SERVICE_PAUSED"),
            (ServiceState::Unknown, 0, "SERVICE_UNKNOWN"),
        ];
        for (state, code, text) in cases {
            assert_eq!(statuscode_exit_code(state), code);
            assert_eq!(statuscode_state_text(state), text);
        }
    }

    #[test]
    fn reset_and_statuscode_parse_as_commands() {
        let cli = Cli::try_parse_from(["ngsm", "reset", "MySvc", "AppStdout"]).unwrap();
        match cli.command {
            Some(Command::Reset { name, param }) => {
                assert_eq!(name, "MySvc");
                assert_eq!(param, "AppStdout");
            }
            other => panic!("expected reset command, got {other:?}"),
        }

        let cli = Cli::try_parse_from(["ngsm", "statuscode", "MySvc"]).unwrap();
        match cli.command {
            Some(Command::StatusCode { name }) => assert_eq!(name, "MySvc"),
            other => panic!("expected statuscode command, got {other:?}"),
        }

        let cli = Cli::try_parse_from(["ngsm", "repair", "MySvc"]).unwrap();
        match cli.command {
            Some(Command::Repair { name }) => assert_eq!(name, "MySvc"),
            other => panic!("expected repair command, got {other:?}"),
        }

        assert!(
            Cli::try_parse_from(["ngsm", "edit", "MySvc", "--image-path", "C:\\evil.exe"]).is_err(),
            "raw ImagePath editing must not be accepted"
        );
        assert!(
            Cli::try_parse_from(["ngsm", "edit", "MySvc", "--service-type", "kernel"]).is_err(),
            "raw service type editing must not be accepted"
        );
    }

    /// Build an `InstallArgs` with the minimum required positional fields
    /// and every optional knob at its default. Tests then mutate only the
    /// flags they care about, so an unrelated field flip later cannot
    /// silently broaden test coverage.
    fn install_args_defaults() -> InstallArgs {
        InstallArgs {
            name: "TestSvc".into(),
            application: "C:\\app\\svc.exe".into(),
            app_parameters: None,
            app_directory: None,
            display: None,
            description: None,
            start: StartTypeArg::Manual,
            depend_service: Vec::new(),
            depend_group: Vec::new(),
            account: None,
            password_stdin: false,
            stdout: None,
            stderr: None,
            rotate_bytes: None,
            rotate_seconds: None,
            rotate_online: RotateOnlineArg::Offline,
            hook: Vec::new(),
        }
    }

    #[test]
    fn parse_install_args_rejects_rotation_flags_without_stdout_or_stderr() {
        // --rotate-bytes alone (no --stdout / --stderr) must be rejected.
        // Without a redirected log stream, `has_online_rotation` returns
        // false and `ngsm rotate` later refuses the request — install
        // should not silently accept inert rotation config.
        let mut args = install_args_defaults();
        args.rotate_bytes = Some(1_024_000);
        let err = validate_install_args(&args).expect_err(
            "--rotate-bytes without --stdout/--stderr must be rejected at the CLI boundary",
        );
        let msg = err.to_string();
        assert!(
            msg.contains("--stdout") && msg.contains("--stderr"),
            "error should name the missing flags, got {msg:?}"
        );
        assert!(
            msg.contains("rotation"),
            "error should explain why rotation needs them, got {msg:?}"
        );

        // --rotate-seconds alone — same rejection.
        let mut args = install_args_defaults();
        args.rotate_seconds = Some(3600);
        assert!(validate_install_args(&args).is_err());

        // --rotate-online online — same rejection.
        let mut args = install_args_defaults();
        args.rotate_online = RotateOnlineArg::Online;
        assert!(validate_install_args(&args).is_err());
    }

    #[test]
    fn parse_install_args_accepts_rotation_flags_with_stdout() {
        // The complementary positive case: rotation flags + --stdout
        // (or --stderr) is the supported configuration and must pass.
        let mut args = install_args_defaults();
        args.rotate_bytes = Some(1_024_000);
        args.stdout = Some("C:\\logs\\out.log".into());
        validate_install_args(&args).expect("rotation + stdout is valid");

        let mut args = install_args_defaults();
        args.rotate_seconds = Some(3600);
        args.stderr = Some("C:\\logs\\err.log".into());
        validate_install_args(&args).expect("rotation + stderr is valid");
    }

    #[test]
    fn parse_install_args_accepts_no_rotation_and_no_streams() {
        // The vanilla install path (no rotation, no streams) must keep
        // passing — the validator only fires when rotation is requested.
        let args = install_args_defaults();
        validate_install_args(&args).expect("plain install with no rotation must pass");
    }

    #[test]
    fn install_args_parse_dependencies_and_account_without_argv_password() {
        let cli = Cli::try_parse_from([
            "ngsm",
            "install",
            "TestSvc",
            "C:\\app\\svc.exe",
            "--depend-service",
            "Tcpip",
            "--depend-group",
            "NetworkProvider",
            "--account",
            ".\\svc_user",
            "--password-stdin",
        ])
        .unwrap();

        match cli.command {
            Some(Command::Install(args)) => {
                validate_install_args(&args).expect("dependencies/account are valid");
                assert_eq!(args.depend_service, vec!["Tcpip"]);
                assert_eq!(args.depend_group, vec!["NetworkProvider"]);
                assert_eq!(args.account.as_deref(), Some(".\\svc_user"));
                assert!(args.password_stdin);
            }
            other => panic!("expected install command, got {other:?}"),
        }
    }

    #[test]
    fn install_rejects_password_without_account_and_no_password_argv_flag_exists() {
        let mut args = install_args_defaults();
        args.password_stdin = true;
        let err = validate_install_args(&args)
            .expect_err("--password-stdin without --account must be rejected")
            .to_string();
        assert!(err.contains("--account"), "got: {err}");
        assert!(
            !err.contains("argv-password-value"),
            "error must not echo password-like data: {err}"
        );

        let err = Cli::try_parse_from([
            "ngsm",
            "install",
            "TestSvc",
            "C:\\app\\svc.exe",
            "--password",
            "argv-password-value",
        ])
        .expect_err("password must not be accepted as argv flag");
        assert!(
            err.to_string().contains("--password-stdin")
                || err.to_string().contains("unexpected argument"),
            "got: {err}"
        );
    }

    #[test]
    fn install_rejects_invalid_dependency_entries_without_echoing_value() {
        let mut args = install_args_defaults();
        args.depend_service.push("Bad\nName".into());
        let err = validate_install_args(&args)
            .expect_err("control chars in dependencies must be rejected")
            .to_string();
        assert!(err.contains("control"), "got: {err}");
        assert!(
            !err.contains("Bad"),
            "dependency value should not be echoed: {err}"
        );

        let mut args = install_args_defaults();
        args.depend_group.push(String::new());
        let err = validate_install_args(&args)
            .expect_err("empty group dependency must be rejected")
            .to_string();
        assert!(err.contains("empty"), "got: {err}");
    }

    /// Build a `RecoverySetArgs` with everything off — tests then flip just
    /// the field they care about.
    fn recovery_set_args_defaults() -> RecoverySetArgs {
        RecoverySetArgs {
            default_action: None,
            restart_delay_ms: None,
            no_restart_delay: false,
            throttle_delay_ms: None,
            no_throttle_delay: false,
            exit_actions: Vec::new(),
            clear_exit_actions: false,
        }
    }

    /// A baseline persisted recovery spec to merge against in unit tests.
    fn recovery_spec_baseline() -> RecoverySpec {
        let mut exit_actions = BTreeMap::new();
        exit_actions.insert("0".into(), ExitAction::Ignore);
        RecoverySpec {
            name: "TestSvc".into(),
            restart_delay_ms: Some(1_000),
            throttle_delay_ms: Some(2_000),
            default_action: ExitAction::Restart,
            exit_actions,
        }
    }

    #[test]
    fn recovery_set_with_only_restart_delay_preserves_default_action() {
        // Regression for finding #9: a partial update that only changes
        // restart_delay_ms must keep the existing default_action — it should
        // not silently flip to a clap-supplied default.
        let current = recovery_spec_baseline();
        let mut args = recovery_set_args_defaults();
        args.restart_delay_ms = Some(5_000);

        let merged = merge_recovery_args("TestSvc", &current, &args).expect("merge succeeds");

        assert_eq!(merged.restart_delay_ms, Some(5_000));
        assert_eq!(
            merged.default_action, current.default_action,
            "default_action must be preserved when --default-action is absent"
        );
        // Untouched fields are still preserved.
        assert_eq!(merged.throttle_delay_ms, current.throttle_delay_ms);
        assert_eq!(merged.exit_actions, current.exit_actions);
    }

    /// Build an `EditArgs` with only the service name — every editable
    /// field at None — so tests can flip one flag at a time.
    fn edit_args_defaults() -> EditArgs {
        EditArgs {
            name: "TestSvc".into(),
            application: None,
            app_parameters: None,
            app_directory: None,
            display: None,
            description: None,
            start: None,
            depend_service: Vec::new(),
            depend_group: Vec::new(),
            clear_dependencies: false,
            account: None,
            password_stdin: false,
            stdout: None,
            stderr: None,
            force_native: false,
        }
    }

    #[test]
    fn bare_edit_returns_error_about_no_fields() {
        // Regression for finding #16: a bare `ngsm edit <name>` with no
        // editable flags must be rejected at the CLI boundary instead of
        // silently reporting success.
        let args = edit_args_defaults();
        let err = validate_edit_args(&args).expect_err("bare edit must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("no edit fields"),
            "error should explain no fields were specified, got {msg:?}"
        );
        assert!(
            msg.contains("--help"),
            "error should point to --help for the field list, got {msg:?}"
        );

        // --force-native on its own is also nothing-to-change: the flag only
        // relaxes a guard, it carries no new value.
        let mut args = edit_args_defaults();
        args.force_native = true;
        assert!(
            validate_edit_args(&args).is_err(),
            "--force-native without any value-bearing flag must also be rejected"
        );
    }

    #[test]
    fn edit_with_one_field_passes_validation() {
        // The complementary positive case: any single editable flag is
        // enough to make the invocation meaningful.
        let mut args = edit_args_defaults();
        args.display = Some("New Display".into());
        validate_edit_args(&args).expect("--display alone is valid");

        let mut args = edit_args_defaults();
        args.application = Some("C:\\app\\new.exe".into());
        validate_edit_args(&args).expect("--application alone is valid");

        let mut args = edit_args_defaults();
        args.start = Some(StartTypeArg::Automatic);
        validate_edit_args(&args).expect("--start alone is valid");
    }

    #[test]
    fn edit_dependency_flags_are_edit_fields_and_clear_conflicts() {
        let mut args = edit_args_defaults();
        args.depend_service.push("Tcpip".into());
        validate_edit_args(&args).expect("--depend-service alone is valid");
        let deps = edit_dependencies_from_cli(&args)
            .expect("dependencies parse")
            .expect("dependencies set");
        assert_eq!(deps.services, vec!["Tcpip"]);
        assert!(deps.groups.is_empty());

        let mut args = edit_args_defaults();
        args.clear_dependencies = true;
        validate_edit_args(&args).expect("--clear-dependencies alone is valid");
        let deps = edit_dependencies_from_cli(&args)
            .expect("dependencies parse")
            .expect("clear dependencies set");
        assert!(deps.is_empty());

        assert!(
            Cli::try_parse_from([
                "ngsm",
                "edit",
                "TestSvc",
                "--clear-dependencies",
                "--depend-service",
                "Tcpip",
            ])
            .is_err(),
            "clear and explicit dependencies must conflict"
        );
    }

    #[test]
    fn edit_accepts_password_stdin_only_with_account_and_rejects_password_argv() {
        let mut args = edit_args_defaults();
        args.account = Some(".\\svc_user".into());
        args.password_stdin = true;
        validate_edit_args(&args).expect("account + password-stdin is valid");

        let mut args = edit_args_defaults();
        args.password_stdin = true;
        let err = validate_edit_args(&args)
            .expect_err("--password-stdin without --account must be rejected")
            .to_string();
        assert!(err.contains("--account"), "got: {err}");

        assert!(
            Cli::try_parse_from([
                "ngsm",
                "edit",
                "TestSvc",
                "--password",
                "argv-password-value",
            ])
            .is_err(),
            "password must not be accepted as argv flag"
        );
    }

    #[test]
    fn recovery_set_with_explicit_default_action_overrides() {
        // When the operator does pass --default-action, the new value wins.
        let current = recovery_spec_baseline();
        let mut args = recovery_set_args_defaults();
        args.default_action = Some(ExitActionArg::Exit);
        args.restart_delay_ms = Some(5_000);

        let merged = merge_recovery_args("TestSvc", &current, &args).expect("merge succeeds");

        assert_eq!(merged.default_action, ExitAction::Exit);
        assert_eq!(merged.restart_delay_ms, Some(5_000));
    }
}
