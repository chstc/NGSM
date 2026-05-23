use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use servicemanager_core::{
    HookConfig, IoRedirectionConfig, IoStream, LogRotationConfig, ManagedApplicationConfig,
    ManagementKind, Result, ServiceDefinition,
};
use servicemanager_ops::{EditSpec, InstallSpec};
use servicemanager_win32::{
    build_run_service_command, control_service, enumerate_descendants, install_service,
    query_service, remove_service, start_service, update_native_config, InstallOptions,
    InstallStartType, ServiceControlSignal,
};

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
        /// Also delete the managed config under `Parameters` (default: true).
        #[arg(long, default_value_t = true)]
        purge_config: bool,
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
    /// Edit an installed service. Only the supplied fields are changed.
    Edit(EditArgs),
    /// Force the supervisor to rotate the service's logs now. Requires the
    /// service to be running.
    Rotate {
        /// Service name.
        name: String,
    },
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
    /// Replace the SCM start type.
    #[arg(long, value_enum)]
    start: Option<StartTypeArg>,
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
    /// SCM start type.
    #[arg(long, value_enum, default_value_t = StartTypeArg::Manual)]
    start: StartTypeArg,
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
            purge_config,
            force_native,
        } => cmd_remove(name, *purge_config, *force_native, cli.json),
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
        Command::Edit(args) => cmd_edit(args, cli.json),
        Command::Rotate { name } => cmd_rotate(name, cli.json),
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

fn cmd_install(args: &InstallArgs, json: bool) -> Result<()> {
    let has_hooks = !args.hook.is_empty();
    let has_rotation = args.rotate_bytes.is_some()
        || args.rotate_seconds.is_some()
        || args.rotate_online != RotateOnlineArg::Offline;

    if has_hooks || has_rotation {
        // ops::install does not yet carry hooks or rotation in InstallSpec.
        // Fall back to the full local path for these CLI-only extended options.
        cmd_install_extended(args, json)
    } else {
        let spec = InstallSpec {
            name: args.name.clone(),
            display_name: args.display.clone(),
            application: args.application.clone(),
            app_parameters: args.app_parameters.clone(),
            app_directory: args.app_directory.clone(),
            stdout: args.stdout.clone(),
            stderr: args.stderr.clone(),
            start_type: args.start.into(),
        };
        let msg = servicemanager_ops::install(spec).map_err(servicemanager_core::Error::other)?;
        if json {
            println!("{}", serde_json::json!({ "installed": args.name }));
        } else {
            println!("{msg}");
        }
        Ok(())
    }
}

/// Full local install path used when hook or rotation options are present
/// (features not yet supported in [`servicemanager_ops::InstallSpec`]).
fn cmd_install_extended(args: &InstallArgs, json: bool) -> Result<()> {
    if args.application.trim().is_empty() {
        return Err(servicemanager_core::Error::InvalidConfig(
            "application path is required".into(),
        ));
    }

    // Build (and validate) the complete managed config *before* creating the
    // SCM service, so a bad hook spec or argument fails without leaving an
    // orphaned, unconfigured service behind.
    let mut managed = ManagedApplicationConfig {
        application: Some(args.application.clone()),
        app_parameters: args.app_parameters.clone(),
        app_directory: args.app_directory.clone(),
        io: IoRedirectionConfig {
            stdin: None,
            stdout: args.stdout.clone().map(cli_io_stream),
            stderr: args.stderr.clone().map(cli_io_stream),
            timestamp_log: None,
        },
        ..Default::default()
    };
    if args.rotate_bytes.is_some()
        || args.rotate_seconds.is_some()
        || args.rotate_online != RotateOnlineArg::Offline
    {
        managed.rotation = LogRotationConfig {
            enabled: Some(true),
            online: Some(args.rotate_online.as_nssm_value()),
            seconds: args.rotate_seconds,
            bytes: args.rotate_bytes,
            delay_ms: None,
        };
    }
    for raw in &args.hook {
        managed.hooks.push(parse_hook_spec(raw)?);
    }

    let binary_path = build_run_service_command(&args.name)?;
    let display = args.display.clone().unwrap_or_else(|| args.name.clone());

    install_service(&InstallOptions {
        name: args.name.clone(),
        display_name: display,
        binary_path,
        start_type: args.start.into(),
    })?;

    // Roll the SCM service back if the managed config write fails — otherwise
    // the service exists but the runner has nothing to run.
    if let Err(e) = servicemanager_registry::create_managed_config(&args.name, &managed) {
        return Err(match remove_service(&args.name) {
            Ok(()) => servicemanager_core::Error::other(format!(
                "install failed, service rolled back: {e}"
            )),
            Err(re) => servicemanager_core::Error::other(format!(
                "install failed ({e}); rollback also failed ({re})"
            )),
        });
    }

    if json {
        println!("{}", serde_json::json!({ "installed": args.name }));
    } else {
        println!("Installed service '{}'.", args.name);
    }
    Ok(())
}

fn cmd_remove(name: &str, purge_config: bool, force_native: bool, json: bool) -> Result<()> {
    let msg = servicemanager_ops::remove(name, force_native, purge_config)
        .map_err(servicemanager_core::Error::other)?;
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
    let msg = msg.map_err(servicemanager_core::Error::other)?;

    if json {
        println!("{}", serde_json::json!({ json_key: name }));
    } else {
        println!("{msg}");
    }
    Ok(())
}

fn cmd_restart(name: &str, timeout_ms: u32, force_native: bool, json: bool) -> Result<()> {
    if force_native {
        // Bypass the NGSM-managed check — run the restart loop locally.
        cmd_restart_force_native(name, timeout_ms, json)
    } else {
        let msg = servicemanager_ops::restart(name, timeout_ms as u64)
            .map_err(servicemanager_core::Error::other)?;
        if json {
            println!("{}", serde_json::json!({ "restarted": name }));
        } else {
            println!("{msg}");
        }
        Ok(())
    }
}

/// Restart implementation for `--force-native`: bypasses NGSM-managed check
/// and uses the CLI's configurable `timeout_ms` stop-wait deadline.
fn cmd_restart_force_native(name: &str, timeout_ms: u32, json: bool) -> Result<()> {
    use servicemanager_core::ServiceState;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    let already_stopped = |e: &servicemanager_core::Error| {
        if let servicemanager_core::Error::Scm(msg) = e {
            msg.contains("0x80070426") || msg.contains("has not been started")
        } else {
            false
        }
    };

    let snapshot = query_service(name)?;
    let initial_state = snapshot.runtime.as_ref().map(|r| r.state);
    let needs_stop = !matches!(initial_state, Some(ServiceState::Stopped) | None);

    if needs_stop {
        match control_service(name, ServiceControlSignal::Stop) {
            Ok(_) => {}
            Err(e) if already_stopped(&e) => {}
            Err(e) => return Err(e),
        }

        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        loop {
            let snapshot = query_service(name)?;
            let state = snapshot.runtime.as_ref().map(|r| r.state);
            if matches!(state, Some(ServiceState::Stopped)) {
                break;
            }
            if Instant::now() >= deadline {
                return Err(servicemanager_core::Error::other(format!(
                    "service '{name}' did not stop within {timeout_ms} ms (last state: {state:?})"
                )));
            }
            sleep(Duration::from_millis(200));
        }
        sleep(Duration::from_millis(250));
    }

    start_service(name)?;
    if json {
        println!("{}", serde_json::json!({ "restarted": name }));
    } else {
        println!("Restarted '{name}'.");
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

fn cmd_edit(args: &EditArgs, json: bool) -> Result<()> {
    let want_native = args.display.is_some() || args.start.is_some();

    // When --force-native is set and only native SCM fields are being changed,
    // ops::edit is not usable (it always enforces NGSM-managed ownership).
    // Fall through to the direct SCM call for that narrow case.
    if args.force_native && want_native {
        // Also reject managed-field edits on a non-managed service even with
        // --force-native: the managed registry key must exist for those to make
        // sense.
        let managed_cfg = servicemanager_registry::read_managed_config(&args.name)?;
        let want_managed = args.application.is_some()
            || args.app_parameters.is_some()
            || args.app_directory.is_some()
            || args.stdout.is_some()
            || args.stderr.is_some();
        if want_managed && managed_cfg.is_none() {
            return Err(servicemanager_core::Error::InvalidConfig(format!(
                "'{}' is not an NGSM-managed service — managed fields can only be edited on \
                 a service installed via NGSM; use `install` instead",
                args.name
            )));
        }
        update_native_config(
            &args.name,
            args.display.as_deref(),
            args.start.map(Into::into),
        )?;
        if json {
            println!("{}", serde_json::json!({ "edited": args.name }));
        } else {
            println!("Edited '{}'.", args.name);
        }
        return Ok(());
    }

    // Delegate to ops — enforces NGSM-managed ownership internally.
    let spec = EditSpec {
        name: args.name.clone(),
        display_name: args.display.clone(),
        application: args.application.clone(),
        app_parameters: args.app_parameters.clone(),
        app_directory: args.app_directory.clone(),
        stdout: args.stdout.clone(),
        stderr: args.stderr.clone(),
        start_type: args.start.map(Into::into),
    };
    let msg = servicemanager_ops::edit(spec).map_err(servicemanager_core::Error::other)?;
    if json {
        println!("{}", serde_json::json!({ "edited": args.name }));
    } else {
        println!("{msg}");
    }
    Ok(())
}

fn cmd_rotate(name: &str, json: bool) -> Result<()> {
    let msg = servicemanager_ops::rotate(name).map_err(servicemanager_core::Error::other)?;
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

/// Parse a `EVENT/ACTION=command` spec from `--hook`.
fn parse_hook_spec(raw: &str) -> Result<HookConfig> {
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
    // Reject hook names that cannot be used as registry subkey / value names.
    servicemanager_core::validate_hook_component(event, "event")?;
    servicemanager_core::validate_hook_component(action, "action")?;
    Ok(HookConfig {
        event: event.to_string(),
        action: action.to_string(),
        command: command.trim().to_string(),
    })
}

/// Wrap a log-file path in a plain [`IoStream`] (default share/disposition).
/// Used only by the extended install path (hooks/rotation); basic installs
/// go through [`servicemanager_ops::install`] which has its own internal helper.
fn cli_io_stream(path: String) -> IoStream {
    IoStream {
        path,
        share_mode: None,
        creation_disposition: None,
        flags_and_attributes: None,
        copy_and_truncate: None,
    }
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
    fn truncate_adds_ellipsis_past_limit() {
        assert_eq!(truncate("short", 10), "short");
        let t = truncate("abcdefghij", 5);
        assert_eq!(t.chars().count(), 5);
        assert!(t.ends_with('…'));
    }
}
