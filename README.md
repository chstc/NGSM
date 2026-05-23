# Next-Gen Service Manager (NGSM)

**A modern Windows service manager** — run any application as a Windows
service, and supervise it properly.

NGSM is a ground-up Rust reimplementation in the spirit of
**[NSSM — the Non-Sucking Service Manager](https://nssm.cc/)**. It installs an
arbitrary executable as a Windows service and then babysits it: restarts it on
failure, redirects and rotates its logs, runs lifecycle hooks, and shuts it
down gracefully. NGSM reads and writes the same `Parameters` registry layout
NSSM uses, so it recognises services that NSSM installed.

A single `ngsm.exe` is the whole product: a desktop GUI, a command-line
interface, and the Windows service host itself.

## Heritage & credit

NGSM stands on the shoulders of **NSSM, the Non-Sucking Service Manager**,
created by **Iain Patterson** and released into the **public domain**
(<https://nssm.cc/>). NSSM has been the go-to tool for running programs as
Windows services for well over a decade — this project would not exist
without it, and owes it a real debt of thanks.

NGSM is an **independent rewrite**: it is written from scratch in Rust and
shares no source code with NSSM (which is C). It does, however, deliberately
keep NSSM's registry layout — the `Application`, `AppParameters`,
`AppDirectory`, `AppExit`, `AppRotate*`, `AppEnvironment`, … values under each
service's `Parameters` key — so the two tools recognise each other's
services. The no-strings, public-domain spirit of NSSM is carried forward
here with the equally permissive **0BSD** license.

## Features

- **One self-contained binary.** `ngsm.exe` is the GUI, the CLI, and the
  service runner. It statically links the C runtime — no DLLs to ship.
- **Desktop GUI** — double-click `ngsm.exe` for a dashboard with live
  service stats, install / edit / remove, a recovery-policy editor, a
  Recent Events feed, and a settings view (auto-refresh, managed-only
  filter persistence).
- **Full CLI** — `install`, `remove`, `edit`, `list`, `status`,
  `start` / `stop` / `restart` / `pause` / `continue`, `rotate`,
  `get` / `set` / `unset`.
- **Process supervision** — restart and throttle policies, per-exit-code
  actions (`AppExit`), and a Job Object so the whole process tree dies with
  the service.
- **Persistent event log** — every supervisor records lifecycle events
  (start, stop, restart, child exit, throttle) to
  `%ProgramData%\NGSM\events.log` as JSON Lines, so the GUI's Recent Events
  panel survives restarts and the history is observable from any tool that
  can read a text file.
- **Graceful shutdown** — CTRL+BREAK → WM_CLOSE → WM_QUIT → terminate, each
  step configurable.
- **Log handling** — redirect stdout/stderr to files, with offline
  (on-restart) and online (live) rotation by size or age.
- **Lifecycle hooks** — run commands on Start / Stop / Exit / Rotate / Power
  events, each contained in its own kill-on-close job.
- **Environment control** — replacement (`AppEnvironment`) and additive
  (`AppEnvironmentExtra`) environment variables.
- **NSSM registry compatibility** — reads and writes the `Parameters` keys
  that NSSM uses.

## Install

NGSM is **Windows-only** (x64).

1. Download `ngsm.exe` from the
   [Releases](https://github.com/chstc/NGSM/releases) page.
2. **Place it in an administrator-protected directory** — for example
   `C:\Program Files\NGSM\`. This matters: NGSM refuses to register a service
   whose runner lives in a user-writable location (Downloads, Temp, a profile
   folder). A service's image path is permanent, so a replaceable runner
   binary would be a privilege-escalation risk.
3. Run it from there.

Anything that creates, changes, or controls a service must be run **elevated**
(as Administrator).

## Usage

```text
ngsm                                   Launch the desktop GUI
ngsm install MySvc "C:\app\app.exe"     Install a service
ngsm install MySvc "C:\app\app.exe" --app-parameters "--flag" --stdout "C:\logs\out.log"
ngsm list                               List NGSM-managed services
ngsm status MySvc                       Show a service's state
ngsm start MySvc                        Start it (also: stop / restart / pause / continue)
ngsm edit MySvc --display "My Service"  Edit an installed service
ngsm remove MySvc                       Remove a service and its config
ngsm get MySvc AppDirectory             Read an NSSM-compatible value
ngsm set MySvc AppDirectory "C:\app"    Write one
```

`ngsm --help` and `ngsm <command> --help` list every option.

## Building from source

Requires a Windows host with the **Rust** toolchain (stable; MSRV 1.88) and
the **MSVC** build tools.

```text
cargo build --release
```

The binary lands at `target/release/ngsm.exe`. It statically links the C
runtime, so it can be copied to any Windows machine with no extra
dependencies.

An optional named-pipe **broker** for headless automation is gated behind a
Cargo feature and is off by default:

```text
cargo build --release -p servicemanager-cli --features broker
```

## Project layout

A Cargo workspace of focused crates:

| Crate | Responsibility |
|---|---|
| `servicemanager-core` | Platform-agnostic domain model and validation |
| `servicemanager-win32` | SCM, Job Object, process, and console wrappers |
| `servicemanager-registry` | NSSM-compatible `Parameters` registry adapter |
| `servicemanager-ops` | High-level service operations (install, remove, edit, control) |
| `servicemanager-supervisor` | Child-process supervision, hooks, log rotation |
| `servicemanager-runner` | Windows service entry point (SCM dispatcher) |
| `servicemanager-broker` | Optional elevated named-pipe broker |
| `servicemanager-gui` | Slint desktop interface |
| `servicemanager-cli` | `ngsm.exe` — the CLI and the launcher for everything above |

## License

NGSM is released under the **BSD Zero Clause License (0BSD)** — see
[LICENSE](LICENSE). It is a permissive, OSI-approved license that requires no
attribution, chosen to preserve the no-strings spirit of the public-domain
NSSM project this descends from.
