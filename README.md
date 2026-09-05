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
- **Desktop GUI** — double-click `ngsm.exe` for a dashboard with four
  classification tiles (Managed services, Stopped, Failed, Availability 30d)
  with sub-captions, a 30-day availability sparkline, a Recent Events feed
  sourced from the persistent supervisor log, install / edit / remove, a
  recovery-policy editor, and a settings view (auto-refresh, managed-only
  filter persistence).
- **Full CLI** — `install`, `remove`, `edit`, `list`, `status`,
  `start` / `stop` / `restart` / `pause` / `continue`, `rotate`,
  `get` / `set` / `reset` / `unset`, `statuscode`, `repair`.
- **Process supervision** — restart and throttle policies, per-exit-code
  actions (`AppExit`), and a Job Object so the whole process tree dies with
  the service.
- **Persistent event log** — every supervisor records lifecycle events
  (start, stop, restart, child exit, throttle) to
  `%ProgramData%\NGSM\events.log` as JSON Lines, so the GUI's Recent Events
  panel survives restarts and the history is observable from any tool that
  can read a text file. Runtime failures are recorded separately in the
  Windows **Application Event Log** under source `NGSM`, not in the child's
  redirected stderr.
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

NGSM is **Windows-only** (x64 primary; aarch64 and i686 builds are configured but untested).

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

### Release integrity and upgrades

Releases include `SHA256SUMS.txt`; compare its `ngsm.exe` entry with:

```powershell
Get-FileHash .\ngsm.exe -Algorithm SHA256
```

The executable is **unsigned**. A matching checksum detects a damaged or
different download; it is not an Authenticode publisher signature.
`BUILD-INFO.json` identifies the source commit, Rust toolchain, and build
run. The accompanying source archive includes the tagged project and
vendored dependencies, and is the source used for the offline release
build. See [third-party notices](THIRD-PARTY-NOTICES.md) for licenses and
rebuild instructions.

Before replacing an installed runner, stop the services using that
`ngsm.exe` and close its GUI. Keep the executable at the same protected
path, then restart those services. Keep a copy of the previous version for
rollback; replacing the binary does not require reinstalling services.

## Usage

```text
ngsm                                   Launch the desktop GUI
ngsm install MySvc "C:\app\app.exe"     Install a service
ngsm install MySvc "C:\app\app.exe" --app-parameters="--flag" --stdout "C:\logs\out.log"
ngsm install MySvc "C:\app\app.exe" --depend-service Tcpip --account ".\svc_user" --password-stdin
ngsm list                               List NGSM-managed services
ngsm status MySvc                       Show a service's state
ngsm statuscode MySvc                   Print SERVICE_* state and exit with SCM state code
ngsm start MySvc                        Start it (also: stop / restart / pause / continue)
ngsm edit MySvc --display "My Service"  Edit an installed service
ngsm edit MySvc --description "Runs My Service"
ngsm edit MySvc --depend-group NetworkProvider
ngsm edit MySvc --clear-dependencies
ngsm recovery MySvc                    Show the recovery policy
ngsm recovery MySvc set --restart-delay-ms 5000
ngsm recovery MySvc set --exit-action "-1=exit"
ngsm repair MySvc                       Rebind SCM ImagePath to the validated NGSM runner
ngsm remove MySvc                       Remove a service and its config
ngsm get MySvc AppDirectory             Read an NSSM-compatible value
ngsm set MySvc AppDirectory "C:\app"    Write one
ngsm reset MySvc AppDirectory           Reset one NSSM-compatible value
```

`ngsm --help` and `ngsm <command> --help` list every option.
Use the `--app-parameters="..."` form when the application's arguments
start with a hyphen, so they are not parsed as NGSM options.

`start`, `stop`, `pause`, and `continue` report acceptance of an SCM control
request, not completion of the transition. Check `ngsm status <service>`
before a dependent action; in particular, wait for `Stopped` before
removing a service or replacing its runner. `restart` waits for the old
service instance to stop before requesting a new start.

NGSM does not expose raw `ImagePath` or service-type editing for managed
services. Use `ngsm repair <service>` to safely restore the SCM binding to the
validated `ngsm.exe run-service <service>` command and `Win32OwnProcess`
service type.

### Configuration notes

Managed runner settings are loaded when the service host starts. Restart
the service after changing its application, environment, recovery, or
logging settings; editing the registry does not reconfigure an already
running child. Native SCM settings follow Windows' own update semantics.

Environment lists use comma-separated `NAME=value` entries. `\,` encodes
a literal comma and `\\` a literal backslash; other backslashes and
significant whitespace are preserved. For example:

```powershell
ngsm set MySvc AppEnvironmentExtra 'APP_HOME=C:\Tools\app,LABEL=one\,two'
ngsm set MySvc AppEnvironmentExtra 'APP_HOME=\\\\server\\share'
```

The second example encodes the UNC value `\\server\share`. A later `set`
replaces the entire selected environment list, rather than appending to it.
The encoded value returned by `get` can be used for a lossless round trip.

Imported `REG_EXPAND_SZ` values retain their raw text/type and are expanded
in the service environment, not the desktop user's environment. Percent
characters in ordinary `REG_SZ` application/argument values are not
expanded by NGSM; a child shell can still apply its own syntax.
For log paths containing service-environment references, the GUI explains
that it cannot safely infer another account's environment instead of
opening a misleading literal or editor-expanded path.

Removing a service also removes its registry subtree: Windows SCM owns
that deletion. `--no-purge-config` cannot preserve it and is rejected.
Inspect/export the configuration before removal, for example with
`ngsm --json dump MySvc`. Configuration exports can contain environment
secrets and must be stored securely; a dump is not an automatic restore
command.

### Compatibility limits

NGSM recognizes NSSM's registry layout, but does not promise every NSSM
option or identical runtime behavior. Previously ignored non-default
settings may now take effect or cause an explicit startup error.

| Setting | Supported behavior |
|---|---|
| `AppPriority` / `AppAffinity` | Applied before the child runs. Affinity uses CPU IDs/ranges in one supported processor group (group 0), not a multi-group mask. Invalid or unavailable selections are rejected. |
| `AppTimestampLog` / `AppRotateDelay` | Timestamp insertion and nonzero rotation delay are not supported; enabled values are rejected rather than silently ignored. |
| Stream opening and rotation | Supported sharing/disposition/attribute options are honored. Destructive creation combined with rotation, overlapped/unbuffered or delete-on-close/reparse-point flags, alternate-stream output, and incompatible hard-link/alias combinations are rejected. Rotation recovery reopens without truncating acknowledged output; stdin remains read-only. |

Use unique log destinations for independent services and review inherited
NSSM options before upgrading. Availability is an estimate of observed
child-process lifetime, not an application health check; insufficient
history is shown as unknown rather than 100%.

Service accounts need the appropriate logon and file permissions, including
write access to their chosen output locations and the shared NGSM event
directory when lifecycle history is required. NGSM does not broaden log-file
ACLs automatically. Runtime diagnostic text is also available in the
Application event's Details/XML view if Windows has no registered message
resource for source `NGSM`.

## Building from source

Requires a Windows host with the **Rust** toolchain (stable; MSRV 1.90) and
the **MSVC** build tools.

```text
cargo build --locked --release
```

The binary lands at `target\release\ngsm.exe`. It statically links the C
runtime, so it can be copied to any Windows machine with no extra
dependencies.

An optional named-pipe **broker** for headless automation is gated behind a
Cargo feature and is off by default:

```text
cargo build --locked --release -p servicemanager-cli --features broker
```

CI covers both default and broker-enabled configurations on Windows,
using Rust **1.90.0**, the committed lockfile, formatting, Clippy, tests, and
release compilation. Tagging a matching `vMAJOR.MINOR.PATCH` version runs
those gates and prepares a **draft** GitHub release with the executable,
source bundle, license notices, checksums, and build metadata.

Maintainers can reproduce the packaging step from a clean checkout of
the release tag with `.\scripts\package-release.ps1 -Tag vMAJOR.MINOR.PATCH`.
It vendors dependencies, builds their bundled sources offline, and writes
assets to a new `target\dist` directory. Inspect the draft assets before
publishing the release; the workflow never automatically marks a draft
as the latest public release.

The accepted findings, behavioral specifications, and remediation
checklist for this release are in [QUALITY-REVIEW.md](QUALITY-REVIEW.md).

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

NGSM's own source code is released under the **BSD Zero Clause License
(0BSD)** — see [LICENSE](LICENSE). The official GUI binary also links the
Slint UI framework, which is used under Slint's GPLv3 terms; see
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) for source and license
distribution details and [SECURITY.md](SECURITY.md) for the security policy.
