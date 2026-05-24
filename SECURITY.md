# Security Policy

NGSM is a Rust rewrite of NSSM — a Windows service manager. Because the tool's
purpose is installing, modifying, and controlling Windows services, it
necessarily exercises the same OS surfaces that malware uses for persistence.
This document covers (a) how to report a vulnerability, (b) what versions are
supported, (c) why NGSM trips antivirus / sandbox heuristics and what's
inherent vs. addressable, and (d) the project's supply-chain stance.

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting** for anything sensitive:

1. Go to the repository's **Security** tab → **Report a vulnerability**.
2. Describe the issue. Include affected version, reproduction steps, and the
   expected vs. observed behavior. A minimal reproducer (a small managed-config,
   a CLI invocation, or a code snippet) is the fastest path to triage.
3. The advisory stays private between you and the maintainer until a fix
   ships.

For non-sensitive bugs (crash on bad input, incorrect status, UI glitch),
open a normal GitHub issue.

Maintenance is best-effort. Practical turnaround for confirmed
vulnerabilities is typically days to a couple of weeks depending on
scope.

### Out of scope

- Anything requiring local Administrator: NGSM operates as an administrator
  tool. A user with Administrator already owns the box; surfacing that they
  can also install a service is not a vulnerability.
- Antivirus / sandbox heuristic flags on the unsigned binary — see
  [Antivirus & sandbox reports](#antivirus--sandbox-reports) below.
- Stale or hand-edited registry state under a service's `Parameters` key —
  if the registry is wrong, NGSM may produce surprising output. Use
  `ngsm get <svc>` / `ngsm set <svc> ...` to repair rather than editing
  the registry directly.

## Supported versions

Only the latest published release receives fixes. There is no LTS line.

| Version | Status |
|---|---|
| v0.3.2 | Supported (current) |
| < v0.3.2 | Not supported — upgrade to v0.3.2 |

NGSM is not yet at v1.0; expect occasional breaking changes between minor
versions until then. The on-disk schema (registry layout, event log format)
is stable and additive across the v0.x line.

## Antivirus & sandbox reports

NGSM is a service manager. The Windows APIs it must call —
`OpenSCManager`, `CreateService`, `ChangeServiceConfig`, `ControlService`,
registry writes under `HKLM\SYSTEM\CurrentControlSet\Services`,
`CreateProcessW`, `AdjustTokenPrivileges`, Job Object assignment,
`TerminateProcess` — are also what persistence-oriented malware uses.
Heuristic and ML-based AV engines flag the *capability* (the imports and
strings present in the binary) even when nothing malicious is happening
at runtime.

Sandbox reports on the released `ngsm.exe` (e.g. Hybrid Analysis,
VirusTotal) typically show:

- **~1 "malicious" indicator** — `OpenSCManager` access. This is the tool's
  defining capability. It cannot be removed.
- **~30–40 "suspicious" indicators** — heuristic tags on Win32 imports +
  string matches. Categorized below.
- **0 detected malicious runtime behavior** — the sandbox observes no
  exfiltration, no C2, no payload execution, no credential theft.

### What the flags actually mean

| Indicator class | Example flags | Source | Addressable? |
|---|---|---|---|
| **Service control** | "Able to change service configuration", "Contains ability to open/control a service", "Service Stop (T1489)" | NGSM's purpose | No — would defeat the tool |
| **Process control** | "Contains ability to terminate a process", "Enumerate processes/modules/threads" | Supervisor + Processes dialog | No |
| **Token / privilege** | "Adjust token privileges", "Token Impersonation/Theft" | `AdjustTokenPrivileges` for SCM ops; `DuplicateHandle` in the broker | No — both are required |
| **Persistence (MITRE T1543.003)** | "Windows Service" persistence | NGSM's purpose | No |
| **Registry (T1112)** | "Modify Registry" | Managed config writes to `Parameters` | No |
| **GUI framework imports** | "Read clipboard data", "Register/read input devices", "Take screenshots", "Hidden Window" | Slint + winit + femtovg transitive imports | No — would mean replacing the GUI |
| **Compiler heuristics** | "High entropy section", "Software Packing", "Junk code insertion" | Rust release build with LTO | Partially — disabling LTO reduces entropy but hurts performance. Not recommended. |
| **VM detection signatures** | "Anti-VM trick", "Reads VM-specific registry key" | Coincidental byte matches from compiler-emitted code or hardware-probing crates (cpufeatures, etc.) | Effectively no — would require forensic disassembly |

### What would change with code signing

NGSM's released binary is currently **unsigned**. Adding an Authenticode
signature from a recognized publisher would not remove any of the indicators
above, but engines weigh signed binaries differently:

- Heuristic engines down-weight individual capability flags when the
  publisher identity is verified.
- Windows SmartScreen reputation accrues to the publisher cert, removing
  the "Unknown publisher" prompt for end users after some download volume.
- Vendor false-positive submissions (Microsoft, VirusTotal) are generally
  taken more seriously for signed binaries.

Signing is on the project's backlog but not yet committed to a timeline.

### What end users can do today

- **Verify the SHA-256** of the downloaded `ngsm.exe` against the release
  page's published hash.
- **Run the binary in a VM first** if your environment requires it.
- **Check the audit trail** — the public commit history and the two
  code-review remediation cycles documented in [CHANGELOG.md](CHANGELOG.md)
  (v0.3.1 + v0.3.2) cover ~35 reviewed findings across the codebase.
- **Submit false-positive feedback** to the specific AV vendor flagging
  the binary, with a link to this document and the GitHub release page.

## Supply chain

### Build provenance

- **All releases are built from the public repository** by CI
  (`.github/workflows/ci.yml`, `windows-latest` runner, pinned Rust 1.90).
- **The released `ngsm.exe` is the same artifact** that CI built from the
  tagged commit. There is no second build pipeline, no third-party
  repackaging, and no post-build modification.
- **No telemetry, no network calls** outside what the managed child process
  itself does. NGSM does not phone home.

### What's bundled

The single `ngsm.exe` statically links:

- The Rust standard library and the C runtime (no `MSVCRT*.DLL` dependency).
- The Slint UI framework, used under its
  [GPLv3 license](https://slint.dev/terms-and-conditions.html#gplv3).
- Standard Rust ecosystem crates (serde, time, clap, etc.) — see
  [Cargo.lock](Cargo.lock) in the repo for the exact resolved dependency
  graph.

### What's not bundled

- No telemetry SDK, no analytics, no error-reporting service.
- **No auto-updater, by design.** NGSM runs entirely offline — no update
  checks, no telemetry, no network calls outside what the managed child
  process itself does. This is a deliberate trust-model choice: an offline
  binary cannot be compromised through a hijacked update channel or a
  compromised CDN, and it removes an entire class of supply-chain risk
  between releases. Any future change here would be a deliberate design
  shift, documented in CHANGELOG and accompanied by a fresh security
  review.
- No bundled third-party services or external resources.

### Known supply-chain caveats

- The Windows resource (manifest + icon) is compiled by `rc.exe` discovered
  via the build host's `PATH`. On the CI runner this is the Microsoft-shipped
  rc.exe from the preinstalled Windows SDK on the GitHub-managed
  `windows-latest` image. Pinning a specific SDK path is on the backlog as
  a supply-chain-hygiene improvement.
- The MSRV is currently 1.90 (driven by transitive Slint deps); CI pins to
  exactly that version to prevent toolchain drift between dev and release.

### Audit history

The codebase has been through two end-to-end code reviews since v0.3.0:

- **v0.3.1 remediation cycle** — 20 findings addressed across HIGH /
  MEDIUM / LOW. See [CHANGELOG.md](CHANGELOG.md) v0.3.1 entry.
- **v0.3.2 remediation cycle** — 15 additional findings addressed. See
  CHANGELOG.md v0.3.2 entry.

Both cycles' commit history is preserved in the repository.

---

If you have questions about this document or NGSM's security posture
that don't fit the channels above, opening a regular GitHub issue is
the right place.
