# NGSM v0.3.3 quality review

This is the specification and remediation checklist for the review of the
v0.3.2 workspace at commit `4b5a14f`. It covers the nine production crates,
desktop interface, build configuration, documentation, and release path.
Historical local review notes are not the source of truth for this pass.

Four independent domain reviews cover runtime supervision, Windows and
registry contracts, management interfaces, and desktop behavior. The
architect separately evaluates proposed findings, checks their failure
paths and acceptance criteria, and owns integrated/release validation.
Speculative issues and unsupported-platform behavior are not accepted as
Windows product defects without a concrete failing contract.

Checked items denote implemented remediation with independent code and
local acceptance evidence. Publication is a separate final gate: the
release page and its `BUILD-INFO.json` identify the shipped tag, commit,
toolchain, and artifact integrity records.

## Remediation checklist

- [x] REL-01: Build release assets from matching tagged, bundled sources.
- [x] REL-02: Embed Cargo-derived Windows executable identity.
- [x] REL-03: Correct the leading-hyphen application-argument example.
- [x] REL-04: Explain asynchronous SCM control completion.

## Release and usage specifications

### REL-01 - Traceable, complete release assets (medium)

**Evidence:** The existing workflow only validates pull requests, does not
use `--locked`, does not exercise the optional CLI broker configuration,
and has no tag-triggered packaging. The v0.3.2 GitHub release contains only
`ngsm.exe`, with no checksum manifest, build metadata, or dependency-source
bundle. A source tag alone does not establish which sources were compiled
into a manually uploaded binary.

**Required behavior:** Default and broker-enabled configurations must pass
the existing Windows quality gates using the declared minimum Rust version
and committed dependency lockfile. A release tag, Cargo version, and Windows
and CLI executable versions must agree. Package only a clean, committed
tree. Include the exact tracked source, vendored dependency source/license
files, and the static-CRT Cargo configuration; build the shipped binary
from those bundled sources with Cargo network access disabled.

**Acceptance:** Publish a draft containing the executable, source archive,
license notices, package inventory, build information, and SHA-256 manifest.
Reject dirty or mismatched source/tag/version inputs and existing output
directories rather than overwriting artifacts. Verify the uploaded asset
hashes and release target independently before making the release public.
An empty managed-service list must pass the executable smoke check.
Record the actual toolchain, target, commit, and CI run without claiming
Authenticode signing or universal byte-for-byte reproducibility.

### REL-02 - Windows executable identity (low)

**Evidence:** `app.rc` previously contained only an icon. Reading Windows
`VersionInfo` from the existing executable returned empty file version,
product version, description, and original filename.

**Required behavior:** Derive `VERSIONINFO` from Cargo's package version,
without a second hard-coded release number. Preserve the existing icon
and Windows-target resource-compilation gate. Reject numeric version
components that cannot be represented in Windows' 16-bit fields.

**Acceptance:** The rebuilt executable reports matching Cargo, CLI,
`FileVersion`, and `ProductVersion` values; `OriginalFilename` is
`ngsm.exe`, and the product has a meaningful Windows description.

### REL-03 - Leading-hyphen child arguments (low)

**Evidence:** The README's `--app-parameters "--flag"` example is rejected
by Clap. An independent isolated-service attempt using a leading `-NoLogo`
argument failed at parsing, before service creation. Shell quoting does
not make a leading option token an accepted value for this option.

**Required behavior:** Show `--app-parameters="..."` and explain the equals
form for arguments beginning with a hyphen. Preserve the established CLI
parsing contract rather than changing unrelated option semantics.

**Acceptance:** The documented shape is accepted by the actual executable
and successfully installs the isolated PowerShell child fixture.

### REL-04 - Asynchronous service controls (low)

**Evidence:** An isolated fixture's `stop` command returned after SCM
accepted the request. An immediate `remove` correctly refused while the
service was still stopping; another stop request during `StopPending` was
also refused by SCM. Child termination is not itself evidence that SCM has
already reached `Stopped`.

**Required behavior:** Document request acceptance versus transition
completion for `start`, `stop`, `pause`, and `continue`. Require checking
the final state before dependent actions, especially removal or runner
replacement. Do not change the established asynchronous API implicitly.

**Acceptance:** A live fixture waits for terminal SCM states and completes
install, recovery editing, native description editing, repair, start,
shared stdout/stderr logging, manual online rotation, restart, stop, and
removal. Confirm that the old child exits on restart and stop. Use unique
service names and protected fixture directories; never control existing
user services, and remove each fixture service and directory.

## Desktop specifications and checklist

Scope: `crates\servicemanager-gui\src` and `crates\servicemanager-gui\ui`.
Each item includes the observed defect, required behavior, and regression
criteria. Completion includes checking the production wiring, not just an
isolated helper that the application does not call.

- [x] **GUI-01 (medium), asynchronous modal identity.** A delayed Processes result can replace a newer Install/Edit/Remove/Warnings modal. Give both successful and failed requests a modal generation; only a matching response may populate the modal. Cover A-to-B requests, cancellation while loading, replacement by every modal kind, and protection of newer fields/passwords.
- [x] **GUI-02 (medium), queue rejection ownership.** The common send helper clears an unrelated modal's busy flag while log/recovery views can remain indefinitely Loading/Saving. Return send failure to the initiating caller; clear only its own pending token/state and show its own retryable error. Test full/disconnected queues, an accepted install plus rejected refresh, and successful retry without duplicate mutation.
- [x] **GUI-03 (medium), recovery save identity.** A save for service A can overwrite service B's editor status, or an older generation of A. Associate save results with service and form/request generation, bound duplicate submissions, and preserve attributable global outcomes. Test service switches, reload during save, stale success/error, and failed enqueue.
- [x] **GUI-04 (medium), actual recovery reload.** Reload reconstructs cached scan data instead of rereading current registry policy. Add an asynchronous backend read with generation protection and clear error/loading behavior; do not overwrite a newer draft. Test cache P0/backend P1, reload after save, service switching, read failure, and edits or disabled editing during an outstanding read.
- [x] **GUI-05 (medium), numeric recovery rows.** `01`, `+1`, and `-0` are stored under spellings that runtime lookup never uses, and semantic duplicates bypass validation. Canonicalize parsed signed-32-bit values before duplicate detection and saving. Cover aliases, negative values, extrema, overflow, and duplicate numeric identities; coordinate the shared boundary with OP-04/PL-13.
- [x] **GUI-06 (medium), log snapshot identity.** Old lines are displayed under a newly selected service/stream while a read is pending. Bind content/results to monotonic request identity and clear or honestly label the previous snapshot. Test service changes, stdout-to-stderr, A-to-B-to-A, failed enqueue/read, and the newest successful response.
- [x] **GUI-07 (medium), actual recovery classification.** A genuinely recovering NGSM supervisor remains SCM Running, which the old classifier excludes. Use the latest valid lifecycle state and recorded retry duration; a successful start/restart or stopped supervisor ends recovery. Test the observed Running/ChildExited/Throttled sequence, long delays, Ignore, explicit stop, and future timestamps.
- [x] **GUI-08 (medium), missing availability coverage.** No usable history becomes a false 100% availability value and chart. Track coverage separately from I/O failure and service count; show unknown/no chart when the managed fleet lacks usable timelines. Test empty, malformed, future-only, partial-fleet, and genuinely continuously running histories.
- [x] **GUI-09 (medium), state before the history boundary.** Dropping a retained pre-window start turns 29 up days out of 30 into 0%. Retain the nearest relevant pre-window state and consume it as the boundary state. Test Started at -31 days/Stopped at -1 day (29/30), stopped seeds, continuous uptime, exact boundaries, missing seeds, and daily buckets.
- [x] **GUI-10 (medium), historical uptime under transitions.** A current Paused/pending snapshot erases an entire previously open uptime interval. Preserve observed history or explicitly mark an unknowable tail; never invent retroactive downtime. Test Running-to-Paused-to-Running, transitional states, and unchanged closed intervals.
- [x] **GUI-11 (medium), real read budgets.** Seeking from a metadata snapshot does not bound later reads from a growing file. Limit all tail/history readers to the captured byte window, including partial-line handling. Test growing/infinite readers, giant unterminated lines, truncation/rotation, UTF-16 alignment, and the existing 400-line tail contract.
- [x] **GUI-12 (medium), bounded variable-height layout.** Recovery rows and twelve Recent Events can push controls beyond the viewport. Make variable content scrollable while keeping relevant headers/actions reachable. Check minimum/default windows with 0/1/30 recovery rows and 0/12 events, including last-row edit/remove behavior.
- [x] **GUI-13 (medium), accepted mutation outcomes.** Dismissing a pending modal discards its eventual outcome and cache refresh, although the mutation still runs. Freeze submitted fields/dismissal as appropriate, but always retain an attributable outcome and refresh successful mutations independently of modal identity. Test stale success/error with auto-refresh off and a newer modal.
- [x] **GUI-14 (medium), durable action status.** A routine Services result can overwrite an error/progress message in the same drain before it is rendered. Separate scan summaries from bounded operation status or prioritize the latter. Test Error-then-Services, refresh during a pending action, post-success refresh, next explicit action, and reachable scan warnings.
- [x] **GUI-15 (low), atomic preferences.** Direct overwrite can truncate the last good preferences or mix concurrent writers. Prepare a complete sibling file and atomically replace the destination, cleaning only owned staging files. Test exact old-byte preservation on preparation/replacement failures, concurrent complete snapshots, and ordinary round trips away from real APPDATA.
- [x] **GUI-16 (low), cleared account feedback.** Clearing a populated account silently means unchanged while other edits succeed. Reject the newly blank identity with explicit guidance rather than silently changing privileges or reporting an unexplained no-op. Test explicit LocalSystem, unchanged accounts, password-only changes, and secret-free errors.
- [x] **GUI-17 (low), disabled restart gating.** A Running/Paused service can have Disabled startup, yet Restart remains enabled. Require both a stoppable state and enabled startup; retain Stop and backend preflight. Test disabled live/pending services, enabled services, stopped services, and existing elevation/ownership gates.
- [x] **GUI-18 (low), historical local time.** The current UTC offset misformats retained events from another daylight-saving season. Look up the offset at each event instant. Test different seasonal offsets with an injected provider, non-DST behavior, lookup failure, and malformed timestamps without changing machine timezone.
- [x] **AR-02 (medium), Windows service identity in history.** Case-sensitive event matching loses history when the same SCM service is invoked/repaired under a different spelling. Associate names with Windows ordinal case-insensitive semantics without merging distinct linguistic spellings or adding native calls per record/service pair. Test ASCII/non-ASCII equivalents, mixed-spelling boundary/retry events, counts/availability consistency, and distinct sharp-s/SS names.

## Windows and registry specifications and checklist

Scope: `servicemanager-core`, `servicemanager-win32`, and
`servicemanager-registry` under `crates`. Registry fixtures must use unique
owned HKCU locations unless an explicitly isolated SCM acceptance case
requires HKLM.

- [x] **PL-01 (high), executable-only ownership.** Runner-looking arguments or directory fragments classify native executables as managed. Restrict fallback parsing to the executable prefix, preserve genuine legacy unquoted runner paths conservatively, and reject ambiguous native authorization. Test quoted/native commands with full runner-path arguments, directory fragments, case/separator variants, and lifecycle/removal ownership decisions.
- [x] **PL-02 (high), persist the validated path.** ACL validation checks a canonical target but ImagePath stores the original replaceable alias. Return and serialize the exact validated canonical path using strict, lossless conversion. Cover differing aliases, junction/symlink fixtures when supported, trusted/untrusted targets, and argument quoting in install and repair.
- [x] **PL-03 (high), volume-root replacement safety.** The ACL chain omits the volume root, whose delete-child rights can replace protected descendants. Include roots using an appropriate dangerous-rights policy without rejecting harmless create-sibling-directory grants. Test ordinary/extended roots, a runner directly under a root, ownership/DACL takeover, delete-child rights, and normal Program Files installation.
- [x] **PL-04 (medium), case-insensitive hook reconciliation.** Registry-preserved casing can cause a just-written hook to be deleted as stale. Reconcile logical event/action identity case-insensitively and reject conflicting duplicate pairs before writes. Test casing-only changes in real HKCU keys, multiple actions, stale pruning, and first-write duplicates.
- [x] **PL-05 (medium), representable multi-string entries.** An interior empty entry encodes a premature block terminator and makes configuration unreadable. Reject every empty/NUL-containing entry before any full write or service creation; allow an empty vector and nonempty `KEY=` entries. Verify leading/middle/trailing/sole empties leave all prior values/subtrees unchanged.
- [x] **PL-06 (medium), lossless environment codec.** Unknown backslash escapes erase Windows path separators and trimming erases significant value whitespace. Preserve unknown escapes and entry data while retaining the established comma/backslash escaping grammar. Test normal paths, escaped commas/backslashes/UNC values, trailing backslashes, whitespace, empty values, and exact get/set round trips.
- [x] **PL-07 (medium), targeted corruption repair.** Set/unset/reset decode the whole configuration before checking ownership, so they cannot repair an unrelated corrupt optional field. Check only a strict nonempty Application marker for targeted mutation and validate the replacement first. Test corrupt optional strings/numbers/multi-strings, unrelated corruption, and refusal of missing/empty/wrong-type markers or removal of Application.
- [x] **PL-08 (medium), standard empty REG_MULTI_SZ.** A valid double-NUL empty block is rejected. Accept standard and previously supported empty encodings plus NUL padding, while still rejecting nonzero trailing data, missing termination, odd lengths, and malformed UTF-16. Cover a complete configuration containing externally written empty environment values.
- [x] **PL-09 (medium; also OP-03), owned install rollback.** Description setup can fail after CreateService succeeds, leaving an unconfigured service. Roll back only the newly created service through its authorized handle, with both primary and rollback failures visible. Inject create/description/delete failures; never delete an existing-name service and retain managed-config-failure rollback.
- [x] **PL-10 (low), native string preflight.** NUL in display/description/command strings truncates data at Win32 boundaries. Validate all native request strings before any SCM mutation, sharing the pure preflight with ops. Test mixed updates, Unicode, valid empty description clearing, and password-redacted errors.
- [x] **PL-11 (medium), dependency kind preservation.** A service dependency beginning with `+` is silently encoded as a load-order group. Reject this unrepresentable service-name shape before mutation and keep explicit groups separate. Test solitary/leading plus, normal mixed lists, and double-NUL clear encoding.
- [x] **PL-12 (high), terminal control delivery.** A full ordinary queue drops Stop/Shutdown while returning success. Provide bounded, nonblocking terminal delivery/coalescing independent of ordinary capacity; treat overflow/disconnection honestly and avoid queuing Interrogate unnecessarily. Test an undrained queue, repeated terminal controls, overflow, receiver teardown, and normal status reporting.
- [x] **PL-13 (medium), canonical exit-code identity.** Registry aliases and unsigned DWORD spellings fail exact signed runtime lookup. Normalize the 32-bit numeric identity, preserving legacy unsigned bit patterns, and reject conflicting aliases. Test signed/unsigned extrema, `0xC0000005`'s decimal spellings, leading/sign aliases, default representations, and invalid inputs.
- [x] **PL-14 (medium), complete pre-write validation.** Invalid AppExit names are found after scalar values have changed. Validate/normalize all exit/default/hook/string invariants before any value or subtree creation, with a defensive low-level invariant too. Verify exact unchanged prior scalars/subtrees for invalid keys and valid read-back default mirrors.
- [x] **PL-15 (medium), strict registry-name decoding.** Lossy UTF-16 names can skip or alias stored keys before reopening/deletion. Decode owned names strictly and return contextual corruption errors. Test unpaired-surrogate key/value fixtures, replacement-named neighbors, and valid Unicode including a genuine replacement character.
- [x] **PL-16 (medium), expandable-string intent.** REG_EXPAND_SZ is read as plain text and later downgraded to REG_SZ. Preserve raw text/type through unrelated edits and resolve marked values only in the effective service context before use. Keep REG_SZ percent text literal. Test application/directory/parameters and relevant streams/hooks, different service environments, unusable expansion, and raw type preservation.

## Management and broker specifications and checklist

Scope: `servicemanager-ops`, CLI runtime, and `servicemanager-broker`.
Public safety preconditions must agree across GUI, CLI, broker, and direct
shared-operation calls.

- [x] **OP-01 (medium), path-only stream edits.** Rebuilding IoStream erases sharing/disposition/flags/copy policy. Change only an existing stream's path; construct defaults only for a new stream and clear the whole stream only explicitly. Test changed/unchanged paths, both outputs, all four retained options, None/empty values, and invalid-path preflight.
- [x] **OP-02 (high), mixed edit failure semantics.** Managed fields commit before native validation/failure, without restoration. Validate the complete native request before writes, retain the original managed snapshot, restore it on later native failure, and report rollback/partial-native outcomes honestly. Test zero-write rejection, managed failure, native failure, rollback failure, and successful unrelated-field preservation.
- [x] **OP-04 (medium), shared per-code input validation.** The shared validator accepts aliases that runtime exact lookup cannot use. Newly entered per-code keys must equal canonical signed decimal before persistence, with useful canonical-spelling guidance. Test aliases/extrema and every front end; GUI-normalized and registry-normalized legacy keys remain valid.
- [x] **OP-05 (medium), safe force-native restart.** Disabled live services are stopped before the inevitable failed start. Share disabled preflight and restart sequencing rather than duplicating divergent loops. Test Disabled Running/Paused/Stopped with no destructive calls, enabled flows, stop errors, and CLI/broker timeout behavior.
- [x] **OP-06 (medium), truthful removal preservation.** DeleteService removes the service key and its subkeys regardless of NGSM's explicit scrub flag. Reject unsupported no-purge preservation before mutation and direct the operator to export/backup first. Test fail-before-delete and unchanged default/force-native safeguards; deferred handle closure is not permanent preservation.
- [x] **OP-07 (medium), coherent concurrent mutations.** Full read/merge/write cycles overwrite independent successful edits, including CLI recovery's earlier read. Hold one shared, reentrant, bounded cross-process per-service guard across the entire operation and rollback, with all registry writers participating. Test disjoint field updates, recovery merging, single-value writes, case aliases, independent services, and rollback ordering.
- [x] **OP-08 (high), broker shutdown versus admission.** Separate idle/count snapshots can terminate a newly admitted operation or its reply. Atomically coordinate admission, completion activity, active lifetime, and shutdown claim; no handler may start after closing. Test both admission and completion races, long work, errors/unwind, response lifetime, and genuine idle expiry without exiting a unit-test process.
- [x] **OP-09 (medium), terminal response delivery.** DisconnectNamedPipe discards unread busy/auth/malformed responses even after successful WriteFile. Drain terminal frames before intentional disconnect with actual bounded cancellation, not an unbounded flush or unbounded helper threads. Test delayed/fragmented readers, non-readers, deadline release, handle cleanup, and ordinary authenticated multi-request traffic.
- [x] **OP-10 (low), negative mapping argument syntax.** The ordinary split `--exit-action "-1=exit"` form is rejected although signed codes are supported. Allow leading hyphens for this value-taking option and retain semantic validation. Test minimum signed values, repeated mappings, equals form, malformed values, and subsequent genuine flags.

## Runtime specifications and checklist

Scope: `servicemanager-supervisor`, `servicemanager-runner`, and narrowly
required Job Object/process-handle helpers. Fault injection and timeout
tests must be bounded and must never target an unrelated process.

- [x] **RT-01 (high), racing stop/exit bookkeeping.** An if-let MutexGuard survives into a callback that locks it again; a separate publication gap can lose the exit. Consume state outside the guard and coordinate generation observations so exit bookkeeping and Exit/Post occur exactly once. Test the actual stop path with a bounded timeout, watcher interposition, and a late queued exit.
- [x] **RT-02 (high), definitive pause/continue outcomes.** Timed-out queued requests execute after SCM has reported the old state. Cancel with confirmed non-execution or retain a definitive pending transition, including the execution/deadline race. Test delayed hooks, both directions, Stop while pending, disconnection/completion, and no stale transition on a later generation.
- [x] **RT-03 (high), pause intent across generations.** Pause with no live root is acknowledged but the next retry runs anyway. Persist pause intent independently of a child and gate creation/resumption until Continue. Test backoff expiry, failing starts, zero delay, duplicate controls, and Stop while paused without a child.
- [x] **RT-04 (medium), contained transactional suspension.** Partial suspend/resume failure and incomplete ancestry snapshots contradict reported stable state. Track owned increments with pinned, verified job-member handles, roll back failed batches, and report degraded rollback failure explicitly. Test disappearing/added members, surviving descendants, partial failures, duplicates, and no unrelated PID reuse target.
- [x] **RT-05 (high), cancellation before retry.** Expired/zero waits can bypass queued Stop, and positive-delay Stop paths omit lifecycle side effects. Check committed cancellation before every hook/spawn and delay completion; unify accepted stop bookkeeping. Test zero/positive waits, missing applications, attach/resume failure, duplicate Stop, and nonterminal traffic without starvation.
- [x] **RT-06 (medium; also AR-01), truthful lifetime/minimum delay.** Short-lived children ignore the configured mandatory delay and delayed hooks inflate measured lifetime. Capture actual start/exit observations and use at least the greater applicable delay. Test the delay matrix, hook latency, event-time ordering, and the real persisted-600000ms fixture; long waits remain interruptible.
- [x] **RT-07 (medium), startup liveness.** Start/Post completion can announce a generation already known dead. Tie readiness to that generation's observed liveness and apply terminal/retry policy instead. Define initial Ignore/quiesced readiness explicitly. Test delayed Post plus Restart/Exit/Suicide/Ignore, exactly one later valid acknowledgement, and normal startup.
- [x] **RT-08 (high), output generation ownership.** Detached readers lose final output and retain old rotation owners into the next generation. Own and drain readers after terminating contained writers, before reuse or completed stop; escalate stalled I/O under a bound. Test final markers, rapid restarts, shared outputs, descendants, partial startup, and no surviving old-generation writer.
- [x] **RT-09 (high), recoverable rotation destination.** Failed reopen leaves a disposable scratch file as the supposedly successful destination. Use explicit valid/recovery state and preserve every acknowledged byte in the active/defined archive location. Inject rename/reopen failure and recovery, including on-demand-only rotation, distinct sinks, and repeated failure.
- [x] **RT-10 (high), CopyAndTruncate semantics.** The option unconditionally truncates at startup without copying. Archive successfully before truncation only when rotation occurs, preserve append defaults, and keep old data on archive failure. Test disabled/below-threshold rotation, retained external handles, failed copy/rename, shared outputs, and online behavior or explicit unsupported combinations.
- [x] **RT-11 (medium), actual log destination identity.** String lowercasing misses dot/junction aliases and can conflate case-sensitive files. Coordinate real equivalent destinations and keep distinct files/streams distinct; diagnose unsafe alias/option combinations rather than corrupting data. Test dot/parent/trailing-dot aliases, supported link fixtures, rotation through both streams, and distinct destinations.
- [x] **RT-12 (medium), hook shell quoting.** Quoted executable plus quoted arguments fail cmd parsing. Use the documented `/d /s /c` outer-command convention, preserving inner command semantics and containment, and report nonzero completion. Test a benign executable in a spaced path, quoted arguments/metacharacters, failure, timeout, and no ambient AutoRun.
- [x] **RT-13 (high), SCM-observable Suicide.** Nonzero SERVICE_STOPPED does not trigger recovery when non-crash failure actions are disabled. Use an intentional crash-style terminal outcome after cleanup without reporting STOPPED; keep explicit Stop/Exit clean and apply the rule during startup too. Test the decision path and isolated SCM recovery with both flag settings and zero/nonzero child exits.
- [x] **RT-14 (medium), shared-log authorization.** Creator-default mutex ACLs and ALL_ACCESS opens reject other supported service identities. Use explicit minimal coordination access or file-authorized synchronization, scoped to the destination and without broadening content permissions. Test supported/denied tokens, cross-process writes/rotation, abandonment, timeouts, and separate destinations.
- [x] **RT-15 (medium), effective resource settings.** Persisted priority and affinity are never applied. Validate and apply supported settings to the suspended child before execution, preserve unspecified defaults, and make group/width/unavailable-CPU limits explicit. Test effective non-default priority/CPU subset, invalid inputs, permission failure, and retry/Stop behavior.
- [x] **RT-16 (medium), effective stream/log options.** Persisted open options, timestamping and delay silently do nothing. Honor supported options or explicitly diagnose/reject unsupported non-default combinations, preserving safe defaults and read-only stdin. Test CREATE_NEW/OPEN_EXISTING, sharing/flags, rotation recovery, conflicting shared-stream options, timestamp/encoding or stated limitations, and delay/cancellation.
- [x] **RT-17 (medium), completion under control traffic.** Finished supervisors are checked only after a quiet receive timeout. Check completion independently on every runner iteration and around transitions. Test continuous controls with normal/error/panic completion, terminal reporting once, and priority of an already accepted Stop.
- [x] **RT-18 (medium), consistent rotation hooks.** Automatic/offline rotations bypass hooks while manual no-ops/failures can report Post. Define one logical lifecycle for actual rotations with hooks outside sink locks. Test all rotation modes, ordering, shared/separate outputs, no-op/failure semantics, hook output, and bounded cancellation without recursive deadlock.
- [x] **RT-19 (medium), recoverable pipe logging.** One sink error permanently closes the child's pipe. Retain connectivity under a bounded buffering/backpressure or observable-loss policy, retry safely, and report read errors. Test one-shot/repeated/partial failures, recovery without duplicate acknowledged prefixes, continued child execution, dropped-byte accounting, and bounded Stop.
- [x] **RT-20 (low), persistent runtime diagnostics.** Host stderr is not the configured child's stderr under SCM. Provide a nonrecursive, bounded persistent diagnostic path while retaining interactive stderr. Test startup/spawn, hook nonzero/timeout, rotation/reopen and event-log failure reporting, with useful context, secret redaction, and harmless diagnostic-sink failure.
- [x] **RT-21 (high), retained process identity.** A descendant membership check closes its handle before a PID-based control reopens the target, permitting identity substitution after exit. Validate membership and perform control through the same owned handle; do not treat a bare bool as a lifetime guard. Test deterministic identity replacement, denial/non-members, and owned-worker controls without stressing or touching unrelated processes.

## Shared implementation contracts

The registry mutation guard covers the complete read/merge/write and
rollback interval, including the CLI recovery merge that previously
preceded save. Registry single-value writers participate in the same
Windows-case-consistent protocol. Native edit validation is a pure shared
preflight, and post-create rollback uses only a proven newly created
service handle.

Expandable strings retain raw intent in the domain model and registry.
Expansion belongs to the service's effective environment, with dynamic
hook context resolved at invocation; it must not persist the GUI user's
environment as service configuration. New per-code recovery inputs use
canonical signed decimal while legacy DWORD registry spellings preserve
their 32-bit identity.

The environment text format keeps its established `\,` and `\\` escapes.
Unknown escapes and significant whitespace are preserved. An unescaped
UNC prefix is ambiguous with doubled-backslash escaping, so the contract
uses the documented escaped representation rather than claiming both
interpretations or introducing a second encoding format.

Availability is an event-derived process-lifetime estimate, not an
application health probe. Missing observations and ambiguous tails must
not be presented as certain health or retroactive downtime. NGSM's
Running-supervisor state during child retry remains deliberate.

## Duplicate reports and independent evidence

`OP-03` is tracked by `PL-09`; both describe the same owned post-create
description rollback gap. `AR-01` is tracked by `RT-06`; the architect's
real service fixture independently reproduced the same minimum-delay
violation. These are not additional independent fixes.

Before implementation, the architect added and ran retained regressions
that reproduced desktop, registry, ownership, ACL, input-preflight,
deadlock, cancellation and log-data-loss defects while the original
tests continued to pass. Separate live probes used only GUID-named
protected service fixtures, verified child cleanup, and never controlled
pre-existing user services. The release packager was also rehearsed in an
isolated tagged checkout, built its vendored source offline, and had its
payload hashes and source contents independently inspected.

Final review also exercised failed/cancelled Continue with newly born job
members, invalid terminal-hook environments, existing-only output opens,
and lossless canonical log paths. The release candidate passed both Cargo
feature configurations, strict formatting/Clippy gates, real protected
service lifecycle/configuration scenarios, all four SCM Suicide recovery
flag/exit-code combinations, and native broker transport/idle acceptance.
Subprocess-helper tests marked ignored in ordinary test enumeration are
invoked explicitly by their owning native regression tests.
