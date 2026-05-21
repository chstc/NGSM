//! Optional elevated named-pipe broker for headless automation.
//!
//! This is an opt-in component, compiled only with `--features broker`, and
//! reached through the hidden `ngsm broker` subcommand. It is *not* used by
//! the desktop GUI: the GUI runs privileged operations in-process and relies
//! on UAC elevation of the whole process instead.
//!
//! The broker exists for headless/automation callers that want to run many
//! privileged operations against a long-lived elevated process without a UAC
//! prompt per action. No in-tree launcher/client ships today — this crate is
//! the server half only — so the launcher/client contract is documented
//! here for any external automation that drives it:
//!
//! 1. The launcher generates two random values with a CSPRNG: a *capability
//!    token* (the request-auth secret, kept confidential) and a *pipe nonce*
//!    (a public value that names the pipe — not secret).
//! 2. The launcher starts `ngsm broker --owner-sid <SID> --pipe-nonce
//!    <NONCE>` **elevated**, and writes the token to the broker's stdin as
//!    the first line. The token never appears on the command line (argv is
//!    observable by other same-user processes; an inherited stdin handle is
//!    not).
//! 3. Both the launcher and any client derive the pipe name with
//!    [`pipe_name_for`]`(owner_sid, pipe_nonce)`.
//! 4. A client connects to that pipe and sends length-prefixed JSON frames
//!    (4-byte big-endian length, then body). Every request must carry the
//!    exact capability token; a bad or missing token is a terminal
//!    authentication failure and the broker drops the connection.
//! 5. The broker exits on its own after an idle period (`--idle-timeout-secs`).
//!
//! Request/response shapes live in [`protocol`]. The broker feature should be
//! kept disabled by default unless this end-to-end path is exercised by an
//! automated harness.

#![cfg_attr(not(windows), allow(dead_code, unused_imports))]

#[cfg(windows)]
mod handlers;
#[cfg(windows)]
mod pipe;
#[cfg(windows)]
mod protocol;

#[cfg(windows)]
pub use pipe::run_server;

#[cfg(windows)]
pub use protocol::pipe_name_for;

#[cfg(not(windows))]
pub fn run_server(
    _owner_sid: &str,
    _pipe_nonce: &str,
    _idle_timeout_secs: u64,
    _auth_token: &str,
) -> servicemanager_core::Result<()> {
    Err(servicemanager_core::Error::other("broker requires Windows"))
}

#[cfg(not(windows))]
pub fn pipe_name_for(owner_sid: &str, pipe_nonce: &str) -> String {
    format!("\\\\.\\pipe\\NGSM-broker-{owner_sid}-{pipe_nonce}")
}
