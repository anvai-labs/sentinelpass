//! Fuzz target: IPC frame decode (WBS-903 / TV-003).
//!
//! Every byte an IPC peer sends flows through one of these parsers:
//! - `parse_hello` / `parse_accept` / `is_session_hello` (session handshake
//!   JSON, before any keys exist);
//! - `SessionCrypto::open` (counter extraction, replay/refusal state
//!   machine, AAD-bound AES-256-GCM open);
//! - `decrypt_windows_ipc_frame` (legacy Windows AES-256-GCM frame parse).
//!
//! Invariants: a hostile frame may fail authentication, exhaust its
//! counters, or be rejected for length — it must never panic, mutate
//! counter state on a REFUSED frame, or leak more than a typed error.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinelpass_protocol::session;
// The legacy Windows frame surface is cfg(windows) in the protocol crate,
// so it is fuzzed only on Windows runners; the session surface below is
// cross-platform.
#[cfg(windows)]
use sentinelpass_protocol::windows_frame;

/// Fixed fuzz token (non-production; the key schedule normalizes it).
const FUZZ_TOKEN: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fuzz_target!(|data: &[u8]| {
    // Handshake parses (pre-key surface).
    let _ = session::parse_hello(data);
    let _ = session::parse_accept(data);
    let _ = session::is_session_hello(data);

    // Session frame open against a server endpoint. Feeding the SAME bytes
    // twice also exercises the replay-refusal path (second attempt must be
    // refused as a non-newer counter or fail auth — never panic).
    let (_, cr) = session::new_hello();
    let (_, sr) = session::new_accept();
    if let Ok((c2s, s2c)) = session::derive_directional_keys(FUZZ_TOKEN, &cr, &sr) {
        let mut server = session::SessionCrypto::server(c2s, s2c);
        let _ = server.open(data);
        let _ = server.open(data);
    }

    // Windows named-pipe frame decode (Windows builds only).
    #[cfg(windows)]
    let _ = windows_frame::decrypt_windows_ipc_frame(FUZZ_TOKEN, data);
});
