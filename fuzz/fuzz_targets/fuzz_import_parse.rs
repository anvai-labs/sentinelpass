//! Fuzz target: import/export parse (WBS-903 / TV-003).
//!
//! `parse_json_import_bytes` / `parse_csv_import_bytes` are the byte-level
//! entry points behind KeePass-era JSON and CSV vault imports — parsing of
//! USER-PROVIDED files into entries. Invariants: arbitrary bytes produce
//! either entries or typed errors; per-line CSV failure is bounded by the
//! 10 000-line cap; nothing panics on truncated/oversized/hostile input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinelpass_core::import_export;

fuzz_target!(|data: &[u8]| {
    let _ = import_export::parse_json_import_bytes(data);
    let _ = import_export::parse_csv_import_bytes(data);
});
