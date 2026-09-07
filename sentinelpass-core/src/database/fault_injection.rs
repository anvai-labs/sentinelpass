//! SQLite-authorizer fault injection for the transactional-mutation tests
//! (SR-DATA-001 / WBS-411 acceptance: "fault injection at each statement
//! produces either the complete old or the complete new state, never a
//! partial state").
//!
//! Mechanism: [`rusqlite::Connection::authorizer`] is invoked at statement
//! PREPARE time for every action a statement performs. [`install_write_fault`]
//! counts top-level write actions (`Insert` / `Update` / `Delete` — `Update`
//! fires once per updated column) and denies the `fail_at`-th one. Because
//! action indices are monotonic across the statements of a sequential
//! mutation, sweeping `fail_at = 0, 1, 2, …` until the mutation first
//! SUCCEEDS covers every statement: every failing injection point must leave
//! the complete-OLD state (the transaction rolls back), and the first
//! succeeding point proves the complete-NEW state.
//!
//! Trigger-internal writes carry a non-None `accessor` and are NOT counted —
//! after WBS-409 no entries trigger exists, and injection stays at top-level
//! statement granularity.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

/// Deny the `fail_at`-th TOP-LEVEL write action on `conn` (0-based); every
/// earlier write action is allowed. Reads and transaction control are always
/// allowed.
pub(crate) fn install_write_fault(conn: &rusqlite::Connection, fail_at: usize) {
    let seen = Arc::new(AtomicUsize::new(0));
    conn.authorizer(Some(move |ctx: AuthContext<'_>| match ctx.action {
        AuthAction::Insert { .. } | AuthAction::Update { .. } | AuthAction::Delete { .. }
            if ctx.accessor.is_none() =>
        {
            let n = seen.fetch_add(1, Ordering::SeqCst);
            if n == fail_at {
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }
        _ => Authorization::Allow,
    }));
}

/// Remove any authorizer from `conn` (call in EVERY test path — success or
/// failure — so later statements are never spuriously denied).
pub(crate) fn clear_write_fault(conn: &rusqlite::Connection) {
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
}
