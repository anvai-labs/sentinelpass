//! SQLite-authorizer fault injection for the transactional-mutation tests
//! (SR-DATA-001 / WBS-411 acceptance: "fault injection at each statement
//! produces either the complete old or the complete new state, never a
//! partial state").
//!
//! Mechanism: [`rusqlite::Connection::authorizer`] is invoked at statement
//! PREPARE time for every action a statement performs. [`WriteFaultGuard`]
//! counts top-level write actions (`Insert` / `Update` / `Delete` —
//! `Update` fires once per updated column) and denies the `fail_at`-th one.
//! Because action indices are monotonic across the statements of a
//! sequential mutation, sweeping `fail_at = 0, 1, 2, …` until a run with NO
//! denial (`guard.seen() <= fail_at`) covers every statement: every
//! injected failure must leave the complete-OLD state (or the mutation's
//! documented degraded outcome), and the clean run proves the
//! complete-NEW state.
//!
//! VALIDITY INVARIANT: the authorizer fires only at PREPARE. rusqlite 0.30
//! prepares fresh on every `execute`/`query_row` (no statement cache unless
//! `prepare_cached` is used — this codebase uses it nowhere). A future
//! rusqlite upgrade that routes `execute` through a cache would silently
//! bypass the authorizer and gut every sweep while tests stay green; the
//! `authorizer_fires_on_every_prepare` canary test pins this.
//!
//! Trigger-internal writes carry a non-None `accessor` and are NOT counted —
//! after WBS-409 no entries trigger exists, and injection stays at top-level
//! statement granularity.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

/// A live write-fault on a connection. Read [`WriteFaultGuard::seen`] after
/// the mutation to distinguish an injected denial (`seen > fail_at`) from a
/// clean run (`seen <= fail_at`).
pub(crate) struct WriteFaultGuard {
    seen: Arc<AtomicUsize>,
}

impl WriteFaultGuard {
    /// Write actions the authorizer saw (denied or allowed).
    pub(crate) fn seen(&self) -> usize {
        self.seen.load(Ordering::SeqCst)
    }
}

/// Deny the `fail_at`-th TOP-LEVEL write action on `conn` (0-based); every
/// earlier write action is allowed. Reads and transaction control are always
/// allowed. Clear with [`clear_write_fault`].
pub(crate) fn install_write_fault(conn: &rusqlite::Connection, fail_at: usize) -> WriteFaultGuard {
    install_fault_inner(conn, fail_at, None)
}

/// As [`install_write_fault`], but only write actions against `table` are
/// counted (and denied at `fail_at`) — for pinning degraded-outcome
/// contracts where a specific statement's failure must be isolatable.
pub(crate) fn install_write_fault_on_table(
    conn: &rusqlite::Connection,
    fail_at: usize,
    table: &'static str,
) -> WriteFaultGuard {
    install_fault_inner(conn, fail_at, Some(table))
}

fn install_fault_inner(
    conn: &rusqlite::Connection,
    fail_at: usize,
    table: Option<&'static str>,
) -> WriteFaultGuard {
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    conn.authorizer(Some(move |ctx: AuthContext<'_>| {
        let is_top_level_write = matches!(
            ctx.action,
            AuthAction::Insert { .. } | AuthAction::Update { .. } | AuthAction::Delete { .. }
        ) && ctx.accessor.is_none();
        if !is_top_level_write {
            return Authorization::Allow;
        }
        if let Some(t) = table {
            let touches = match ctx.action {
                AuthAction::Insert { table_name, .. }
                | AuthAction::Update { table_name, .. }
                | AuthAction::Delete { table_name } => table_name == t,
                _ => false,
            };
            if !touches {
                return Authorization::Allow;
            }
        }
        let n = counter.fetch_add(1, Ordering::SeqCst);
        if n == fail_at {
            Authorization::Deny
        } else {
            Authorization::Allow
        }
    }));
    WriteFaultGuard { seen }
}

/// Remove any authorizer from `conn` (call in EVERY test path — success or
/// failure — so later statements are never spuriously denied).
pub(crate) fn clear_write_fault(conn: &rusqlite::Connection) {
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The harness validity canary: the authorizer must fire on EVERY
    /// prepare, including a re-preparation of the IDENTICAL SQL — rusqlite
    /// 0.30 prepares fresh per execute, but a future statement cache would
    /// silently bypass it (see the module docs' validity invariant).
    #[test]
    fn authorizer_fires_on_every_prepare() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (x INTEGER);").unwrap();
        let same_sql = "INSERT INTO t (x) VALUES (1)";

        // fail_at = 0 denies the first write; a fresh install must deny the
        // SAME SQL text again (a statement cache would have allowed it).
        let first = {
            let guard = install_write_fault(&conn, 0);
            let r = conn.execute(same_sql, []);
            clear_write_fault(&conn);
            (r, guard.seen())
        };
        let second = {
            let guard = install_write_fault(&conn, 0);
            let r = conn.execute(same_sql, []);
            clear_write_fault(&conn);
            (r, guard.seen())
        };

        assert!(first.0.is_err(), "first write must be denied");
        assert_eq!(first.1, 1, "the first prepare must have been counted");
        assert!(
            second.0.is_err(),
            "an identical re-prepared statement must ALSO be denied"
        );
        assert_eq!(second.1, 1, "the second prepare must have been counted");
    }
}
