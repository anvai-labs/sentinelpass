//! SQLite-authorizer fault injection for relay transaction tests (WBS-606 /
//! SR-SYNC-003: "fault at every statement → complete-old or complete-new").
//!
//! Same mechanism as `sentinelpass-core/src/database/fault_injection.rs`
//! (the relay does not depend on core, so the ~40-line harness is local):
//! [`rusqlite::Connection::authorizer`] fires at statement PREPARE for every
//! action; the installed fault counts top-level write actions
//! (Insert/Update/Delete) and denies the `fail_at`-th one. Sweeping
//! `fail_at = 0, 1, 2, …` until a clean run covers every write statement of
//! a sequential mutation.
//!
//! The authorizer is CONNECTION state: install it while holding the storage
//! lock, release the lock, run the handler (it re-locks and inherits the
//! authorizer), then re-lock and clear.

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A live write fault on the relay storage connection.
pub(crate) struct WriteFaultGuard {
    seen: Arc<AtomicUsize>,
}

impl WriteFaultGuard {
    /// Write actions the authorizer saw (denied or allowed).
    pub(crate) fn seen(&self) -> usize {
        self.seen.load(Ordering::SeqCst)
    }

    /// Remove the authorizer from the connection (every test path must clear,
    /// success or failure, or later statements are spuriously denied).
    pub(crate) fn clear(&self, conn: &rusqlite::Connection) {
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    }
}

/// Deny the `fail_at`-th top-level write action on `conn` (0-based). Reads
/// and transaction control are always allowed.
pub(crate) fn install_write_fault(conn: &rusqlite::Connection, fail_at: usize) -> WriteFaultGuard {
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
        let n = counter.fetch_add(1, Ordering::SeqCst);
        if n == fail_at {
            Authorization::Deny
        } else {
            Authorization::Allow
        }
    }));
    WriteFaultGuard { seen }
}
