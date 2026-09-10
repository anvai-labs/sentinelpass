# engine.rs: remove leftover debug prints (review finding 8)
p = '/Users/vijaysingh/code/sentinelpass/.claude/worktrees/agent-a91a2e8ade06c0dd8/sentinelpass-core/src/sync/engine.rs'
s = open(p).read()
old = '''        engine_b.sync(&dek).await.unwrap();
        eprintln!(
            "DEBUG: log_len={} b_cursor={}",
            relay.log_len(),
            SyncConfig::load(db_b.lock().unwrap().conn())
                .unwrap()
                .last_pull_sequence
        );
        eprintln!(
            "DEBUG: b_rows={:?}",
            db_b.lock()
                .unwrap()
                .conn()
                .query_row("SELECT COUNT(*) FROM entries", [], |r| r.get::<_, i64>(0))
        );
        let (b_state, b_acked) = row_bookkeeping(&db_b, &sync_id);'''
new = '''        engine_b.sync(&dek).await.unwrap();
        let (b_state, b_acked) = row_bookkeeping(&db_b, &sync_id);'''
assert old in s, "debug block not found"
s = s.replace(old, new)
open(p, 'w').write(s)
print("engine debug removed")

# relay: complete-old covers vault_epochs (review finding 4)
p = '/Users/vijaysingh/code/sentinelpass/.claude/worktrees/agent-a91a2e8ade06c0dd8/sentinelpass-relay/src/handlers/sync_v2.rs'
s = open(p).read()
old = '''        let assert_complete_old = |state: &RelayAppState, vault_id: &str, device_id: &Uuid| {
            let conn = state.storage.conn().unwrap();
            let (log, objects, results, counter, device_seq): (i64, i64, i64, i64, i64) = conn
                .query_row(
                    "SELECT \\
                         (SELECT COUNT(*) FROM sync_mutations_v2), \\
                         (SELECT COUNT(*) FROM sync_entries_v2), \\
                         (SELECT COUNT(*) FROM mutation_results), \\
                         (SELECT COALESCE((SELECT current_sequence FROM sequence_counters WHERE vault_id = ?1), 0)), \\
                         (SELECT COALESCE((SELECT last_sequence FROM device_sequences WHERE device_id = ?2), 0))",
                    rusqlite::params![vault_id, device_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .unwrap();
            assert_eq!(
                (log, objects, results, counter, device_seq),
                (0, 0, 0, 0, 0),
                "a failed push must roll back EVERYTHING"
            );
        };'''
new = '''        let assert_complete_old = |state: &RelayAppState, vault_id: &str, device_id: &Uuid| {
            let conn = state.storage.conn().unwrap();
            let (log, objects, results, counter, device_seq, epoch): (
                i64,
                i64,
                i64,
                i64,
                i64,
                i64,
            ) = conn
                .query_row(
                    "SELECT \\
                         (SELECT COUNT(*) FROM sync_mutations_v2), \\
                         (SELECT COUNT(*) FROM sync_entries_v2), \\
                         (SELECT COUNT(*) FROM mutation_results), \\
                         (SELECT COALESCE((SELECT current_sequence FROM sequence_counters WHERE vault_id = ?1), 0)), \\
                         (SELECT COALESCE((SELECT last_sequence FROM device_sequences WHERE device_id = ?2), 0)), \\
                         (SELECT COALESCE((SELECT key_epoch FROM vault_epochs WHERE vault_id = ?1), 0))",
                    rusqlite::params![vault_id, device_id.to_string()],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ))
                    },
                )
                .unwrap();
            assert_eq!(
                (log, objects, results, counter, device_seq, epoch),
                (0, 0, 0, 0, 0, 0),
                "a failed push must roll back EVERYTHING (all six stores)"
            );
        };'''
assert old in s, "relay assert not found"
s = s.replace(old, new)
open(p, 'w').write(s)
print("relay complete-old extended to vault_epochs")
