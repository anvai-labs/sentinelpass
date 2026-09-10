p = '/Users/vijaysingh/code/sentinelpass/.claude/worktrees/agent-a91a2e8ade06c0dd8/sentinelpass-core/src/sync/engine.rs'
s = open(p).read()

old = '''            // The PAGE transaction is the unit under test; sync() has writes
            // AFTER it (the last_sync_at checkpoint), so a denial that hits
            // those surfaces as Err with the page already complete-new.
            match (result, cursor) {
                (Err(_), 0) => {
                    assert!(denied, "harness bug at write {fail_at}");
                    injected_failures += 1;
                    let (entries, dead): (i64, i64) = db
                        .lock()
                        .unwrap()
                        .conn()
                        .query_row(
                            "SELECT (SELECT COUNT(*) FROM entries), \\
                                    (SELECT COUNT(*) FROM sync_dead_letter)",
                            [],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .unwrap();
                    assert_eq!(
                        (entries, dead),
                        (0, 0),
                        "complete-old: no partial page state at write {fail_at}"
                    );
                }
                (Err(_), 2) => {
                    assert!(denied, "harness bug at write {fail_at}");
                    injected_failures += 1;
                }
                (Ok(_), 2) => {
                    // Complete-new AND no swallowed denial: the clean run
                    // must perform exactly baseline_writes writes.
                    assert_eq!(
                        guard.seen(),
                        baseline_writes,
                        "a denial was swallowed somewhere in the page"
                    );
                    let reason: String = db
                        .lock()
                        .unwrap()
                        .conn()
                        .query_row(
                            "SELECT COALESCE((SELECT reason FROM sync_dead_letter LIMIT 1), 'none')",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap();
                    eprintln!("SWEEP DEBUG: entries={entries} dead={dead} reason={reason}");
                    assert_eq!(entries, 1, "complete-new: the applicable row applied");
                    assert_eq!(dead, 1, "complete-new: the poison dispositioned");
                    assert_eq!(
                        poison_rows, 0,
                        "the dead-lettered object must leave NO rows"
                    );
                    break;
                }
                other => panic!("unexpected outcome at write {fail_at}: {other:?}"),
            }'''
new = '''            // The PAGE transaction is the unit under test; sync() has writes
            // AFTER it (the last_sync_at checkpoint), so a denial that hits
            // those surfaces as Err with the page already complete-new. A
            // denial hitting an APPLY write inside a savepoint surfaces as
            // Ok too — the savepoint rolled the blob back and the mutation
            // was dead-lettered (by design) — but the run's write count
            // inflates past the baseline, which the final branch detects.
            match (result, cursor) {
                (Err(_), 0) => {
                    assert!(denied, "harness bug at write {fail_at}");
                    injected_failures += 1;
                    let (entries, dead): (i64, i64) = db
                        .lock()
                        .unwrap()
                        .conn()
                        .query_row(
                            "SELECT (SELECT COUNT(*) FROM entries), \\
                                    (SELECT COUNT(*) FROM sync_dead_letter)",
                            [],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .unwrap();
                    assert_eq!(
                        (entries, dead),
                        (0, 0),
                        "complete-old: no partial page state at write {fail_at}"
                    );
                }
                (Err(_), 2) => {
                    assert!(denied, "harness bug at write {fail_at}");
                    injected_failures += 1;
                }
                (Ok(_), 2) if guard.seen() != baseline_writes => {
                    // A denial was absorbed by a per-blob savepoint: the
                    // dead-lettered object must have left NO rows.
                    injected_failures += 1;
                    let orphans: i64 = db
                        .lock()
                        .unwrap()
                        .conn()
                        .query_row(
                            "SELECT COUNT(*) FROM entries WHERE sync_id IN \\
                             (SELECT object_id FROM sync_dead_letter)",
                            [],
                            |r| r.get(0),
                        )
                        .unwrap();
                    assert_eq!(
                        orphans, 0,
                        "savepoint rollback: a dead-lettered object left partial rows"
                    );
                }
                (Ok(_), 2) => {
                    // Complete-new AND no swallowed denial: the clean run
                    // must perform exactly baseline_writes writes.
                    assert_eq!(
                        guard.seen(),
                        baseline_writes,
                        "a denial was swallowed somewhere in the page"
                    );
                    let (entries, dead): (i64, i64) = db
                        .lock()
                        .unwrap()
                        .conn()
                        .query_row(
                            "SELECT (SELECT COUNT(*) FROM entries), \\
                                    (SELECT COUNT(*) FROM sync_dead_letter)",
                            [],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .unwrap();
                    assert_eq!(entries, 1, "complete-new: the applicable row applied");
                    assert_eq!(dead, 1, "complete-new: the poison dispositioned");
                    break;
                }
                other => panic!("unexpected outcome at write {fail_at}: {other:?}"),
            }'''
assert old in s, "sweep match not found"
s = s.replace(old, new)
open(p, 'w').write(s)
print("sweep restructured")
