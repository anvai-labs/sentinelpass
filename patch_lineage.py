p = '/Users/vijaysingh/code/sentinelpass/.claude/worktrees/agent-a91a2e8ade06c0dd8/sentinelpass-core/src/sync/engine.rs'
s = open(p).read()

# 1. Pull: fetch high-water with the cursor; refuse rollback; update both after commit.
old = '''    async fn pull_changes(&self, dek: &DataEncryptionKey) -> Result<u64> {
        let mut cursor = {
            let db = self
                .db
                .lock()
                .map_err(|_| DatabaseError::LockPoisoned("pull seq".to_string()))?;
            let config = SyncConfig::load(db.conn())?;
            config.last_pull_sequence
        };'''
new = '''    async fn pull_changes(&self, dek: &DataEncryptionKey) -> Result<u64> {
        let (mut cursor, mut high_water) = {
            let db = self
                .db
                .lock()
                .map_err(|_| DatabaseError::LockPoisoned("pull seq".to_string()))?;
            let config = SyncConfig::load(db.conn())?;
            (config.last_pull_sequence, config.lineage_high_water)
        };'''
assert old in s, "pull head"
s = s.replace(old, new)

# 2. Refuse lineage rollback BEFORE processing the page.
old2 = '''            if response.cursor.as_u64() <= cursor {
                return Err(PasswordManagerError::InvalidInput(
                    "Relay pull cursor did not advance".to_string(),
                ));
            }

            total_count += response.entries.len() as u64;'''
new2 = '''            if response.cursor.as_u64() <= cursor {
                return Err(PasswordManagerError::InvalidInput(
                    "Relay pull cursor did not advance".to_string(),
                ));
            }

            // WBS-613 lineage high-water (trusted state, distinct from the
            // ADR-004 epoch sidecar): a cursor BELOW the high-water means
            // the relay's log moved backwards — reset, vault swap, or a
            // different relay behind the same URL. Fail closed; re-pairing
            // is the remedy.
            if response.cursor.as_u64() < high_water {
                return Err(PasswordManagerError::InvalidInput(format!(
                    "relay lineage moved backwards: cursor {} is below the trusted \\
                     high-water {high_water}. The relay log may have been reset or the \\
                     vault swapped. Refusing to apply (re-pair under v2 to re-baseline)"
                )));
            }

            total_count += response.entries.len() as u64;'''
assert old2 in s, "cursor guard"
s = s.replace(old2, new2)

# 3. Page commit: advance the high-water WITH the cursor.
old3 = '''                let mut config = SyncConfig::load(&tx)?;
                config.last_pull_sequence = response.cursor.as_u64();
                config.save(&tx)?;

                tx.commit().map_err(DatabaseError::Sqlite)?;

                cursor = response.cursor.as_u64();'''
new3 = '''                let mut config = SyncConfig::load(&tx)?;
                config.last_pull_sequence = response.cursor.as_u64();
                config.lineage_high_water =
                    config.lineage_high_water.max(response.cursor.as_u64());
                config.save(&tx)?;

                tx.commit().map_err(DatabaseError::Sqlite)?;

                cursor = response.cursor.as_u64();
                high_water = config.lineage_high_water;'''
assert old3 in s, "page commit"
s = s.replace(old3, new3)
open(p, 'w').write(s)
print("engine lineage wired")

# 4. outbox apply_push_acks: high-water max on push response cursor.
p = '/Users/vijaysingh/code/sentinelpass/.claude/worktrees/agent-a91a2e8ade06c0dd8/sentinelpass-core/src/sync/outbox.rs'
s = open(p).read()
old5 = '''    let mut config = crate::sync::config::SyncConfig::load(&tx)?;
    config.last_push_sequence = server_cursor;
    config.save(&tx)?;

    tx.commit().map_err(DatabaseError::Sqlite)?;
    Ok(summary)
}'''
new5 = '''    let mut config = crate::sync::config::SyncConfig::load(&tx)?;
    config.last_push_sequence = server_cursor;
    // The vault log cursor reported by a push lives in the same lineage
    // domain — fold it into the trusted high-water (max).
    config.lineage_high_water = config.lineage_high_water.max(server_cursor);
    config.save(&tx)?;

    tx.commit().map_err(DatabaseError::Sqlite)?;
    Ok(summary)
}'''
assert old5 in s, "checkpoint save"
s = s.replace(old5, new5)
open(p, 'w').write(s)
print("outbox lineage wired")
