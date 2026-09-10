p = '/Users/vijaysingh/code/sentinelpass/.claude/worktrees/agent-a91a2e8ade06c0dd8/sentinelpass-core/src/sync/engine.rs'
s = open(p).read()

start_marker = '''    /// A version conflict where the relay is AT OR BEYOND our attempt: the
    /// push is durably rejected, the client adopts the relay's baseline, and
    /// the SAME sync's pull brings the peer's winning content down — the
    /// object converges in one cycle (full two-alternative preservation is
    /// WBS-611; this stage must at minimum never wedge).
    #[tokio::test]
    async fn conflict_rejection_converges_without_wedge() {'''
end_marker = '''    /// THE pull-then-edit acceptance (reviewer finding 1): a peer's mutation'''
end = s.index(end_marker)

new_tests = '''    /// SR-SYNC-005 (WBS-611): a push conflict where the relay is AT OR
    /// BEYOND our attempt NEVER silently adopts the relay state — the row is
    /// marked conflicted, the same-run pull stores the peer's content as the
    /// durable alternative, and keep-local resolution re-versions the local
    /// content above the peer so the next push lands cleanly. Both
    /// alternatives were preserved and user resolution drives convergence.
    #[tokio::test]
    async fn conflict_preserves_alternatives_and_resolves_keep_local() {
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device = Uuid::new_v4();
        let sync_id = Uuid::new_v4();

        let db = apply_test_db();
        vault_config(&db, relay_vault, device);
        insert_collectable_pending(&dek, db.conn(), &sync_id, 3, 1);

        let relay = FakeRelay::new();
        relay.set_vault(relay_vault);
        // A peer's edit won: object at v4, WITH a log entry pull can serve.
        let peer_mutation = crate::sync::v2::build_mutation(
            &crate::sync::v2::derive_metadata_mac_key(&dek).unwrap(),
            &crate::sync::v2::MutationInput {
                vault_id: relay_vault,
                object_id: sync_id,
                object_type: SyncEntryType::Credential,
                expected_version: ObjectVersion(2),
                resulting_version: ObjectVersion(4),
                key_epoch: 1,
                origin_device_id: Uuid::new_v4(),
                is_tombstone: false,
                encrypted_payload: {
                    let payload = CredentialPayload {
                        title: "Peer Title".to_string(),
                        username: "peer-user".to_string(),
                        password: Zeroizing::new("peer-pass".to_string()),
                        credential_type: crate::CredentialType::Password,
                        url: None,
                        notes: None,
                        favorite: false,
                        domains: vec![],
                        created_at: 1_700_000_000,
                        modified_at: 1_700_000_200,
                    };
                    encrypt_for_sync(
                        &dek,
                        &Zeroizing::new(serde_json::to_vec(&payload).unwrap()),
                    )
                    .unwrap()
                },
            },
        )
        .unwrap();
        relay.seed_peer_mutation(peer_mutation);

        let db = Arc::new(Mutex::new(db));
        let engine = SyncEngine::new(relay.clone(), db.clone(), device);

        engine.sync(&dek).await.unwrap();
        let (state, acked, version) = row_bookkeeping_full(&db, &sync_id);
        assert_eq!(state, "conflict", "the row is conflicted, never adopted");
        assert_eq!(acked, 1, "acked untouched — the local edit is preserved");
        assert_eq!(version, 3, "the LOCAL content stays in the row");
        let conflicts: Vec<(i64, String)> = {
            let conn = db.lock().unwrap();
            let mut stmt = conn
                .conn()
                .prepare("SELECT remote_version, object_id FROM sync_conflicts")
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        };
        assert_eq!(conflicts.len(), 1, "the alternative is durably stored");
        assert_eq!(conflicts[0].0, 4, "the alternative is the peer's v4");

        // KEEP-LOCAL resolution: re-version above the peer, re-base CAS.
        {
            let conn = db.lock().unwrap();
            resolve_conflict_keep_local(conn.conn(), &sync_id, SyncEntryType::Credential, 4)
                .unwrap();
        }
        let (state, acked, version) = row_bookkeeping_full(&db, &sync_id);
        assert_eq!(state, "pending");
        assert_eq!(acked, 4, "CAS expectation re-based onto the peer's version");
        assert_eq!(version, 5, "local content re-versioned above the peer");

        // The next push applies the LOCAL content (CAS 4 == 4).
        engine.sync(&dek).await.unwrap();
        let (state, acked) = row_bookkeeping(&db, &sync_id);
        assert_eq!(state, "synced");
        assert_eq!(acked, 5);
        assert_eq!(relay.log_len(), 2, "peer v4 + our resolved v5");
        assert!(
            !relay.log.iter().any(|(_, m)| {
                m.object_id == sync_id
                    && m.resulting_version.as_u64() == 4
                    && m.origin_device_id == device
            }),
            "the peer's v4 was not overwritten by a fabricated v4 — ours is v5"
        );
    }

    /// TAKE-REMOTE resolution: the stored alternative is applied through the
    /// normal path (sealing under the LOCAL identity), the local edit is
    /// discarded per the user's choice, and the record is removed.
    #[tokio::test]
    async fn conflict_take_remote_applies_the_alternative() {
        let dek = DataEncryptionKey::new().unwrap();
        let relay_vault = Uuid::new_v4();
        let device = Uuid::new_v4();
        let sync_id = Uuid::new_v4();

        let db = apply_test_db();
        vault_config(&db, relay_vault, device);
        insert_collectable_pending(&dek, db.conn(), &sync_id, 3, 1);

        let relay = FakeRelay::new();
        relay.set_vault(relay_vault);
        let peer_payload = {
            let payload = CredentialPayload {
                title: "Peer Title".to_string(),
                username: "peer-user".to_string(),
                password: Zeroizing::new("peer-pass".to_string()),
                credential_type: crate::CredentialType::Password,
                url: None,
                notes: None,
                favorite: false,
                domains: vec![],
                created_at: 1_700_000_000,
                modified_at: 1_700_000_200,
            };
            encrypt_for_sync(
                &dek,
                &Zeroizing::new(serde_json::to_vec(&payload).unwrap()),
            )
            .unwrap()
        };
        let peer_mutation = crate::sync::v2::build_mutation(
            &crate::sync::v2::derive_metadata_mac_key(&dek).unwrap(),
            &crate::sync::v2::MutationInput {
                vault_id: relay_vault,
                object_id: sync_id,
                object_type: SyncEntryType::Credential,
                expected_version: ObjectVersion(2),
                resulting_version: ObjectVersion(4),
                key_epoch: 1,
                origin_device_id: Uuid::new_v4(),
                is_tombstone: false,
                encrypted_payload: peer_payload.clone(),
            },
        )
        .unwrap();
        relay.seed_peer_mutation(peer_mutation);

        let db = Arc::new(Mutex::new(db));
        let engine = SyncEngine::new(relay.clone(), db.clone(), device);
        engine.sync(&dek).await.unwrap();
        assert_eq!(row_bookkeeping_full(&db, &sync_id).0, "conflict");

        // TAKE REMOTE.
        {
            let conn = db.lock().unwrap();
            let (remote_version, payload, origin): (i64, Vec<u8>, String) = conn
                .conn()
                .query_row(
                    "SELECT remote_version, remote_payload, origin_device_id FROM sync_conflicts \\
                     WHERE object_id = ?1",
                    [&sync_id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .unwrap();
            resolve_conflict_take_remote(
                &engine,
                conn.conn(),
                &dek,
                &sync_id,
                SyncEntryType::Credential,
                remote_version as u64,
                payload,
                Uuid::parse_str(&origin).unwrap(),
                false,
            )
            .unwrap();
        }

        let (state, acked, version) = row_bookkeeping_full(&db, &sync_id);
        assert_eq!(state, "synced", "the alternative applied");
        assert_eq!(acked, 4);
        assert_eq!(version, 4);
        let conflicts: i64 = db
            .lock()
            .unwrap()
            .conn()
            .query_row("SELECT COUNT(*) FROM sync_conflicts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(conflicts, 0, "the record is consumed by resolution");
    }

'''
s = s[:start] + new_tests + s[end:]
open(p, 'w').write(s)
print("tests rewritten")
