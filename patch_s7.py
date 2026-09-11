# Stage-7 review fixes (F1-F6).
p = '/Users/vijaysingh/code/sentinelpass/.claude/worktrees/agent-a91a2e8ade06c0dd8/sentinelpass-relay/src/server.rs'
s = open(p).read()
old = '''    // v1 routes (WBS-624): mounted ONLY behind the retirement gate — 410
    // Gone by default; `allow_v1 = true` opens a bounded migration window.
    let v1 = Router::new()
        .route("/api/v1/pairing/bootstrap", post(pairing::upload_bootstrap))
        .route("/api/v1/devices/register", post(devices::register_device))
        .route("/api/v1/sync/push", post(sync::push))
        .route("/api/v1/sync/pull", post(sync::pull))
        .route("/api/v1/sync/full-push", post(sync::full_push))
        .route("/api/v1/sync/full-pull", post(sync::full_pull))
        .route(
            "/api/v1/pairing/bootstrap/{token}",
            get(pairing::fetch_bootstrap),
        )
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            v1_retirement_middleware,
        ));

    // Authenticated routes (v2 protocol + management)
    let authenticated = Router::new()
        .route(
            "/api/v2/pairing/bootstrap",
            post(pairing_v2::upload_bootstrap_v2),
        )
        .route("/api/v1/devices", get(devices::list_devices))
        .route("/api/v1/devices/{id}/revoke", post(devices::revoke_device))
        .route("/api/v1/sync/status", get(sync::status))
        // v2 mutation protocol (ADR-006): idempotent push with durable
        // per-object results; paginated pull over the vault mutation log.
        .route("/api/v2/sync/push", post(sync_v2::push_v2))
        .route("/api/v2/sync/pull", post(sync_v2::pull_v2))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    // Unauthenticated routes (v2 + management)
    let public = Router::new()
        .route(
            "/api/v2/pairing/bootstrap/retrieve",
            post(pairing_v2::retrieve_bootstrap_v2),
        )
        .route("/health", get(health))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            public_rate_limit_middleware,
        ));

    Router::new()
        .merge(v1)
        .merge(authenticated)
        .merge(public)'''
new = '''    // v1 AUTHENTICATED routes (WBS-624): gate OUTERMOST, auth UNDER it — a
    // retired v1 route answers 410 before auth even runs; with
    // `allow_v1 = true` (bounded migration window) auth still applies.
    let v1_authenticated = Router::new()
        .route("/api/v1/pairing/bootstrap", post(pairing::upload_bootstrap))
        .route("/api/v1/sync/push", post(sync::push))
        .route("/api/v1/sync/pull", post(sync::pull))
        .route("/api/v1/sync/full-push", post(sync::full_push))
        .route("/api/v1/sync/full-pull", post(sync::full_pull))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            v1_retirement_middleware,
        ));

    // v1 PUBLIC routes (register + bootstrap fetch): rate-limited, then
    // gated. Device registration is PROTOCOL-NEUTRAL — the v2 path
    // (/api/v2/devices/register) below serves v2 clients ungated.
    let v1_public = Router::new()
        .route("/api/v1/devices/register", post(devices::register_device))
        .route(
            "/api/v1/pairing/bootstrap/{token}",
            get(pairing::fetch_bootstrap),
        )
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            public_rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            v1_retirement_middleware,
        ));

    // Authenticated routes (v2 protocol + management)
    let authenticated = Router::new()
        .route(
            "/api/v2/pairing/bootstrap",
            post(pairing_v2::upload_bootstrap_v2),
        )
        .route("/api/v1/devices", get(devices::list_devices))
        .route("/api/v1/devices/{id}/revoke", post(devices::revoke_device))
        .route("/api/v1/sync/status", get(sync::status))
        // v2 mutation protocol (ADR-006): idempotent push with durable
        // per-object results; paginated pull over the vault mutation log.
        .route("/api/v2/sync/push", post(sync_v2::push_v2))
        .route("/api/v2/sync/pull", post(sync_v2::pull_v2))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    // Unauthenticated routes (v2 + management)
    let public = Router::new()
        // Device registration is protocol-neutral and load-bearing for v2
        // onboarding (sync_now preflight, pair-join) — NOT gated by the v1
        // retirement. Self-gating: existing vaults require a pairing proof.
        .route("/api/v2/devices/register", post(devices::register_device))
        .route(
            "/api/v2/pairing/bootstrap/retrieve",
            post(pairing_v2::retrieve_bootstrap_v2),
        )
        .route("/health", get(health))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            public_rate_limit_middleware,
        ));

    Router::new()
        .merge(v1_authenticated)
        .merge(v1_public)
        .merge(authenticated)
        .merge(public)'''
assert old in s, "router block not found"
s = s.replace(old, new)
open(p, 'w').write(s)
print("routers restructured")

# F1/F5: claim repoints claimant + membership check; 409 without vault id.
p = '/Users/vijaysingh/code/sentinelpass/.claude/worktrees/agent-a91a2e8ade06c0dd8/sentinelpass-relay/src/handlers/sync_v2.rs'
s = open(p).read()
old = '''    // The claimant must be a registered device.
    tx.query_row(
        "SELECT 1 FROM devices WHERE device_id = ?1",
        [device_id.to_string()],
        |row| row.get::<_, i64>(0),
    )
    .map_err(|_| RelayError::NotFound("Device not found".to_string()))?;'''
new = '''    // The claimant must be a registered device OF THE ORIGIN VAULT (the
    // v1-era relay vault being migrated away from).
    let claimant_vault: String = tx
        .query_row(
            "SELECT vault_id FROM devices WHERE device_id = ?1",
            [device_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| RelayError::NotFound("Device not found".to_string()))?;
    if claimant_vault != origin {
        return Err(RelayError::BadRequest(
            "claimant device does not belong to the origin vault".into(),
        ));
    }'''
assert old in s, "claimant check not found"
s = s.replace(old, new)

old = '''    if inserted == 0 {
        let (existing_vault, existing_claim): (String, String) = tx
            .query_row(
                "SELECT new_vault_id, claimed_by FROM migration_claims WHERE origin_vault_id = ?1",
                [&origin],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|e| RelayError::Database(e.to_string()))?;
        return Err(RelayError::Conflict(format!(
            "origin vault already re-baselined by device {existing_claim} onto vault {existing_vault}; \\
             re-onboard through that device's v2 pairing instead"
        )));
    }'''
new = '''    if inserted == 0 {
        let existing_claim: String = tx
            .query_row(
                "SELECT claimed_by FROM migration_claims WHERE origin_vault_id = ?1",
                [&origin],
                |row| row.get(0),
            )
            .map_err(|e| RelayError::Database(e.to_string()))?;
        // The fresh vault id is deliberately NOT in the response (log only).
        tracing::warn!(
            origin = %origin,
            claimed_by = %existing_claim,
            "duplicate authoritative claim refused"
        );
        return Err(RelayError::Conflict(format!(
            "origin vault already re-baselined by device {existing_claim}; \\
             re-onboard through that device's v2 pairing instead"
        )));
    }'''
assert old in s, "409 body not found"
s = s.replace(old, new)

old = '''    // Fresh vault scaffolding for the re-baseline.
    tx.execute('''
new = '''    // THE CLAIMANT'S DEVICE ROW MOVES: push/pull derive the vault from the
    // devices table, so the authority's binding must follow the claim or
    // the migration can never complete (review finding 1).
    tx.execute(
        "UPDATE devices SET vault_id = ?1 WHERE device_id = ?2",
        rusqlite::params![&new_vault_str, device_id.to_string()],
    )
    .map_err(|e| RelayError::Database(e.to_string()))?;

    // Fresh vault scaffolding for the re-baseline.
    tx.execute('''
assert old in s, "scaffold anchor not found"
s = s.replace(old, new)

# F6: stale comment.
s = s.replace('''// Per-entry payload cap: the configured request-body limit (one consistent
// limit set, TD-NET-06) — a body that passes the global body-limit layer
// cannot contain an entry larger than it. Sanity floor of 1 KiB guards a
// misconfigured zero/near-zero body limit.''',
'''// TD-NET-06: the per-entry payload size is bounded by the GLOBAL
// request-body limit layer (max_payload_size) — one consistent limit set.
// The request body is base64 (~1.37x decoded), so the decoded payload is
// always smaller than the bounded body. RelayConfig::validate rejects a
// zero body limit.''')
open(p, 'w').write(s)
print("sync_v2 fixes applied")

# client register path → v2.
p = '/Users/vijaysingh/code/sentinelpass/.claude/worktrees/agent-a91a2e8ade06c0dd8/sentinelpass-core/src/sync/client.rs'
s = open(p).read()
s = s.replace('let path = "/api/v1/devices/register";', 'let path = "/api/v2/devices/register";')
open(p, 'w').write(s)
print("client register → v2")

# F4: migration purges conflicts + dead-letter.
p = '/Users/vijaysingh/code/sentinelpass/.claude/worktrees/agent-a91a2e8ade06c0dd8/sentinelpass-core/src/vault/sync_ops.rs'
s = open(p).read()
old = '''        for table in ["entries", "ssh_keys", "totp_secrets"] {
            tx.execute(
                &format!(
                    "UPDATE {table} SET sync_state = 'pending',
                     sync_acked_version = 0
                     WHERE is_deleted = 0"
                ),
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
            // Locally deleted rows keep their tombstone (they push as
            // deletions); a never-synced deleted row has nothing to push.
        }'''
new = '''        // Stale lineage state is PURGED (stage-7 review): conflict
        // alternatives and dead-letters belong to the abandoned lineage —
        // keeping them would let take-remote regress post-migration data
        // and count pre-migration debris against the dead-letter cap.
        tx.execute("DELETE FROM sync_conflicts", [])
            .map_err(DatabaseError::Sqlite)?;
        tx.execute("DELETE FROM sync_dead_letter", [])
            .map_err(DatabaseError::Sqlite)?;

        for table in ["entries", "ssh_keys", "totp_secrets"] {
            tx.execute(
                &format!(
                    "UPDATE {table} SET sync_state = 'pending',
                     sync_acked_version = 0
                     WHERE is_deleted = 0"
                ),
                [],
            )
            .map_err(DatabaseError::Sqlite)?;
            // Locally deleted rows keep their tombstone (they push as
            // deletions); a never-synced deleted row has nothing to push.
        }'''
assert old in s, "migrate body not found"
s = s.replace(old, new)
open(p, 'w').write(s)
print("migration purge added")
