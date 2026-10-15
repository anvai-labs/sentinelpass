//! Exercise the real HTTP client, auth middleware, relay and JSON contract.
use ed25519_dalek::SigningKey;
use rand::RngCore;
use sentinelpass_core::sync::{
    client::SyncClient,
    models::SyncEntryType,
    v2::{
        build_mutation, DeviceSequence, MutationInput, ObjectVersion, PullRequestV2, PushRequestV2,
        ServerCursor,
    },
};
use sentinelpass_relay::{
    app_state::RelayAppState, config::RelayConfig, server, storage::RelayStorage,
};
use uuid::Uuid;

struct RunningRelay(tokio::task::JoinHandle<std::io::Result<()>>);
impl Drop for RunningRelay {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn register(storage: &RelayStorage, vault: Uuid) -> (Uuid, SigningKey) {
    let device = Uuid::new_v4();
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let key = SigningKey::from_bytes(&bytes);
    storage.conn().unwrap().execute(
        "INSERT INTO devices(device_id,vault_id,device_name,device_type,public_key,registered_at)
         VALUES(?1,?2,'wire test','desktop',?3,0)",
        rusqlite::params![device.to_string(),vault.to_string(),key.verifying_key().as_bytes()],
    ).unwrap();
    (device, key)
}

#[tokio::test]
async fn real_client_push_retry_and_pull_preserve_all_object_types() {
    // This integration-test executable has a single test; its environment is
    // isolated from the unit-test binaries and production relay processes.
    std::env::set_var("SENTINELPASS_ALLOW_LOOPBACK_RELAY", "1");
    assert_eq!(
        sentinelpass_core::sync::client::MAX_RELAY_RESPONSE_BYTES,
        sentinelpass_relay::handlers::sync_v2::MAX_PULL_RESPONSE_BYTES
    );
    let dir = tempfile::tempdir().unwrap();
    let storage = RelayStorage::open(&dir.path().join("relay.db")).unwrap();
    let vault = Uuid::new_v4();
    storage
        .conn()
        .unwrap()
        .execute(
            "INSERT INTO vaults(vault_id,created_at) VALUES(?1,0)",
            [vault.to_string()],
        )
        .unwrap();
    storage
        .conn()
        .unwrap()
        .execute(
            "INSERT INTO sequence_counters(vault_id,current_sequence) VALUES(?1,0)",
            [vault.to_string()],
        )
        .unwrap();
    let (device, key) = register(&storage, vault);
    let (reader, reader_key) = register(&storage, vault);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let router = server::build_router(RelayAppState::new(storage.clone(), RelayConfig::default()));
    let _running = RunningRelay(tokio::spawn(server::serve(router, listener)));
    let writer = SyncClient::new(&url, device, key).unwrap();
    let reader = SyncClient::new(&url, reader, reader_key).unwrap();
    let mut mac_key = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut mac_key);
    let mutations = [
        SyncEntryType::Credential,
        SyncEntryType::SshKey,
        SyncEntryType::TotpSecret,
        SyncEntryType::Credential,
    ]
    .into_iter()
    .enumerate()
    .map(|(i, object_type)| {
        build_mutation(
            &mac_key,
            &MutationInput {
                vault_id: vault,
                object_id: Uuid::new_v4(),
                object_type,
                expected_version: ObjectVersion(0),
                resulting_version: ObjectVersion(1),
                key_epoch: 1,
                origin_device_id: device,
                is_tombstone: i == 3,
                encrypted_payload: vec![i as u8; 40],
            },
        )
        .unwrap()
    })
    .collect();
    let request = PushRequestV2 {
        device_sequence: DeviceSequence(1),
        mutations,
    };
    let first = writer.push_v2(&request).await.unwrap();
    let retry = writer.push_v2(&request).await.unwrap();
    assert_eq!(first.results, retry.results);
    assert_eq!(first.server_cursor, ServerCursor(4));
    assert!(first.results.iter().all(|r| r.outcome.is_applied()));
    let pulled = reader
        .pull_v2(&PullRequestV2 {
            since: ServerCursor(0),
            limit: Some(2),
        })
        .await
        .unwrap();
    assert!(pulled.has_more);
    assert_eq!(
        pulled
            .entries
            .iter()
            .map(|e| e.mutation.clone())
            .collect::<Vec<_>>(),
        request.mutations[..2]
    );
    let next = reader
        .pull_v2(&PullRequestV2 {
            since: pulled.cursor,
            limit: Some(2),
        })
        .await
        .unwrap();
    assert!(!next.has_more);
    assert_eq!(
        next.entries
            .iter()
            .map(|e| e.mutation.clone())
            .collect::<Vec<_>>(),
        request.mutations[2..]
    );
    let mut wrong_vault = request.clone();
    wrong_vault.mutations[0].vault_id = Uuid::new_v4();
    assert!(writer.push_v2(&wrong_vault).await.is_err());
    assert_eq!(
        storage
            .conn()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM sync_mutations_v2", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        4
    );

    let canonical = serde_json::to_value(&request).unwrap();
    assert_eq!(canonical["mutations"][0]["entry_type"], "credential");
    assert!(canonical["mutations"][0].get("object_type").is_none());
    let mut early_client = canonical.clone();
    for mutation in early_client["mutations"].as_array_mut().unwrap() {
        let fields = mutation.as_object_mut().unwrap();
        let kind = fields.remove("entry_type").unwrap();
        fields.insert("object_type".into(), kind);
    }
    serde_json::from_value::<sentinelpass_relay::handlers::sync_v2::PushRequestV2>(
        early_client.clone(),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_value::<PushRequestV2>(early_client)
            .unwrap()
            .mutations,
        request.mutations
    );
    let mut ambiguous = canonical;
    ambiguous["mutations"][0]["object_type"] = serde_json::json!("ssh_key");
    assert!(serde_json::from_value::<PushRequestV2>(ambiguous.clone()).is_err());
    assert!(
        serde_json::from_value::<sentinelpass_relay::handlers::sync_v2::PushRequestV2>(ambiguous)
            .is_err()
    );
}

#[tokio::test]
async fn client_bounds_chunked_success_and_error_bodies() {
    use axum::{body::Body, http::StatusCode, response::Response, routing::post, Router};
    std::env::set_var("SENTINELPASS_ALLOW_LOOPBACK_RELAY", "1");
    for status in [StatusCode::OK, StatusCode::BAD_REQUEST] {
        let router = Router::new().route(
            "/api/v2/sync/push",
            post(move || async move {
                // No Content-Length: the streaming path must enforce the limit too.
                let chunks = futures_util::stream::iter(
                    (0..65).map(|_| Ok::<_, std::io::Error>(vec![b'x'; 65_536])),
                );
                Response::builder()
                    .status(status)
                    .body(Body::from_stream(chunks))
                    .unwrap()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let _running = RunningRelay(tokio::spawn(server::serve(router, listener)));
        let mut bytes = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let client = SyncClient::new(&url, Uuid::new_v4(), SigningKey::from_bytes(&bytes)).unwrap();
        let error = client
            .push_v2(&PushRequestV2 {
                device_sequence: DeviceSequence(1),
                mutations: vec![],
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds"), "{error}");
    }
}
