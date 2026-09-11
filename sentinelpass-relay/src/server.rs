//! Axum router setup.

use crate::app_state::RelayAppState;
use crate::auth::auth_middleware;
use crate::error::RelayError;
use crate::handlers::{devices, pairing, pairing_v2, sync, sync_v2};
use axum::extract::ConnectInfo;
use axum::middleware;
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use axum::{body::Body, extract::State, http::Request, middleware::Next, response::Response};
use serde::Serialize;
use std::net::SocketAddr;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

/// WBS-624 (ADR-006 retirement): v1-shaped requests are HARD-REJECTED once
/// v1 is retired — mixed v1/v2 operation is forbidden. Explicit 410 Gone
/// with the remediation in the message (never a silent 404).
async fn v1_retirement_middleware(
    State(state): State<RelayAppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, RelayError> {
    if state.config.allow_v1 {
        return Ok(next.run(request).await);
    }
    Err(RelayError::Gone(
        "sync protocol v1 is retired (ADR-006): this relay accepts only v2 \
         requests. Upgrade the client and re-pair under v2"
            .to_string(),
    ))
}

pub fn build_router(app_state: RelayAppState) -> Router {
    // v1 AUTHENTICATED routes (WBS-624): gate OUTERMOST, auth UNDER it — a
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
        .route("/api/v2/migration/claim", post(sync_v2::migration_claim))
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
        .merge(public)
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(
            app_state.config.max_payload_size,
        ))
        .with_state(app_state)
}

#[derive(Debug, Clone, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "sentinelpass-relay",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn public_rate_limit_middleware(
    State(state): State<RelayAppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, crate::error::RelayError> {
    let path = request.uri().path().to_string();
    if path == "/health" {
        return Ok(next.run(request).await);
    }

    // WBS-618 (TD-NET-03): X-Forwarded-For is honored ONLY when the direct
    // peer is a CONFIGURED trusted proxy. With the default (empty) trust
    // set, a spoofed XFF header cannot rotate rate-limit identities.
    let xff = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let client_ip = effective_client_ip(
        &addr.ip().to_string(),
        xff.as_deref(),
        &state.config.trusted_proxies,
    );

    let key = format!("public:{}:{}", path, client_ip);
    if !state.rate_limiter.check(&key) {
        tracing::warn!(
            path = %path,
            client_ip = %client_ip,
            "Public endpoint rate limit exceeded"
        );
        return Err(crate::error::RelayError::RateLimited);
    }

    Ok(next.run(request).await)
}

/// The effective client identity for rate limiting (WBS-618 / TD-NET-03):
/// the X-Forwarded-For value ONLY when the direct peer is a configured
/// trusted proxy; otherwise the direct peer address. A spoofed XFF from an
/// untrusted peer cannot rotate rate-limit identities.
fn effective_client_ip(peer_ip: &str, xff: Option<&str>, trusted_proxies: &[String]) -> String {
    let trusted = trusted_proxies.iter().any(|p| p == peer_ip);
    if trusted {
        xff.and_then(|v| {
            v.split(',')
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| peer_ip.to_string())
    } else {
        peer_ip.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;
    use crate::storage::RelayStorage;

    #[tokio::test]
    async fn health_returns_structured_relay_status() {
        let Json(response) = health().await;

        assert_eq!(response.status, "ok");
        assert_eq!(response.service, "sentinelpass-relay");
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
    }

    /// WBS-624: retired v1 routes answer 410 Gone (BEFORE auth — a request
    /// without credentials still gets the 410, not 401), while the v2
    /// register path is reachable.
    #[tokio::test]
    async fn retired_v1_routes_answer_gone_and_v2_register_is_live() {
        use tower::util::ServiceExt;
        let state = RelayAppState::new(RelayStorage::in_memory().unwrap(), RelayConfig::default());
        let app = build_router(state);

        // POST /api/v1/sync/push with NO credentials: 410 (gate) — not 401
        // (which would mean auth ran first) and not 404 (route mounted).
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/sync/push")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::GONE);

        // POST /api/v2/devices/register with no credentials: passes the
        // retirement path (4xx for the empty body — the route is LIVE).
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v2/devices/register")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            response.status(),
            axum::http::StatusCode::GONE,
            "v2 register is live"
        );
    }

    /// WBS-618 / TD-NET-03: forwarded IPs are trusted ONLY from configured
    /// proxies. Untrusted peer + spoofed XFF → the DIRECT address keys the
    /// limiter; trusted proxy + XFF → the forwarded address keys it.
    #[test]
    fn forwarded_ip_trust_follows_configuration() {
        let untrusted: &[String] = &[];
        assert_eq!(
            effective_client_ip("10.0.0.9", Some("203.0.113.7"), untrusted),
            "10.0.0.9",
            "untrusted proxy: the spoofed XFF is ignored"
        );
        let trusted: &[String] = &["10.0.0.9".to_string()];
        assert_eq!(
            effective_client_ip("10.0.0.9", Some("203.0.113.7"), trusted),
            "203.0.113.7",
            "trusted proxy: the forwarded address is honored"
        );
        // Empty/garbage XFF from a trusted proxy falls back to the peer.
        assert_eq!(
            effective_client_ip("10.0.0.9", Some("  "), trusted),
            "10.0.0.9"
        );
        assert_eq!(effective_client_ip("10.0.0.9", None, trusted), "10.0.0.9");
    }
}
