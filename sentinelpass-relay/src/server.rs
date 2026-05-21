//! Axum router setup.

use crate::app_state::RelayAppState;
use crate::auth::auth_middleware;
use crate::handlers::{devices, pairing, sync};
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

pub fn build_router(app_state: RelayAppState) -> Router {
    // Authenticated routes
    let authenticated = Router::new()
        .route("/api/v1/pairing/bootstrap", post(pairing::upload_bootstrap))
        .route("/api/v1/devices", get(devices::list_devices))
        .route("/api/v1/devices/{id}/revoke", post(devices::revoke_device))
        .route("/api/v1/sync/push", post(sync::push))
        .route("/api/v1/sync/pull", post(sync::pull))
        .route("/api/v1/sync/full-push", post(sync::full_push))
        .route("/api/v1/sync/full-pull", post(sync::full_pull))
        .route("/api/v1/sync/status", get(sync::status))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    // Unauthenticated routes
    let public = Router::new()
        .route("/api/v1/devices/register", post(devices::register_device))
        .route(
            "/api/v1/pairing/bootstrap/{token}",
            get(pairing::fetch_bootstrap),
        )
        .route("/health", get(health))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            public_rate_limit_middleware,
        ));

    Router::new()
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

    // Prefer proxy-provided client IP if present; fall back to direct connection IP.
    let client_ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| addr.ip().to_string());

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_returns_structured_relay_status() {
        let Json(response) = health().await;

        assert_eq!(response.status, "ok");
        assert_eq!(response.service, "sentinelpass-relay");
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
    }
}
