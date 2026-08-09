//! The zt-gateway service: issues JWT SVIDs, exposes an `ext_authz`-style
//! decision API, and reverse-proxies traffic to a protected backend
//! application, denying anything that fails `zero_trust::validate`.
//!
//! v0.1 limitation (see the plan doc / README): this serves plain HTTP,
//! not mTLS. Caller identity comes entirely from the presented
//! `X-SPIFFE-OBO-Token` — there is no independently-verified transport
//! identity, so `ValidationRequest::source_principal` is always `None`
//! here. See `obo::validate`'s doc comment for what that does and doesn't
//! check as a result.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use zero_trust::{
    now_unix_secs, validate, Decision, GatewayConfig, IdentityError, IdentityProvider,
    LocalIssuer, Registry, SpiffeId, ValidationRequest, HEADER_CALLER_CHAIN, HEADER_OBO_TOKEN,
};

/// Everything a request handler needs, cheap to clone (every field is an
/// `Arc` or otherwise cheap) because axum clones `State<AppState>` per
/// request.
#[derive(Clone)]
struct AppState {
    identity: Arc<dyn IdentityProvider + Send + Sync>,
    registry: Arc<Registry>,
    http_client: reqwest::Client,
    upstream_addr: String,
    protected_workload: Arc<SpiffeId>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "gateway.config.yaml".to_string());
    let config = GatewayConfig::from_file(&config_path)?;

    let registry = Registry::from_reader(std::fs::File::open(&config.registry_path)?)?;
    let protected_workload = config.protected_workload_id()?;

    let issuer = match &config.signing_key_path {
        Some(path) => {
            let pem = std::fs::read(path)?;
            LocalIssuer::from_rsa_private_pem(registry.clone(), &pem, config.token_ttl_seconds)?
        }
        None => {
            tracing::warn!(
                "no signing_key_path configured — generating an ephemeral keypair; \
                 issued tokens will not survive a restart"
            );
            LocalIssuer::generate(registry.clone(), config.token_ttl_seconds)?
        }
    };

    let state = AppState {
        identity: Arc::new(issuer),
        registry: Arc::new(registry),
        http_client: reqwest::Client::new(),
        upstream_addr: config.upstream_addr.clone(),
        protected_workload: Arc::new(protected_workload),
    };

    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, upstream = %config.upstream_addr, "zt-gateway listening");
    axum::serve(listener, router).await?;

    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/svid/jwt", post(issue_svid))
        .route("/v1/authorize", post(authorize))
        .fallback(proxy_handler)
        .with_state(state)
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(ErrorBody { error: message.into() })).into_response()
}

// --- POST /v1/svid/jwt ---

#[derive(Deserialize)]
struct IssueRequest {
    workload_name: String,
    audience: String,
    bootstrap_token: String,
}

#[derive(Serialize)]
struct IssueResponse {
    token: String,
    expires_at: i64,
}

async fn issue_svid(State(state): State<AppState>, Json(req): Json<IssueRequest>) -> Response {
    match state
        .identity
        .issue_jwt_svid(&req.workload_name, &req.audience, &req.bootstrap_token)
    {
        Ok(issued) => (
            StatusCode::OK,
            Json(IssueResponse {
                token: issued.token,
                expires_at: issued.expires_at,
            }),
        )
            .into_response(),
        Err(IdentityError::UnknownWorkload(name)) => {
            error_response(StatusCode::NOT_FOUND, format!("unknown workload: {name}"))
        }
        Err(IdentityError::InvalidBootstrapToken) => {
            error_response(StatusCode::UNAUTHORIZED, "invalid bootstrap token")
        }
        Err(e) => error_response(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

// --- POST /v1/authorize ---

#[derive(Deserialize)]
struct AuthorizeRequest {
    destination: String,
    obo_token: Option<String>,
    caller_chain: Option<String>,
}

#[derive(Serialize)]
struct AuthorizeResponse {
    allow: bool,
    deny_reason: String,
}

async fn authorize(State(state): State<AppState>, Json(req): Json<AuthorizeRequest>) -> Response {
    let Ok(destination) = req.destination.parse::<SpiffeId>() else {
        return error_response(StatusCode::BAD_REQUEST, "destination is not a valid SPIFFE ID");
    };

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: req.obo_token.as_deref(),
        caller_chain: req.caller_chain.as_deref(),
    };
    let decision = validate(&state.registry, state.identity.verifier(), &request, now_unix_secs());

    (
        StatusCode::OK,
        Json(AuthorizeResponse {
            allow: decision.is_allow(),
            deny_reason: decision.deny_reason_str().to_string(),
        }),
    )
        .into_response()
}

// --- fallback: the actual reverse proxy ---

#[derive(Serialize)]
struct DenyBody {
    deny_reason: String,
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_string)
}

async fn proxy_handler(State(state): State<AppState>, req: Request) -> Response {
    let obo_token = header_str(req.headers(), HEADER_OBO_TOKEN);
    let caller_chain = header_str(req.headers(), HEADER_CALLER_CHAIN);

    let request = ValidationRequest {
        destination: &state.protected_workload,
        source_principal: None,
        obo_token: obo_token.as_deref(),
        caller_chain: caller_chain.as_deref(),
    };
    let decision = validate(&state.registry, state.identity.verifier(), &request, now_unix_secs());

    // Structured fields deliberately mirror the blueprint Rego policies'
    // decision_log shape (allow, destination, obo_present, obo_chain,
    // deny_reason) so this log line could feed the same kind of
    // audit/OTEL pipeline described in ADR-0008.
    tracing::info!(
        allow = decision.is_allow(),
        destination = %state.protected_workload,
        obo_present = obo_token.is_some(),
        obo_chain = caller_chain.as_deref().unwrap_or(""),
        deny_reason = decision.deny_reason_str(),
        "authorization decision"
    );

    match decision {
        Decision::Allow => forward_to_upstream(&state, req).await,
        Decision::Deny(reason) => (
            StatusCode::FORBIDDEN,
            Json(DenyBody {
                deny_reason: reason.as_str().to_string(),
            }),
        )
            .into_response(),
    }
}

/// Headers that describe *this* hop's transport framing, not the request
/// itself — stripped before forwarding so `reqwest` can set correct ones
/// for the new connection to the upstream instead of reusing stale values.
const HOP_BY_HOP_HEADERS: [&str; 3] = ["host", "content-length", "connection"];

async fn forward_to_upstream(state: &AppState, req: Request) -> Response {
    let (parts, body) = req.into_parts();

    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "failed to read request body"),
    };

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", state.upstream_addr.trim_end_matches('/'), path_and_query);

    let mut headers = parts.headers.clone();
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }

    let upstream_request = state
        .http_client
        .request(parts.method, url)
        .headers(headers)
        .body(body_bytes);

    let upstream_response = match upstream_request.send().await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(error = %e, "upstream request failed");
            return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    let status = upstream_response.status();
    let response_headers = upstream_response.headers().clone();
    let response_body = match upstream_response.bytes().await {
        Ok(bytes) => bytes,
        Err(_) => return error_response(StatusCode::BAD_GATEWAY, "failed to read upstream response"),
    };

    let mut builder = Response::builder().status(status);
    for (name, value) in response_headers.iter() {
        builder = builder.header(name, value);
    }
    match builder.body(Body::from(response_body)) {
        Ok(response) => response,
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to build response"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::http::StatusCode as SC;
    use tower::ServiceExt;

    const TRUST_DOMAIN: &str = "chakra.internal";
    const INVENTORY: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
    const ORDERS: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";

    fn test_registry() -> Registry {
        Registry::from_yaml_str(&format!(
            r#"
trust_domain: {TRUST_DOMAIN}
workloads:
  - name: inventory-svc
    spiffe_id: {INVENTORY}
    max_obo_chain_depth: 3
    allowed_callers:
      - {ORDERS}

  - name: orders-svc
    spiffe_id: {ORDERS}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: orders-secret
"#
        ))
        .unwrap()
    }

    fn test_state(upstream_addr: String) -> AppState {
        let registry = test_registry();
        let issuer = LocalIssuer::generate(registry.clone(), 300).unwrap();
        AppState {
            identity: Arc::new(issuer),
            registry: Arc::new(registry),
            http_client: reqwest::Client::new(),
            upstream_addr,
            protected_workload: Arc::new(INVENTORY.parse().unwrap()),
        }
    }

    /// Binds a real local upstream that always returns `body`, and tracks
    /// how many times it was hit — used to prove denied requests never
    /// reach it.
    async fn spawn_test_upstream(body: &'static str) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_for_handler = hits.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = Router::new().fallback(move || {
            let hits = hits_for_handler.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                (SC::OK, body)
            }
        });

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (format!("http://{addr}"), hits)
    }

    #[tokio::test]
    async fn issue_svid_returns_a_token_for_correct_credentials() {
        let state = test_state("http://unused.invalid".to_string());
        let router = build_router(state);

        let body = r#"{"workload_name":"orders-svc","audience":"spiffe://chakra.internal/ns/inventory/sa/inventory-svc","bootstrap_token":"orders-secret"}"#;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/svid/jwt")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);
    }

    #[tokio::test]
    async fn issue_svid_rejects_wrong_bootstrap_token() {
        let state = test_state("http://unused.invalid".to_string());
        let router = build_router(state);

        let body = r#"{"workload_name":"orders-svc","audience":"spiffe://chakra.internal/ns/inventory/sa/inventory-svc","bootstrap_token":"wrong"}"#;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/svid/jwt")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authorize_reflects_the_same_decision_engine() {
        let state = test_state("http://unused.invalid".to_string());
        let issued = state
            .identity
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();
        let router = build_router(state);

        let body = format!(r#"{{"destination":"{INVENTORY}","obo_token":"{}"}}"#, issued.token);
        let request = Request::builder()
            .method("POST")
            .uri("/v1/authorize")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["allow"], true);
        assert_eq!(parsed["deny_reason"], "none");
    }

    #[tokio::test]
    async fn proxy_forwards_when_token_is_valid() {
        let (upstream_addr, hits) = spawn_test_upstream("hello from upstream").await;
        let state = test_state(upstream_addr);
        let issued = state
            .identity
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();
        let router = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, issued.token)
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"hello from upstream");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn proxy_denies_without_a_token_and_never_reaches_upstream() {
        let (upstream_addr, hits) = spawn_test_upstream("should never be seen").await;
        let state = test_state(upstream_addr);
        let router = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::FORBIDDEN);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn proxy_denies_an_expired_token_and_never_reaches_upstream() {
        let (upstream_addr, hits) = spawn_test_upstream("should never be seen").await;
        let state = test_state(upstream_addr);

        // Issue with a negative TTL by minting through an issuer configured
        // with ttl_seconds = -1, so exp is already in the past.
        let registry = test_registry();
        let expired_issuer = LocalIssuer::generate(registry, -1).unwrap();
        let issued = expired_issuer
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();

        // Swap in a state whose verifier matches expired_issuer's key so the
        // signature itself is valid — only expiry should cause the deny.
        let mut state = state;
        state.identity = Arc::new(expired_issuer);
        let router = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, issued.token)
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::FORBIDDEN);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }
}
