//! The zt-gateway service: issues JWT SVIDs and X.509 SVIDs, exposes an
//! `ext_authz`-style decision API, and reverse-proxies traffic to a
//! protected backend application, denying anything that fails
//! `zero_trust::validate`.
//!
//! When TLS is configured with `client_auth: optional` or `required` (see
//! `GatewayConfig::tls`), a verified client certificate's SPIFFE ID becomes
//! `ValidationRequest::source_principal` — extracted once per connection
//! right after the TLS handshake (see `serve()`/`extract_peer_identity`)
//! and threaded into every request on that connection via `axum::Extension`.
//! With `client_auth: none` (or no `tls:` block at all), it's always
//! `None`, same as v0.1. See `obo::validate`'s doc comment for exactly what
//! that does and doesn't enable.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::error_handling::HandleErrorLayer;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::extract::DefaultBodyLimit;
use axum::routing::post;
use axum::{Extension, Json, Router};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use opentelemetry::propagation::{Extractor, Injector};
use opentelemetry::trace::{Status, TraceContextExt, Tracer as _, TracerProvider as _};
use opentelemetry::{global, Context as OtelContext, KeyValue};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::buffer::BufferLayer;
use tower::limit::{ConcurrencyLimitLayer, RateLimitLayer};
use tower::ServiceBuilder;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use zero_trust::{
    build_client_cert_verifier, build_server_config, compute_cert_thumbprint_x5t_s256, current_actor,
    exchange_token_with_cert_binding, load_certs, now_unix_secs, validate_with_cert_binding_and_clock_skew,
    validate_for_proxy, CaError,
    CertificateAuthority, ClientAuth, Decision, GatewayConfig, IdentityError, IdentityProvider, JsonWebKeySet, LocalCa,
    LocalIssuer, Registry, UserIdp, CapabilityDecision, CapabilityPolicy, CapabilityPolicyHandle, CapabilityRequest, RouteTable, watch_capability_policy, ServerCertificate, SpiffeId, SpireProvider, TokenExchangeError, TokenExchangeRequest,
    TokenExchangeResponse, ValidationRequest, DEFAULT_MAX_OBO_CHAIN_DEPTH, HEADER_CALLER_CHAIN, HEADER_OBO_TOKEN,
    HEADER_USER_PRINCIPAL,
};

/// Everything a request handler needs, cheap to clone (every field is an
/// `Arc` or otherwise cheap) because axum clones `State<AppState>` per
/// request.
#[derive(Clone)]
struct AppState {
    identity: Arc<dyn IdentityProvider + Send + Sync>,
    /// `None` whenever this gateway isn't configured to issue X.509 SVIDs
    /// itself — either no `ca:` block at all, or a verify-only setup
    /// (`ca.cert_path` without `ca.key_path`). `POST /v1/svid/x509` returns
    /// `501` in that case rather than this field ever being unwrap()'d.
    ca: Option<Arc<dyn CertificateAuthority + Send + Sync>>,
    registry: Arc<Registry>,
    http_client: reqwest::Client,
    upstream_addr: String,
    protected_workload: Arc<SpiffeId>,
    /// This gateway's own identity, appended to the signed `act`
    /// delegation chain by `POST /v1/token-exchange`. See
    /// `GatewayConfig::gateway_id`'s doc comment.
    gateway_id: Arc<SpiffeId>,
    /// TTL (seconds) for tokens minted by `POST /v1/token-exchange`.
    /// Mirrors `GatewayConfig::token_ttl_seconds`, the same TTL
    /// `LocalIssuer` itself uses for `issue_jwt_svid`.
    token_exchange_ttl_secs: u64,
    /// Max body size in bytes (F6 fix).
    max_body_bytes: usize,
    /// Multi-backend routing table (F14 / Task 1). Empty whenever
    /// `GatewayConfig::routes` is unset — see `resolve_route`'s doc
    /// comment for the backward-compatible fallback this enables.
    route_table: Arc<RouteTable>,
    /// `nbf` clock-skew allowance (seconds, Task 3). Mirrors
    /// `GatewayConfig::clock_skew_tolerance_secs`, threaded through to every
    /// `validate_with_cert_binding_and_clock_skew` call below so an
    /// operator-configured tolerance actually reaches the decision, instead
    /// of the fixed `DEFAULT_CLOCK_SKEW_SECS` plain `validate` would use.
    clock_skew_tolerance_secs: i64,
    /// Trusted IdP issuers for the N5 edge-mint path (review 0002), mirrors
    /// `GatewayConfig::user_issuers`. `POST /v1/svid/jwt-with-user` checks
    /// a request's `user_issuer` against this list (via
    /// `IdentityProvider::issue_jwt_svid_with_user`) before minting
    /// anything, and it's the same list a downstream validator would pass
    /// to `obo::validate_with_user_issuers` to accept this gateway's
    /// human-principal tokens.
    user_issuers: Arc<Vec<String>>,
    /// Verification keys and checks for each trusted user IdP (N5 fix,
    /// review 0002), keyed by `iss`. `POST /v1/svid/jwt-with-user` verifies
    /// the user's credential against the entry for `user_issuer` before it
    /// trusts any principal from it.
    user_idps: Arc<std::collections::HashMap<String, UserIdp>>,
    /// F11 capability policy (review 0002), or `None` when no policy file is
    /// configured. Checked after the OBO decision on every proxied request.
    capability_policy: Option<Arc<CapabilityPolicyHandle>>,
    /// Issuers this gateway accepts tokens from (N12 fix, review 0002),
    /// mirrors `GatewayConfig::trusted_issuers`. Empty disables the check.
    trusted_issuers: Arc<Vec<String>>,
    /// Whether a token's `jti` is checked against the replay cache (N12 fix),
    /// mirrors `GatewayConfig::jti_cache_enabled`.
    jti_cache_enabled: bool,
    /// How long a seen `jti` is remembered, in seconds. Mirrors
    /// `GatewayConfig::jti_ttl_secs`.
    jti_ttl_secs: u64,
    /// Mirrors `GatewayConfig::effective_require_cert_binding()` (N6 fix,
    /// review 0002): whether `POST /v1/svid/jwt` must refuse issuance
    /// outright when the caller presented no mTLS client certificate at
    /// all, rather than falling back to an unbound token. See
    /// `issue_svid`'s doc comment for the full decision this field feeds
    /// into.
    require_cert_binding: bool,
}

/// Sets up structured stdout logs (always) plus, when
/// `OTEL_EXPORTER_OTLP_ENDPOINT` is set, real OTLP trace export (an
/// `opentelemetry_sdk` `TracerProvider` bridged into `tracing` spans via
/// `tracing-opentelemetry`). Returns the provider so `main` can keep it
/// alive for the process lifetime — dropping it would tear down the batch
/// exporter's background flush task.
///
/// F12 fix: the W3C TraceContext propagator (`traceparent`/`tracestate`)
/// and the `TracerProvider` itself are now configured *unconditionally* —
/// both are needed for `proxy_handler` to extract/inject trace context and
/// generate per-hop span IDs end-to-end (see `extract_trace_context`,
/// `inject_trace_context`), independent of whether anything is actually
/// exporting those spans anywhere. Only the OTLP *export* half remains
/// conditional on `OTEL_EXPORTER_OTLP_ENDPOINT`: with no endpoint
/// configured, `TracerProvider::builder()` is given no span processor at
/// all, so spans are still created (real trace/span IDs, real sampling)
/// and still propagate, but are simply never shipped anywhere — local
/// `cargo run` otherwise behaves exactly as before.
fn init_tracing() -> opentelemetry_sdk::trace::TracerProvider {
    global::set_text_map_propagator(TraceContextPropagator::new());

    let resource = opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new(
        "service.name",
        "zt-gateway",
    )]);

    let mut builder = opentelemetry_sdk::trace::TracerProvider::builder().with_resource(resource);
    if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()
            .expect("failed to build OTLP span exporter");
        builder = builder.with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio);
    }
    let provider = builder.build();
    global::set_tracer_provider(provider.clone());

    let otel_layer = tracing_opentelemetry::layer().with_tracer(provider.tracer("zt-gateway"));

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .init();

    provider
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Kept alive for the rest of `main` -- see `init_tracing`'s doc comment.
    let _otel_provider = init_tracing();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "gateway.config.yaml".to_string());
    let config = GatewayConfig::from_file(&config_path)?;

    let registry = Registry::from_reader(std::fs::File::open(&config.registry_path)?)?;
    let protected_workload = config.protected_workload_id()?;
    let gateway_id = config.gateway_id_spiffe_id()?;

    // Task 5 / F13: `spire_socket_path` set opts this gateway into a
    // SPIRE-backed `IdentityProvider` (`SpireProvider`) instead of
    // `LocalIssuer` -- entirely optional, and `LocalIssuer` remains the
    // default/backward-compatible path when it's unset. See
    // `spire_provider.rs`'s module doc comment for what `SpireProvider`
    // can't faithfully provide relative to `LocalIssuer` (notably: RFC
    // 8693 token exchange).
    let identity: Arc<dyn IdentityProvider + Send + Sync> = if let Some(socket_path) = &config.spire_socket_path {
        tracing::info!(
            socket_path = %socket_path,
            "spire_socket_path configured — issuing workload identity via the SPIRE Workload API \
             instead of LocalIssuer"
        );
        Arc::new(SpireProvider::new(socket_path).await?)
    } else {
        let issuer = match (&config.jwks_path, &config.active_kid) {
            // N7 (review 0002 / F4): `jwks_path` is the public verification
            // set only. This gateway's private key comes from its own
            // `signing_key_path`, never from the shared JWKS file.
            (Some(jwks_path), Some(active_kid)) => {
                let signing_key_path = config.signing_key_path.as_ref().ok_or(
                    "jwks_path is configured but signing_key_path is missing — the private \
                     signing key must be loaded separately from the public JWKS",
                )?;
                let jwks = JsonWebKeySet::from_json(&std::fs::read_to_string(jwks_path)?)?;
                let pem = std::fs::read(signing_key_path)?;
                LocalIssuer::with_separated_keys(
                    registry.clone(),
                    &pem,
                    Some(active_kid.clone()),
                    &jwks,
                    config.token_ttl_seconds,
                )?
            }
            (Some(_), None) => {
                return Err(
                    "jwks_path is configured but active_kid is missing — set active_kid to \
                     the kid this gateway should sign with"
                        .into(),
                );
            }
            (None, _) => match &config.signing_key_path {
                Some(path) => {
                    let pem = std::fs::read(path)?;
                    LocalIssuer::from_rsa_private_pem(registry.clone(), &pem, config.token_ttl_seconds)?
                }
                None => {
                    tracing::warn!(
                        "no signing_key_path or jwks_path configured — generating an ephemeral \
                         keypair; issued tokens will not survive a restart and cannot be verified \
                         by any other gateway"
                    );
                    LocalIssuer::generate(registry.clone(), config.token_ttl_seconds)?
                }
            },
        };
        Arc::new(issuer)
    };

    let ca = resolve_ca(&config, &registry)?;

    let tls_acceptor = match &config.tls {
        Some(tls_config) => {
            let server_cert = match (&tls_config.cert_path, &tls_config.key_path) {
                (Some(cert_path), Some(key_path)) => ServerCertificate::load(cert_path, key_path)?,
                (None, None) => {
                    tracing::warn!(
                        "no tls.cert_path/key_path configured — generating an ephemeral \
                         self-signed server certificate; not for anything a real client \
                         should be asked to trust long-term"
                    );
                    ServerCertificate::generate_ephemeral(vec![
                        "localhost".to_string(),
                        "127.0.0.1".to_string(),
                    ])?
                }
                _ => return Err("tls.cert_path and tls.key_path must both be set, or both omitted".into()),
            };

            let client_cert_verifier = match tls_config.client_auth {
                ClientAuth::None => None,
                ClientAuth::Optional | ClientAuth::Required => {
                    let trust_root_der = resolve_trust_root_der(&config, &ca)?.ok_or(
                        "tls.client_auth is enabled but no CA trust root could be resolved \
                         (set ca.cert_path or ca.key_path)",
                    )?;
                    let allow_unauthenticated = tls_config.client_auth == ClientAuth::Optional;
                    Some(build_client_cert_verifier(&trust_root_der, allow_unauthenticated)?)
                }
            };

            let server_config = build_server_config(server_cert, client_cert_verifier)?;
            Some(TlsAcceptor::from(Arc::new(server_config)))
        }
        None => None,
    };

    let upstream_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
        .timeout(Duration::from_secs(config.request_timeout_secs))
        .build()?;

    let state = AppState {
        identity,
        ca,
        registry: Arc::new(registry),
        http_client: upstream_client,
        upstream_addr: config.upstream_addr.clone(),
        protected_workload: Arc::new(protected_workload),
        gateway_id: Arc::new(gateway_id),
        token_exchange_ttl_secs: config.token_ttl_seconds.max(0) as u64,
        max_body_bytes: (config.max_body_mb as usize) * 1024 * 1024,
        route_table: Arc::new(RouteTable::new(config.routes.clone())),
        clock_skew_tolerance_secs: config.clock_skew_tolerance_secs as i64,
        user_issuers: Arc::new(config.user_issuers.clone()),
        user_idps: Arc::new(load_user_idps(&config)?),
        capability_policy: load_capability_policy(&config)?,
        trusted_issuers: Arc::new(config.trusted_issuers.clone()),
        jti_cache_enabled: config.jti_cache_enabled,
        jti_ttl_secs: config.jti_ttl_secs,
        require_cert_binding: config.effective_require_cert_binding(),
    };

    let listener_config = ListenerConfig {
        proxy_addr: config.proxy_addr,
        admin_addr: config.admin_addr,
        admin_rate_limit_rps: config.admin_rate_limit,
        max_body_mb: config.max_body_mb,
        request_timeout_secs: config.request_timeout_secs,
        max_concurrent_connections: config.max_concurrent_connections,
    };

    let handles = setup_listeners(&listener_config, state, tls_acceptor).await?;
    tracing::info!(
        admin_addr = %handles.admin_addr,
        proxy_addr = %handles.proxy_addr,
        upstream = %config.upstream_addr,
        admin_rate_limit_rps = listener_config.admin_rate_limit_rps,
        "zt-gateway listening"
    );

    // Neither task ever returns under normal operation -- `serve()` loops
    // forever, only giving up an iteration (not the whole loop) on a
    // per-connection accept error. Waiting on both keeps `main` alive for
    // the process lifetime and surfaces a panic in either listener as a
    // process exit rather than silently leaving the other half running.
    let (admin_result, proxy_result) = tokio::join!(handles.admin, handles.proxy);
    admin_result?;
    proxy_result?;

    Ok(())
}

/// Pre-resolved listener settings `setup_listeners` needs, split out of
/// `GatewayConfig` so tests can construct one directly (with test-chosen
/// ports) without building a full, file-backed `GatewayConfig`.
struct ListenerConfig {
    proxy_addr: SocketAddr,
    admin_addr: SocketAddr,
    admin_rate_limit_rps: u32,
    max_body_mb: u32,
    request_timeout_secs: u64,
    max_concurrent_connections: u32,
}

/// What `setup_listeners` hands back: the two background tasks (so the
/// caller can await/abort them) plus the addresses each listener actually
/// bound to -- the same as `config.{admin,proxy}_addr` in production, but
/// meaningfully different from the requested address when a test asks for
/// port `0` and needs to learn which port the OS actually picked.
struct ListenerHandles {
    admin_addr: SocketAddr,
    proxy_addr: SocketAddr,
    admin: tokio::task::JoinHandle<()>,
    proxy: tokio::task::JoinHandle<()>,
}

/// Binds and spawns the admin and proxy listeners as two independent
/// background tasks, each running the same hand-rolled `serve()` accept
/// loop (see its doc comment) -- same TLS configuration on both (Task 6
/// doesn't change TLS setup, only which routes live on which listener; see
/// `docs/design/` for the planned per-listener `client_auth` split), but
/// completely disjoint route tables: issuance/`authorize`/`token-exchange`
/// only ever reach `build_admin_router`'s routes, and protected traffic
/// only ever reaches `build_proxy_router`'s fallback (F7, F10 fixes).
async fn setup_listeners(
    config: &ListenerConfig,
    state: AppState,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<ListenerHandles, Box<dyn std::error::Error>> {
    let admin_router = build_admin_router(state.clone(), config.admin_rate_limit_rps, config.max_body_mb, config.request_timeout_secs, config.max_concurrent_connections);
    let proxy_router = build_proxy_router(state, config.max_body_mb, config.request_timeout_secs, config.max_concurrent_connections);

    let admin_listener = TcpListener::bind(config.admin_addr).await?;
    let admin_addr = admin_listener.local_addr()?;
    let proxy_listener = TcpListener::bind(config.proxy_addr).await?;
    let proxy_addr = proxy_listener.local_addr()?;

    let admin_tls = tls_acceptor.clone();
    let admin = tokio::spawn(async move {
        serve(admin_listener, admin_router, admin_tls).await;
    });

    let proxy = tokio::spawn(async move {
        serve(proxy_listener, proxy_router, tls_acceptor).await;
    });

    Ok(ListenerHandles {
        admin_addr,
        proxy_addr,
        admin,
        proxy,
    })
}

/// Builds the admin listener's router: the issuance routes (`/v1/svid/jwt`,
/// `/v1/svid/jwt-with-user`, `/v1/svid/x509`), `/v1/authorize`, and
/// `/v1/token-exchange` -- every
/// control-plane route this gateway exposes, all behind a shared rate
/// limit (F7 fix: previously unlimited, making the bootstrap-token compare
/// a practical brute-force target). No fallback is registered, so any path
/// this router doesn't recognize 404s instead of being proxied anywhere.
///
/// The rate limiter is wrapped in a `tower::buffer::Buffer` specifically
/// because `tower::limit::RateLimit` does not implement `Clone` -- its
/// token-bucket state would otherwise have to live directly on the
/// `Router`, and axum's hand-rolled `serve()` (see its doc comment) clones
/// the whole `Router` once per accepted TCP connection, not once per
/// request. Without the buffer, every new connection would start its own
/// independent rate limiter and the limit would only ever hold within a
/// single connection, never across the listener as a whole. `Buffer`
/// instead runs the rate-limited service once, in a spawned worker task,
/// and hands every clone of the returned `Router` a cheap handle (an mpsc
/// `Sender`) to that same worker -- so the limit is enforced globally, the
/// way `admin_rate_limit` in `GatewayConfig`'s doc comment describes it.
fn build_admin_router(state: AppState, rate_limit_rps: u32, max_body_mb: u32, request_timeout_secs: u64, max_concurrent_connections: u32) -> Router {
    let body_limit_bytes = (max_body_mb as usize) * 1024 * 1024;

    Router::new()
        .route("/v1/svid/jwt", post(issue_svid))
        .route("/v1/svid/jwt-with-user", post(issue_svid_with_user))
        .route("/v1/svid/x509", post(issue_x509_svid))
        .route("/v1/authorize", post(authorize))
        .route("/v1/token-exchange", post(handle_token_exchange))
        .layer(DefaultBodyLimit::max(body_limit_bytes))
        .layer(TimeoutLayer::new(Duration::from_secs(request_timeout_secs)))
        .layer(
            ServiceBuilder::new()
                .layer(ConcurrencyLimitLayer::new(max_concurrent_connections as usize))
                .layer(HandleErrorLayer::new(handle_admin_middleware_error))
                .layer(BufferLayer::new(1024))
                // RateLimitLayer::new panics on a zero rate; `.max(1)` keeps a
                // misconfigured `admin_rate_limit: 0` from crashing the
                // gateway at startup, degrading instead to the lowest
                // meaningful rate (1 req/s) rather than failing closed on an
                // operator typo.
                .layer(RateLimitLayer::new(rate_limit_rps.max(1) as u64, Duration::from_secs(1))),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Converts a `tower::BoxError` bubbling up from the admin router's rate
/// limiting middleware (see `build_admin_router`) into an HTTP response —
/// required so the layered service's error type is `Infallible` rather
/// than `BoxError` (axum's `Router::layer` bound). Not expected to fire in
/// practice: `tower::limit::RateLimit` enforces its budget by delaying
/// (`Poll::Pending`) rather than erroring.
async fn handle_admin_middleware_error(err: tower::BoxError) -> Response {
    error_response(StatusCode::SERVICE_UNAVAILABLE, format!("admin listener unavailable: {err}"))
}

/// Builds the proxy listener's router: only the reverse-proxy catch-all
/// (F7, F10 fixes). No issuance or control-plane route is ever reachable
/// here, which is what makes it safe to set `client_auth: required` on
/// this listener without also locking out workloads that haven't
/// bootstrapped an SVID yet (they'd reach the admin listener instead,
/// which stays `client_auth: optional`/loopback-restricted).
fn build_proxy_router(state: AppState, max_body_mb: u32, request_timeout_secs: u64, max_concurrent_connections: u32) -> Router {
    let body_limit_bytes = (max_body_mb as usize) * 1024 * 1024;

    Router::new()
        .fallback(proxy_handler)
        .layer(DefaultBodyLimit::max(body_limit_bytes))
        .layer(TimeoutLayer::new(Duration::from_secs(request_timeout_secs)))
        .layer(ConcurrencyLimitLayer::new(max_concurrent_connections as usize))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// The pre-Task-6 combined router: every route (issuance, `/v1/authorize`,
/// `/v1/token-exchange`) plus the proxy fallback, all on one `Router`, none
/// of it rate-limited. Kept around (rather than folded into
/// `build_admin_router`/`build_proxy_router`) purely so every test written
/// before this task -- which exercises issuance, authorize, token-exchange,
/// and proxying all through a single `Router` via `tower::ServiceExt::oneshot`
/// -- keeps working completely unmodified; `main` itself no longer calls
/// this, `setup_listeners` is what it uses instead.
#[cfg_attr(not(test), allow(dead_code))]
fn build_router(state: AppState) -> Router {
    let max_body_mb = 100u32;
    let request_timeout_secs = 30u64;
    let max_concurrent_connections = 1000u32;
    let body_limit_bytes = (max_body_mb as usize) * 1024 * 1024;

    Router::new()
        .route("/v1/svid/jwt", post(issue_svid))
        .route("/v1/svid/jwt-with-user", post(issue_svid_with_user))
        .route("/v1/svid/x509", post(issue_x509_svid))
        .route("/v1/authorize", post(authorize))
        .route("/v1/token-exchange", post(handle_token_exchange))
        .fallback(proxy_handler)
        .layer(DefaultBodyLimit::max(body_limit_bytes))
        .layer(TimeoutLayer::new(Duration::from_secs(request_timeout_secs)))
        .layer(ConcurrencyLimitLayer::new(max_concurrent_connections as usize))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Decides whether (and how) this gateway can issue X.509 SVIDs, per the
/// "Trust root vs. issuance capability" split in
/// `docs/design/0001-tls-mtls-termination.md`:
///
/// - `ca.cert_path` + `ca.key_path` both set → self-issuing: load and use them.
/// - `ca.cert_path` set, `ca.key_path` absent → verify-only: no `LocalCa` at all.
/// - Neither set, but `tls.client_auth != None` → dev convenience: generate
///   an ephemeral CA.
/// - Otherwise: no CA needed, `POST /v1/svid/x509` will always 501.
fn resolve_ca(
    config: &GatewayConfig,
    registry: &Registry,
) -> Result<Option<Arc<dyn CertificateAuthority + Send + Sync>>, Box<dyn std::error::Error>> {
    if let Some(ca_config) = &config.ca {
        match (&ca_config.cert_path, &ca_config.key_path) {
            (Some(cert_path), Some(key_path)) => {
                let ca = LocalCa::load(registry.clone(), cert_path, key_path, ca_config.ttl_seconds)?;
                return Ok(Some(Arc::new(ca)));
            }
            (Some(_), None) => {
                tracing::info!(
                    "ca.cert_path configured without ca.key_path — verify-only mode; \
                     POST /v1/svid/x509 will return 501"
                );
                return Ok(None);
            }
            (None, _) => {} // fall through to the ephemeral-dev-CA check below
        }
    }

    let client_auth_enabled = matches!(
        config.tls.as_ref().map(|tls| tls.client_auth),
        Some(ClientAuth::Optional) | Some(ClientAuth::Required)
    );
    if client_auth_enabled {
        tracing::warn!(
            "client_auth is enabled but no ca.cert_path is configured — generating an \
             ephemeral CA; not for anything a real client should trust long-term"
        );
        let ttl_seconds = config.ca.as_ref().map(|c| c.ttl_seconds).unwrap_or(3600);
        let ca = LocalCa::generate(registry.clone(), ttl_seconds)?;
        return Ok(Some(Arc::new(ca)));
    }

    Ok(None)
}

/// Resolves which CA cert to trust when verifying a presented client
/// certificate — independent of whether *this* gateway can also issue
/// (`ca`, from [`resolve_ca`]). If `ca` holds an issuer, its own root is
/// the trust root (self-issuing or ephemeral-dev cases). Otherwise, in
/// verify-only mode, the trust root is read directly from `ca.cert_path`.
fn resolve_trust_root_der(
    config: &GatewayConfig,
    ca: &Option<Arc<dyn CertificateAuthority + Send + Sync>>,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if let Some(ca) = ca {
        return Ok(Some(ca.root_cert_der().to_vec()));
    }
    if let Some(cert_path) = config.ca.as_ref().and_then(|c| c.cert_path.as_ref()) {
        let certs = load_certs(cert_path)?;
        return Ok(certs.first().map(|cert| cert.to_vec()));
    }
    Ok(None)
}

/// A connection's verified client-certificate identity, if any, plus (Task
/// 8, F5) the RFC 8705 thumbprint of that same certificate for RFC
/// 8705 cert-binding validation. Always present as a request extension
/// (see `serve()`) regardless of whether TLS or client auth is in use at
/// all — both fields are `None` in every case where there isn't a
/// presented certificate, so handlers never need to distinguish "no TLS,"
/// "TLS but no client cert," and "client cert with no SPIFFE SAN" — they
/// all just mean "no source_principal" / "no cert to bind against."
///
/// `spiffe_id` is `None` whenever the cert has no parseable SPIFFE URI SAN
/// even if a cert *was* presented; `cert_thumbprint`, by contrast, is
/// `Some` for any presented cert regardless of its SAN shape — cert
/// binding cares about "is this the same certificate," not about identity.
#[derive(Clone)]
struct PeerIdentity {
    spiffe_id: Option<SpiffeId>,
    cert_thumbprint: Option<String>,
}

impl PeerIdentity {
    const NONE: PeerIdentity = PeerIdentity {
        spiffe_id: None,
        cert_thumbprint: None,
    };
}

/// Pulls the verified peer certificate's SPIFFE ID (a URI SAN entry) and
/// RFC 8705 thumbprint out of a just-completed TLS handshake, if the
/// caller presented a certificate at all.
fn extract_peer_identity(tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> PeerIdentity {
    let (_io, connection) = tls_stream.get_ref();
    let leaf_cert = connection.peer_certificates().and_then(|certs| certs.first());
    PeerIdentity {
        spiffe_id: leaf_cert.and_then(|cert| extract_spiffe_id_from_der(cert)),
        cert_thumbprint: leaf_cert.map(|cert| compute_cert_thumbprint_x5t_s256(cert)),
    }
}

fn extract_spiffe_id_from_der(der: &[u8]) -> Option<SpiffeId> {
    let (_remainder, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    san.value.general_names.iter().find_map(|name| match name {
        x509_parser::extensions::GeneralName::URI(uri) => uri.parse::<SpiffeId>().ok(),
        _ => None,
    })
}

/// Accepts raw TCP connections, optionally terminates TLS on each one, and
/// serves the same `Router` behind it either way — with that connection's
/// [`PeerIdentity`] (verified client cert, or `None`) attached to every
/// request via `axum::Extension`. Written by hand (rather than
/// `axum::serve`) specifically so this extraction has direct access to the
/// TLS connection object right after the handshake, instead of going
/// through axum's `Connected`/`ConnectInfo` machinery for `MakeService`.
/// How long a peer may take to finish the TLS handshake before its
/// connection is dropped (N9 fix, review 0002).
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

async fn serve(listener: TcpListener, router: Router, tls_acceptor: Option<TlsAcceptor>) {
    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(%error, "failed to accept connection");
                continue;
            }
        };

        let router = router.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let result = match tls_acceptor {
                // N9 fix (review 0002): bound the handshake. A peer that
                // connects and then stalls would otherwise hold this task
                // open indefinitely.
                Some(acceptor) => match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                    Ok(Ok(tls_stream)) => {
                        let peer_identity = extract_peer_identity(&tls_stream);
                        let hyper_service = TowerToHyperService::new(router.layer(Extension(peer_identity)));
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(tls_stream), hyper_service)
                            .await
                    }
                    Ok(Err(error)) => {
                        tracing::debug!(%error, %remote_addr, "TLS handshake failed");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(%remote_addr, "TLS handshake timed out");
                        return;
                    }
                },
                None => {
                    let hyper_service = TowerToHyperService::new(router.layer(Extension(PeerIdentity::NONE)));
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), hyper_service)
                        .await
                }
            };

            if let Err(error) = result {
                tracing::debug!(%error, %remote_addr, "connection error");
            }
        });
    }
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

/// N6 fix (review 0002): the production issuance path. A caller that
/// presented an mTLS client certificate on this connection (the same
/// [`PeerIdentity`] every other admin/proxy route reads) always gets a
/// token bound to it via [`IdentityProvider::issue_jwt_svid_with_cert_binding`]
/// -- binding costs nothing extra whenever there's a certificate to bind
/// to, so it's never conditional on `require_cert_binding`. A caller with
/// no certificate at all falls back to the pre-N6 unbound
/// [`IdentityProvider::issue_jwt_svid`] *unless* `require_cert_binding` is
/// set (explicitly, or by its mTLS-derived default -- see
/// `GatewayConfig::effective_require_cert_binding`), in which case
/// issuance is refused outright rather than quietly handing back a token
/// with nothing to steal-proof it.
async fn issue_svid(
    State(state): State<AppState>,
    peer_identity: Option<Extension<PeerIdentity>>,
    Json(req): Json<IssueRequest>,
) -> Response {
    let peer_cert_thumbprint = peer_identity.and_then(|Extension(peer)| peer.cert_thumbprint);

    let issued = match &peer_cert_thumbprint {
        Some(thumbprint) => state.identity.issue_jwt_svid_with_cert_binding(
            &req.workload_name,
            &req.audience,
            thumbprint,
            &req.bootstrap_token,
        ),
        None if state.require_cert_binding => {
            return error_response(
                StatusCode::FORBIDDEN,
                "a client certificate is required to issue a JWT SVID on this gateway",
            );
        }
        None => state
            .identity
            .issue_jwt_svid(&req.workload_name, &req.audience, &req.bootstrap_token),
    };

    match issued {
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

// --- POST /v1/svid/jwt-with-user (N5 fix, review 0002) ---
//
// The edge-mint path: unlike `/v1/svid/jwt`, this never issues a token for
// another *workload* -- it's meant to be called once, at the mesh's human
// entry point (an edge gateway fronting a browser/CLI session), to mint a
// token that carries a human user principal (`user`) alongside this
// gateway's own SPIFFE ID (`sub`), bridging the human-to-service
// attribution boundary described in review 0002's N5 finding.

/// Loads the verification keys for every configured user IdP (N5 fix,
/// review 0002). Startup fails if a trusted issuer has no `user_idps` entry,
/// since its credentials could then never be checked, or if a `user_idps`
/// entry names an issuer that isn't trusted.
fn load_user_idps(config: &GatewayConfig) -> Result<std::collections::HashMap<String, UserIdp>, Box<dyn std::error::Error>> {
    let mut idps = std::collections::HashMap::new();
    for entry in &config.user_idps {
        if !config.user_issuers.contains(&entry.issuer) {
            return Err(format!("user_idps entry {:?} is not listed in user_issuers", entry.issuer).into());
        }
        let jwks = JsonWebKeySet::from_json(&std::fs::read_to_string(&entry.jwks_path)?)?;
        let idp = UserIdp::new(
            entry.issuer.clone(),
            jwks,
            entry.audience.clone(),
            entry.principal_claim.clone(),
        );
        idps.insert(entry.issuer.clone(), idp);
    }
    for issuer in &config.user_issuers {
        if !idps.contains_key(issuer) {
            return Err(format!("user_issuers lists {issuer:?} but no user_idps entry provides its keys").into());
        }
    }
    Ok(idps)
}

/// Loads the F11 capability policy from `capability_policy_path`, or returns
/// `None` when no policy is configured. An unconfigured policy disables
/// capability checks, and the gateway logs that at startup so the choice is
/// visible.
fn load_capability_policy(
    config: &GatewayConfig,
) -> Result<Option<Arc<CapabilityPolicyHandle>>, Box<dyn std::error::Error>> {
    let Some(path) = &config.capability_policy_path else {
        tracing::warn!("no capability_policy_path configured -- capability checks are disabled");
        return Ok(None);
    };
    let policy = CapabilityPolicy::from_file(path, now_unix_secs())?;
    let handle = Arc::new(CapabilityPolicyHandle::new(policy));
    // The watcher runs for the life of the process. It is spawned here because
    // this runs inside the tokio runtime, from `main`.
    tokio::spawn(watch_capability_policy(
        handle.clone(),
        path.clone(),
        std::time::Duration::from_secs(config.capability_policy_reload_secs.max(1)),
    ));
    Ok(Some(handle))
}

#[derive(Deserialize)]
struct IssueJwtWithUserRequest {
    /// The human user's credential: an RS256 JWT from the IdP named by
    /// `user_issuer`. It must carry that IdP's `iss` and this gateway's
    /// configured `aud`, be unexpired, and be signed by a key in the IdP's
    /// JWKS. The principal is taken from the claim configured in
    /// `user_idps`. The credential is never trusted as a bare string.
    user_credential: String,
    /// Which trusted IdP issued `user_credential` (e.g.
    /// `auth.corp.internal`). Checked against `GatewayConfig::user_issuers`
    /// -- see `IdentityProvider::issue_jwt_svid_with_user`.
    user_issuer: String,
}

#[derive(Serialize)]
struct IssueJwtWithUserResponse {
    token: String,
    expires_at: i64,
}

async fn issue_svid_with_user(
    State(state): State<AppState>,
    Json(req): Json<IssueJwtWithUserRequest>,
) -> Response {
    // N5 fix (review 0002): verify the credential before trusting any
    // principal from it. The identity provider's own issuer check still runs
    // below, as a second guard.
    let principal = match state.user_idps.get(&req.user_issuer) {
        None => {
            return error_response(StatusCode::UNAUTHORIZED, format!("untrusted user issuer: {}", req.user_issuer))
        }
        Some(idp) => match idp.verify(&req.user_credential) {
            Ok(principal) => principal,
            Err(error) => return error_response(StatusCode::UNAUTHORIZED, error.to_string()),
        },
    };

    match state.identity.issue_jwt_svid_with_user(
        &state.gateway_id,
        &principal,
        &req.user_issuer,
        &state.user_issuers,
    ) {
        Ok(issued) => (
            StatusCode::OK,
            Json(IssueJwtWithUserResponse {
                token: issued.token,
                expires_at: issued.expires_at,
            }),
        )
            .into_response(),
        Err(IdentityError::UntrustedUserIssuer(issuer)) => {
            error_response(StatusCode::UNAUTHORIZED, format!("untrusted user issuer: {issuer}"))
        }
        Err(e) => error_response(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

// --- POST /v1/svid/x509 ---

#[derive(Deserialize)]
struct IssueX509Request {
    workload_name: String,
    bootstrap_token: String,
    csr_pem: String,
}

#[derive(Serialize)]
struct IssueX509Response {
    cert_pem: String,
    expires_at: i64,
}

async fn issue_x509_svid(State(state): State<AppState>, Json(req): Json<IssueX509Request>) -> Response {
    let Some(ca) = &state.ca else {
        return error_response(
            StatusCode::NOT_IMPLEMENTED,
            "this gateway does not hold CA signing key material; obtain X.509 SVIDs from your organization's CA",
        );
    };

    match ca.sign_csr(&req.workload_name, &req.csr_pem, &req.bootstrap_token) {
        Ok(signed) => (
            StatusCode::OK,
            Json(IssueX509Response {
                cert_pem: signed.cert_pem,
                expires_at: signed.expires_at,
            }),
        )
            .into_response(),
        Err(CaError::UnknownWorkload(name)) => {
            error_response(StatusCode::NOT_FOUND, format!("unknown workload: {name}"))
        }
        Err(CaError::InvalidBootstrapToken) => error_response(StatusCode::UNAUTHORIZED, "invalid bootstrap token"),
        Err(e @ CaError::SanMismatch { .. }) => error_response(StatusCode::FORBIDDEN, e.to_string()),
        Err(e @ CaError::MalformedCsr(_)) => error_response(StatusCode::BAD_REQUEST, e.to_string()),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

// --- POST /v1/authorize ---

#[derive(Deserialize)]
struct AuthorizeRequest {
    destination: String,
    obo_token: Option<String>,
    /// Accepted for backward wire-compatibility with existing callers (see
    /// README's `/v1/authorize` shape), but deliberately never read: the
    /// F1 fix means chain depth/membership come only from `obo_token`'s
    /// signed `act` claim, never from a caller-supplied chain string.
    #[allow(dead_code)]
    caller_chain: Option<String>,
}

#[derive(Serialize)]
struct AuthorizeResponse {
    allow: bool,
    deny_reason: String,
}

async fn authorize(
    State(state): State<AppState>,
    peer_identity: Option<Extension<PeerIdentity>>,
    Json(req): Json<AuthorizeRequest>,
) -> Response {
    let Ok(destination) = req.destination.parse::<SpiffeId>() else {
        return error_response(StatusCode::BAD_REQUEST, "destination is not a valid SPIFFE ID");
    };
    let peer = peer_identity.map(|Extension(peer)| peer);
    let source_principal = peer.as_ref().and_then(|peer| peer.spiffe_id.clone());
    let peer_cert_thumbprint = peer.as_ref().and_then(|peer| peer.cert_thumbprint.clone());

    let request = ValidationRequest {
        destination: &destination,
        source_principal: source_principal.as_ref(),
        // F1 fix: `obo::validate` never reads `caller_chain` for a
        // decision — chain depth and membership come from the signed
        // `act` claim on `obo_token` instead (see `obo.rs`'s doc comment).
        // A caller-supplied chain string is never forwarded into the
        // decision path, even though validate() would ignore it anyway —
        // this keeps the call site honest about what actually matters.
        caller_chain: None,
        obo_token: req.obo_token.as_deref(),
    };
    // F5 fix: also enforce RFC 8705 cert binding, same as the proxy path.
    let decision = validate_with_cert_binding_and_clock_skew(
        &state.registry,
        state.identity.verifier(),
        &request,
        peer_cert_thumbprint.as_deref(),
        now_unix_secs(),
        state.clock_skew_tolerance_secs,
    );

    (
        StatusCode::OK,
        Json(AuthorizeResponse {
            allow: decision.is_allow(),
            deny_reason: decision.deny_reason_str().to_string(),
        }),
    )
        .into_response()
}

// --- POST /v1/token-exchange ---

/// N2 fix (review 0002): the admin listener's peer certificate thumbprint
/// (from the same [`PeerIdentity`] every other admin/proxy route reads --
/// `None` whenever the connection presented no TLS client certificate at
/// all, e.g. mTLS disabled in dev) is passed straight into
/// `exchange_token_with_cert_binding`, which both validates the inbound
/// token's `cnf` (if any) against it and re-binds the newly minted token to
/// it -- so a token exchanged at this gateway is always bound to *this*
/// hop's own certificate, never whatever certificate (or lack of one) the
/// inbound token happened to carry.
async fn handle_token_exchange(
    State(state): State<AppState>,
    peer_identity: Option<Extension<PeerIdentity>>,
    Json(req): Json<TokenExchangeRequest>,
) -> Response {
    let caller_cert_thumbprint = peer_identity.and_then(|Extension(peer)| peer.cert_thumbprint);

    // Task 6 (N3 fix, review 0002): the inbound token must be addressed to
    // *this* gateway's own protected workload -- never some other
    // gateway's -- and its signed delegation chain must not already be at
    // or past this gateway's configured maximum. `max_chain_depth` comes
    // from the same registry entry (`max_obo_chain_depth`) that governs
    // every other chain-depth check in this crate; a gateway whose own
    // protected workload isn't registered at all falls back to the same
    // conservative `DEFAULT_MAX_OBO_CHAIN_DEPTH` `obo::validate` uses.
    let max_chain_depth = state
        .registry
        .get(&state.protected_workload)
        .map(|entry| entry.max_obo_chain_depth)
        .unwrap_or(DEFAULT_MAX_OBO_CHAIN_DEPTH);

    match exchange_token_with_cert_binding(
        &req.subject_token,
        &req.audience,
        &state.protected_workload,
        max_chain_depth,
        state.identity.as_ref(),
        state.identity.verifier(),
        &state.gateway_id,
        state.token_exchange_ttl_secs,
        now_unix_secs(),
        caller_cert_thumbprint.as_deref(),
    ) {
        Ok((access_token, expires_in)) => (
            StatusCode::OK,
            Json(TokenExchangeResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in,
            }),
        )
            .into_response(),
        Err(e @ TokenExchangeError::InvalidToken) => error_response(StatusCode::BAD_REQUEST, e.to_string()),
        Err(e @ TokenExchangeError::ExpiredToken) => error_response(StatusCode::UNAUTHORIZED, e.to_string()),
        Err(e @ TokenExchangeError::NotYetValid) => error_response(StatusCode::UNAUTHORIZED, e.to_string()),
        Err(e @ TokenExchangeError::InvalidAudience) => error_response(StatusCode::BAD_REQUEST, e.to_string()),
        Err(e @ TokenExchangeError::AudienceMismatch) => error_response(StatusCode::FORBIDDEN, e.to_string()),
        Err(e @ TokenExchangeError::ChainDepthExceeded) => error_response(StatusCode::FORBIDDEN, e.to_string()),
        Err(e @ TokenExchangeError::CertificateBindingMismatch) => {
            error_response(StatusCode::FORBIDDEN, e.to_string())
        }
        Err(e @ TokenExchangeError::InternalError) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    }
}

// --- fallback: the actual reverse proxy ---

#[derive(Serialize)]
struct DenyBody {
    deny_reason: String,
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_string)
}

// --- F12: W3C TraceContext propagation ---

/// Adapts an axum `HeaderMap` so `opentelemetry`'s propagators (see
/// `extract_trace_context`) can read `traceparent`/`tracestate` straight
/// out of it.
struct HeaderExtractor<'a>(&'a HeaderMap);

impl<'a> Extractor for HeaderExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|name| name.as_str()).collect()
    }
}

/// The write-side counterpart to [`HeaderExtractor`] — lets a propagator
/// write `traceparent`/`tracestate` straight into an outbound `HeaderMap`,
/// whether that's the response going back to the caller or the request
/// forwarded to the upstream. A header value a propagator produces that
/// somehow isn't valid for an HTTP header is silently dropped rather than
/// panicking — never hit in practice (`TraceContextPropagator` only ever
/// emits ASCII hex and a restricted `tracestate` grammar), but `Injector`
/// is a general-purpose trait and this keeps the impl total.
struct HeaderInjector<'a>(&'a mut HeaderMap);

impl<'a> Injector for HeaderInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(key.as_bytes()),
            axum::http::HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, value);
        }
    }
}

/// Extracts a W3C TraceContext from inbound request headers via the
/// globally-configured propagator (see `init_tracing`). Absent or
/// malformed `traceparent`/`tracestate` headers simply yield an empty
/// context — the same as starting a fresh trace — never an error callers
/// have to handle.
fn extract_trace_context(headers: &HeaderMap) -> OtelContext {
    global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(headers)))
}

/// Injects `cx`'s span context back out as `traceparent`/`tracestate`
/// headers. Called on both the response handed back to the caller and the
/// request forwarded to the upstream (see `proxy_handler` and
/// `forward_to_upstream`), so every hop of a delegation chain — including
/// the original caller, who gets it echoed straight back — carries the
/// same trace ID end-to-end.
fn inject_trace_context(cx: &OtelContext, headers: &mut HeaderMap) {
    global::get_text_map_propagator(|propagator| propagator.inject_context(cx, &mut HeaderInjector(headers)));
}

/// Attaches `cx`'s propagated trace headers onto an outgoing `Response`,
/// whether the request was allowed (forwarded upstream) or denied —
/// tracing needs the same trace ID back either way, and a 403 is exactly
/// as interesting to a trace as a 200.
fn with_trace_headers(mut response: Response, cx: &OtelContext) -> Response {
    inject_trace_context(cx, response.headers_mut());
    response
}

/// Records verified OBO claims onto `cx`'s span — never the unsigned
/// `X-SPIFFE-*` headers (see this module's F2 note above `proxy_handler`),
/// only claims `obo::validate_with_cert_binding` has already told us are
/// trustworthy (`decision == Allow`) or, on a deny, whatever the signature
/// verification alone can still vouch for, for audit purposes.
///
/// Attribute names follow the brief's F12 naming:
/// - `obo.immediate_caller` — the verified direct caller. N1 fix (review
///   0002): this is `zero_trust::current_actor(claims)` (the outermost
///   `act.sub`, or `sub` itself with no delegation) — never bare `sub`,
///   which names the chain's *originator* and would misreport a delegated
///   token's immediate caller as whoever started the chain. Falls back to
///   the mTLS-verified `source_principal` for a direct, tokenless call.
/// - `obo.user_principal` — the signed `user` claim, if the token carries
///   one (the originating human/service the whole chain acts on behalf
///   of).
/// - `obo.delegation_depth` — `claims.delegation_chain().len()`: the
///   signed chain's depth, never the unsigned `X-SPIFFE-Caller-Chain`
///   header.
/// - `obo.delegation_chain` — that same signed chain, rendered as a single
///   string for a trace UI to display directly.
fn record_obo_span_attributes(
    cx: &OtelContext,
    decision: &Decision,
    verifier: &zero_trust::JwtVerifier,
    obo_token: Option<&str>,
    source_principal: Option<&SpiffeId>,
) {
    let span = cx.span();
    let verified_claims = obo_token.and_then(|token| verifier.verify_signature(token).ok());

    match decision {
        Decision::Allow => {
            if let Some(claims) = &verified_claims {
                let chain = claims.delegation_chain();
                // Safe to call `current_actor` (which panics on an
                // unparseable chain entry) only because `decision` is
                // already `Allow` here: `obo::validate` only ever returns
                // `Allow` after its own chain-entry check has confirmed
                // every hop in this same `delegation_chain()` parses as a
                // SPIFFE ID.
                span.set_attribute(KeyValue::new("obo.immediate_caller", current_actor(claims).to_string()));
                span.set_attribute(KeyValue::new("obo.delegation_depth", chain.len() as i64));
                span.set_attribute(KeyValue::new("obo.delegation_chain", chain.join(" -> ")));
                if let Some(user) = claims.extract_user_principal() {
                    span.set_attribute(KeyValue::new("obo.user_principal", user));
                }
            } else if let Some(source) = source_principal {
                // Direct-call path (no OBO token at all): the mTLS-verified
                // peer identity is the only -- and entire -- delegation
                // chain.
                span.set_attribute(KeyValue::new("obo.immediate_caller", source.to_string()));
                span.set_attribute(KeyValue::new("obo.delegation_depth", 1i64));
                span.set_attribute(KeyValue::new("obo.delegation_chain", source.to_string()));
            }
        }
        Decision::Deny(reason) => {
            span.set_status(Status::error(reason.as_str().to_string()));
            span.set_attribute(KeyValue::new("deny_reason", reason.as_str()));
            // Audit-critical (per the brief): record whatever verified
            // identity is available even on a deny, same signed-claims-only
            // rule as the Allow path above -- an invalid/absent token or
            // signature simply means there's nothing trustworthy to record.
            if let Some(claims) = &verified_claims {
                // Deliberately `claims.sub`, not `current_actor(claims)`,
                // here: the deny may be exactly `InvalidChainEntry` (an
                // unparseable hop), in which case `current_actor` would
                // panic. `sub` is always present and already a validated
                // SPIFFE ID in every other case, so it's the only field
                // safe to read unconditionally on a deny.
                span.set_attribute(KeyValue::new("obo.attempted_caller", claims.sub.clone()));
            } else if let Some(source) = source_principal {
                span.set_attribute(KeyValue::new("obo.attempted_caller", source.to_string()));
            }
        }
    }
}

// Field names deliberately match the blueprint's ADR-0008 OTEL span
// attributes (`obo.caller_principal`, `obo.chain`, `obo.user_principal`,
// `obo.token_ttl_seconds`) so traces from this project line up with what
// the original blueprint's OTEL Collector pipeline expects. Declared as
// `Empty` here (rather than just passed at the `tracing::info!` call site
// below) because a `tracing` span's field set is fixed at creation time —
// `Span::record` can only fill in a value for a field that was already
// declared, never add a new one.
//
// N11 fix (review 0002): `obo.chain` itself is now only ever recorded from
// the verified OBO token's signed `delegation_chain()` -- never the
// unsigned `X-SPIFFE-Caller-Chain` header, which any backend sitting
// between the caller and this gateway could set to anything. That header,
// when present, is instead recorded under the separate `obo.chain_unverified`
// field below -- useful for troubleshooting, but clearly marked as never
// trusted, same as `obo.user_principal_unverified` already does for the
// user-principal header (F2 fix).
/// Resolves which workload identity and upstream backend a proxied
/// request should be forwarded to (F14 / Task 1: multi-backend routing).
///
/// Tries `state.route_table` first; when it's empty, or no configured
/// route matches this request's method/path/host, falls back to the
/// gateway's single `protected_workload`/`upstream_addr` -- exact pre-F14
/// behavior, so a gateway that never configures `routes:` is completely
/// unaffected by this function's existence.
fn resolve_route(state: &AppState, method: &str, path: &str, host: Option<&str>) -> (String, String) {
    if !state.route_table.is_empty() {
        if let Some(resolved) = state.route_table.resolve(method, path, host) {
            return resolved;
        }
    }
    (state.protected_workload.to_string(), state.upstream_addr.clone())
}

#[tracing::instrument(
    skip_all,
    fields(
        obo.caller_principal = tracing::field::Empty,
        obo.chain = tracing::field::Empty,
        // N11 fix (review 0002): the raw, unverified `X-SPIFFE-Caller-Chain`
        // header is recorded under this clearly-unverified attribute,
        // never under `obo.chain` -- see the doc comment above
        // `resolve_route` for the full rationale.
        obo.chain_unverified = tracing::field::Empty,
        obo.user_principal = tracing::field::Empty,
        // F2 fix: the raw, unverified `X-SPIFFE-User-Principal` header is
        // recorded under this clearly-unverified attribute, never under
        // `obo.user_principal` -- see the deny_reason reasoning in
        // `proxy_handler` below.
        obo.user_principal_unverified = tracing::field::Empty,
        obo.token_ttl_seconds = tracing::field::Empty,
        allow = tracing::field::Empty,
        deny_reason = tracing::field::Empty,
    )
)]
async fn proxy_handler(
    State(state): State<AppState>,
    peer_identity: Option<Extension<PeerIdentity>>,
    req: Request,
) -> Response {
    let (parts, body) = req.into_parts();

    // N9 fix (review 0002): enforce the limit while buffering, not after. An
    // unbounded read lets one request exhaust memory before the size check
    // in `forward_to_upstream` ever runs. `to_bytes` stops at the limit and
    // errors, so an oversized body never gets fully buffered.
    let body_bytes = match axum::body::to_bytes(body, state.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds the configured limit or could not be read",
            )
        }
    };

    // F12 fix: extract whatever W3C TraceContext the caller sent (absent or
    // malformed `traceparent`/`tracestate` just yields an empty context —
    // the same as starting a fresh trace) and start this hop's span as its
    // child, so a single delegation chain across multiple gateways shows up
    // as one trace rather than several disconnected ones.
    let parent_trace_cx = extract_trace_context(&parts.headers);
    let otel_span = global::tracer("zt-gateway").start_with_context("gateway_request", &parent_trace_cx);
    let trace_cx = parent_trace_cx.with_span(otel_span);

    let peer = peer_identity.map(|Extension(peer)| peer);
    let source_principal = peer.as_ref().and_then(|peer| peer.spiffe_id.clone());
    let peer_cert_thumbprint = peer.as_ref().and_then(|peer| peer.cert_thumbprint.clone());
    let obo_token = header_str(&parts.headers, HEADER_OBO_TOKEN);
    let caller_chain = header_str(&parts.headers, HEADER_CALLER_CHAIN);
    let user_principal = header_str(&parts.headers, HEADER_USER_PRINCIPAL);

    // F14 / Task 1: resolve which workload/upstream this request targets
    // -- either a matching `state.route_table` entry, or (empty table / no
    // match) the gateway's single `protected_workload`/`upstream_addr`,
    // exactly as before this feature existed.
    let host_header = header_str(&parts.headers, "host");
    let (routed_workload_id, routed_upstream_addr) =
        resolve_route(&state, parts.method.as_str(), parts.uri.path(), host_header.as_deref());

    let destination: SpiffeId = match routed_workload_id.parse() {
        Ok(id) => id,
        Err(_) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                "misconfigured route: workload_id is not a valid SPIFFE ID",
            );
        }
    };
    // Validate the resolved workload against the registry before
    // forwarding anything to it -- a route pointing at an unregistered
    // workload is an operator misconfiguration, not something to silently
    // proxy through.
    if state.registry.get(&destination).is_none() {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "misconfigured route: workload_id not found in registry",
        );
    }

    let request = ValidationRequest {
        destination: &destination,
        source_principal: source_principal.as_ref(),
        obo_token: obo_token.as_deref(),
        // F1 fix: never feed the unsigned `X-SPIFFE-Caller-Chain` header
        // into the decision -- `obo::validate` computes chain depth and
        // membership from the signed `act` claim instead. `caller_chain`
        // (the local variable) is still read below, but only for tracing
        // (`obo.chain`) and the structured log line, never for the
        // decision itself.
        caller_chain: None,
    };
    // F5 fix: enforce RFC 8705 cert binding -- a token minted with a
    // signed `cnf.x5t#S256` claim is rejected outright unless this exact
    // connection's client certificate thumbprint matches it. Tokens with
    // no `cnf` claim (the backward-compatible default) are unaffected.
    // N5 fix (review 0002): pass the trusted user issuers so an edge-minted
    // token's human `user` claim is accepted, instead of being denied as an
    // invalid principal before the capability policy below runs.
    // N12 fix (review 0002): the full proxy decision. It also enforces the
    // configured issuer allow-list and JTI replay check.
    let decision = validate_for_proxy(
        &state.registry,
        state.identity.verifier(),
        &request,
        peer_cert_thumbprint.as_deref(),
        &state.user_issuers,
        &state.trusted_issuers,
        state.jti_cache_enabled,
        state.jti_ttl_secs,
        now_unix_secs(),
        state.clock_skew_tolerance_secs,
    );

    let span = tracing::Span::current();
    span.record("allow", decision.is_allow());
    span.record("deny_reason", decision.deny_reason_str());
    // N11 fix (review 0002): the unsigned `X-SPIFFE-Caller-Chain` header,
    // if present, is recorded only under this separately-named, clearly-
    // unverified attribute -- never under `obo.chain` itself, which is
    // populated further below exclusively from the OBO token's *signed*,
    // already-verified `delegation_chain()` whenever one is available.
    // Observability shows verified facts only; this header is kept around
    // purely for troubleshooting a backend that's still sending it.
    if let Some(chain_header) = &caller_chain {
        span.record("obo.chain_unverified", chain_header.as_str());
    }
    // F2 fix: the raw `X-SPIFFE-User-Principal` header is never trustworthy
    // (any caller can set it to anything), so it is recorded only under
    // this distinctly-named, clearly-unverified attribute -- never under
    // `obo.user_principal`, which below is populated exclusively from the
    // OBO token's *signed* `user` claim, already validated by
    // `obo::validate` as a well-formed SPIFFE ID whenever the decision is
    // Allow.
    if let Some(up) = &user_principal {
        span.record("obo.user_principal_unverified", up.as_str());
    }
    // Only meaningful once the decision is Allow -- re-verifying the token
    // here is purely to read its claims for tracing (obo::validate doesn't
    // expose them), not a second authorization decision.
    //
    // N10 fix (review 0002): this same *verified* identity (never anything
    // read straight off a client-supplied header) is also what
    // `forward_to_upstream` attaches to the upstream request as a
    // gateway-owned `X-ZT-Verified-*` header, after stripping whatever
    // delegation headers the client itself sent -- see
    // `DELEGATION_HEADERS_TO_STRIP`'s doc comment.
    let mut verified_caller: Option<SpiffeId> = None;
    let mut verified_chain: Option<Vec<String>> = None;
    let mut verified_user: Option<String> = None;
    if decision.is_allow() {
        if let Some(token) = obo_token.as_deref() {
            if let Ok(claims) = state.identity.verifier().verify_signature(token) {
                // N1 fix: `current_actor`, not `claims.sub` -- the decision
                // is already `Allow`, so `obo::validate` has already
                // confirmed `current_actor` (not the originator) is what
                // was actually authorized here. Safe to call unconditionally:
                // `Allow` implies every chain entry already parsed as a
                // SPIFFE ID.
                let actor = current_actor(&claims);
                span.record("obo.caller_principal", actor.to_string().as_str());
                span.record("obo.token_ttl_seconds", claims.exp - now_unix_secs());
                if let Some(user) = claims.user.as_deref() {
                    span.record("obo.user_principal", user);
                }
                // N11 fix (review 0002): `obo.chain` comes from this
                // verified token's signed `delegation_chain()` -- never
                // from the unsigned `X-SPIFFE-Caller-Chain` header (see
                // `obo.chain_unverified` above, recorded separately and
                // never trusted).
                let chain = claims.delegation_chain();
                span.record("obo.chain", chain.join(" -> ").as_str());
                verified_chain = Some(chain);
                // F11: the signed `user` claim is the verified user principal
                // the capability policy grants against.
                verified_user = claims.user.clone();
                verified_caller = Some(actor);
            }
        } else if let Some(sp) = &source_principal {
            span.record("obo.caller_principal", sp.to_string().as_str());
            verified_caller = Some(sp.clone());
        }
    }

    // Structured fields deliberately mirror the blueprint Rego policies'
    // decision_log shape (allow, destination, obo_present, obo_chain,
    // deny_reason) -- kept as a plain log line alongside the span
    // attributes above, since stdout logs and OTEL traces serve different
    // consumers (grep/kubectl logs vs. a tracing UI).
    tracing::info!(
        allow = decision.is_allow(),
        destination = %destination,
        source_principal = source_principal.as_ref().map(|id| id.to_string()),
        obo_present = obo_token.is_some(),
        obo_chain = caller_chain.as_deref().unwrap_or(""),
        deny_reason = decision.deny_reason_str(),
        "authorization decision"
    );

    // F12 fix: record verified OBO claims onto the OTel span -- never the
    // unsigned `X-SPIFFE-*` headers (`obo_token`/`source_principal` are
    // already the verified inputs `validate_with_cert_binding` itself used
    // for the decision above, not the raw headers read further up).
    record_obo_span_attributes(
        &trace_cx,
        &decision,
        state.identity.verifier(),
        obo_token.as_deref(),
        source_principal.as_ref(),
    );

    // F11 fix (review 0002): capability policy, applied only after the OBO
    // decision allowed the request. The user comes from the signed `user`
    // claim and the caller from the verified peer or OBO chain, never from
    // client headers.
    let capability = match &state.capability_policy {
        Some(handle) => handle.current().check(
            &CapabilityRequest {
                method: parts.method.as_str(),
                path: parts.uri.path(),
                user: verified_user.as_deref(),
                caller: verified_caller.as_ref(),
            },
            now_unix_secs(),
        ),
        None => CapabilityDecision::Allow("no_policy"),
    };
    if decision.is_allow() && !capability.is_allow() {
        tracing::info!(
            reason = capability.reason(),
            method = %parts.method,
            path = %parts.uri.path(),
            user = verified_user.as_deref().unwrap_or(""),
            caller = verified_caller.as_ref().map(|id| id.to_string()).unwrap_or_default(),
            "capability denied"
        );
    }

    let response = match decision {
        Decision::Allow if !capability.is_allow() => (
            StatusCode::FORBIDDEN,
            Json(DenyBody {
                deny_reason: "capability_denied".to_string(),
            }),
        )
            .into_response(),
        Decision::Allow => {
            forward_to_upstream(
                &state,
                parts,
                body_bytes,
                &trace_cx,
                &routed_upstream_addr,
                verified_caller.as_ref(),
                verified_chain.as_deref(),
            )
            .await
        }
        Decision::Deny(reason) => (
            StatusCode::FORBIDDEN,
            Json(DenyBody {
                deny_reason: reason.as_str().to_string(),
            }),
        )
            .into_response(),
    };

    // Closes out this hop's span (recording its end time) and makes sure
    // the trace ID comes back out on the response regardless of whether
    // the request was allowed or denied -- a 403 is exactly as interesting
    // to a trace as a 200 (F12: "deny events traced with reason").
    trace_cx.span().end();
    with_trace_headers(response, &trace_cx)
}

/// Headers that describe *this* hop's transport framing, not the request
/// itself — stripped before forwarding so `reqwest` can set correct ones
/// for the new connection to the upstream instead of reusing stale values.
const HOP_BY_HOP_HEADERS: [&str; 3] = ["host", "content-length", "connection"];

/// Client-supplied headers that carry OBO delegation state, or sensitive
/// upstream auth material, and must never reach the backend verbatim (N10
/// fix, review 0002): a compromised backend could otherwise replay or
/// forge these to spoof caller identity and impersonate another workload.
/// `forward_to_upstream` removes every one of these on *every* forward --
/// deliberately with no per-route opt-out, since the whole point is that
/// the backend can never be trusted to receive them. Any verified identity
/// the backend does need instead travels through the gateway-owned
/// `X-ZT-Verified-*` headers `forward_to_upstream` adds back afterward,
/// built only from values the decision engine has already vouched for.
///
/// `authorization` is included unconditionally too: whatever bearer
/// credential the *client* presented to this gateway is this gateway's to
/// consume (OBO token exchange, mTLS, etc.), not the backend's to see or
/// replay elsewhere.
const DELEGATION_HEADERS_TO_STRIP: [&str; 4] =
    [HEADER_OBO_TOKEN, HEADER_CALLER_CHAIN, HEADER_USER_PRINCIPAL, "authorization"];

/// Gateway-owned header carrying the verified current actor (see
/// `obo::current_actor`) -- added to the upstream request only when the
/// decision engine actually verified one, and only after
/// `DELEGATION_HEADERS_TO_STRIP` has already removed anything the client
/// itself sent under a similarly-named header. Never populated from a
/// client-supplied value.
const HEADER_VERIFIED_USER: &str = "x-zt-verified-user";

/// Gateway-owned header carrying the verified, chronological delegation
/// chain (`OboClaims::delegation_chain()`), same verified-only rule as
/// [`HEADER_VERIFIED_USER`].
const HEADER_VERIFIED_CHAIN: &str = "x-zt-verified-chain";

/// Why [`read_upstream_body_limited`] gave up on an upstream response body.
enum UpstreamBodyError {
    /// The body grew past the configured limit.
    TooLarge,
    /// The upstream connection failed mid-body.
    Read,
}

/// Reads an upstream response body chunk by chunk, stopping as soon as it
/// would exceed `limit` (N9 fix, review 0002). A misbehaving or hostile
/// upstream therefore can't make this gateway buffer an unbounded body.
async fn read_upstream_body_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<axum::body::Bytes, UpstreamBodyError> {
    let mut buffer = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| UpstreamBodyError::Read)? {
        if buffer.len() + chunk.len() > limit {
            return Err(UpstreamBodyError::TooLarge);
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer.into())
}

async fn forward_to_upstream(
    state: &AppState,
    parts: axum::http::request::Parts,
    body_bytes: axum::body::Bytes,
    trace_cx: &OtelContext,
    upstream_addr: &str,
    verified_caller: Option<&SpiffeId>,
    verified_chain: Option<&[String]>,
) -> Response {
    // Check body size limit (F6 fix)
    if body_bytes.len() > state.max_body_bytes {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "payload too large");
    }

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    // F14 / Task 1: `upstream_addr` is the route-resolved backend (or the
    // gateway's single configured `upstream_addr` when routing doesn't
    // apply -- see `resolve_route`), not necessarily `state.upstream_addr`
    // itself.
    let url = format!("{}{}", upstream_addr.trim_end_matches('/'), path_and_query);

    let mut headers = parts.headers.clone();
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
    // N10 fix (review 0002): strip delegation headers -- and `Authorization`
    // -- unconditionally before anything else touches this request, so
    // nothing below can accidentally reintroduce a client-supplied value
    // under one of these names. See `DELEGATION_HEADERS_TO_STRIP`'s doc
    // comment for why there's no opt-out.
    for name in DELEGATION_HEADERS_TO_STRIP {
        headers.remove(name);
    }
    // F12 fix: propagate the same trace context onward to the upstream, so
    // a delegation chain that keeps going past this gateway still shows up
    // as one trace rather than ending here.
    inject_trace_context(trace_cx, &mut headers);

    // N10 fix (review 0002): attach gateway-owned, VERIFIED replacements --
    // added only after the strip above, and only from `verified_caller`/
    // `verified_chain`, which `proxy_handler` populates exclusively from
    // claims the decision engine has already authenticated (never from the
    // raw `X-SPIFFE-*` headers just removed). Absent whenever the request
    // was a direct, tokenless call with no mTLS-verified peer either.
    if let Some(caller) = verified_caller {
        if let Ok(value) = axum::http::HeaderValue::from_str(&caller.to_string()) {
            headers.insert(HeaderName::from_static(HEADER_VERIFIED_USER), value);
        }
    }
    if let Some(chain) = verified_chain {
        if !chain.is_empty() {
            if let Ok(value) = axum::http::HeaderValue::from_str(&chain.join(",")) {
                headers.insert(HeaderName::from_static(HEADER_VERIFIED_CHAIN), value);
            }
        }
    }

    let upstream_request = state
        .http_client
        .request(parts.method, url)
        .headers(headers)
        .body(body_bytes);

    let upstream_response = match upstream_request.send().await {
        Ok(resp) => resp,
        Err(e) => {
            if e.is_timeout() {
                tracing::warn!(error = %e, "upstream request timeout");
                return error_response(StatusCode::GATEWAY_TIMEOUT, "upstream request timeout");
            }
            tracing::warn!(error = %e, "upstream request failed");
            return error_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    let status = upstream_response.status();
    let response_headers = upstream_response.headers().clone();
    let response_body = match read_upstream_body_limited(upstream_response, state.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(UpstreamBodyError::TooLarge) => {
            return error_response(StatusCode::BAD_GATEWAY, "upstream response exceeds the configured limit")
        }
        Err(UpstreamBodyError::Read) => {
            return error_response(StatusCode::BAD_GATEWAY, "failed to read upstream response")
        }
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
    use zero_trust::Route;

    const TRUST_DOMAIN: &str = "chakra.internal";
    const INVENTORY: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
    const ORDERS: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";
    const API_GATEWAY: &str = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway";

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

  - name: api-gateway
    spiffe_id: {API_GATEWAY}
    max_obo_chain_depth: 1
    allowed_callers: []
    bootstrap_token: api-gateway-secret
"#
        ))
        .unwrap()
    }

    const GATEWAY_SELF: &str = "spiffe://chakra.internal/ns/zt-gateway/sa/zt-gateway";

    fn test_state(upstream_addr: String) -> AppState {
        let registry = test_registry();
        let issuer = LocalIssuer::generate(registry.clone(), 300).unwrap();
        AppState {
            identity: Arc::new(issuer),
            ca: None,
            registry: Arc::new(registry),
            http_client: reqwest::Client::new(),
            upstream_addr,
            protected_workload: Arc::new(INVENTORY.parse().unwrap()),
            gateway_id: Arc::new(GATEWAY_SELF.parse().unwrap()),
            token_exchange_ttl_secs: 300,
            max_body_bytes: 100 * 1024 * 1024,
            route_table: Arc::new(RouteTable::default()),
            clock_skew_tolerance_secs: zero_trust::DEFAULT_CLOCK_SKEW_SECS,
            user_issuers: Arc::new(Vec::new()),
            user_idps: Arc::new(std::collections::HashMap::new()),
            capability_policy: None,
            trusted_issuers: Arc::new(Vec::new()),
            jti_cache_enabled: false,
            jti_ttl_secs: 300,
            // Most existing tests call `/v1/svid/jwt` with no peer
            // certificate at all and expect the pre-N6 unbound token back
            // -- `false` preserves that. Tests exercising the N6 gate
            // itself override this field directly.
            require_cert_binding: false,
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

    /// Binds a real local upstream that always returns `200 OK` and records
    /// the headers of the *last* request it received — used by the N10
    /// tests below to prove what `forward_to_upstream` actually puts on the
    /// wire to the backend (not just what the gateway's own response to the
    /// client looks like).
    async fn spawn_header_capturing_upstream() -> (String, Arc<std::sync::Mutex<Option<HeaderMap>>>) {
        let captured = Arc::new(std::sync::Mutex::new(None));
        let captured_for_handler = captured.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let app = Router::new().fallback(move |headers: HeaderMap| {
            let captured = captured_for_handler.clone();
            async move {
                *captured.lock().unwrap() = Some(headers);
                (SC::OK, "ok")
            }
        });

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        (format!("http://{addr}"), captured)
    }

    // --- N5 fix (review 0002): verified user credentials on the edge-mint path ---

    const USER_IDP: &str = "auth.corp.internal";

    /// Builds state whose only trusted IdP is `USER_IDP`, with keys from a
    /// fresh RSA key. Returns the state and that key's PEM so tests can sign
    /// credentials the IdP would issue.
    fn user_idp_state() -> (AppState, String) {
        use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
        let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        let pem = key.to_pkcs1_pem(LineEnding::LF).unwrap().to_string();
        let jwks = JsonWebKeySet::from_rsa_private_pem("idp-1".to_string(), pem.as_bytes()).unwrap();
        let idp = UserIdp::new(USER_IDP.to_string(), jwks, GATEWAY_SELF.to_string(), "email".to_string());

        let mut state = test_state("http://unused.invalid".to_string());
        state.user_issuers = Arc::new(vec![USER_IDP.to_string()]);
        state.user_idps = Arc::new(std::collections::HashMap::from([(USER_IDP.to_string(), idp)]));
        (state, pem)
    }

    /// Signs an IdP-style RS256 credential under `kid` with the given claims.
    fn sign_idp_credential(pem: &str, kid: &str, claims: serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    fn user_mint_request(credential: &str, issuer: &str) -> Request<Body> {
        let body = serde_json::json!({"user_credential": credential, "user_issuer": issuer}).to_string();
        Request::builder()
            .method("POST")
            .uri("/v1/svid/jwt-with-user")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn user_mint_issues_a_token_for_a_verified_credential() {
        let (state, pem) = user_idp_state();
        let exp = zero_trust::now_unix_secs() + 300;
        let credential = sign_idp_credential(
            &pem,
            "idp-1",
            serde_json::json!({"iss": USER_IDP, "aud": GATEWAY_SELF, "exp": exp, "email": "alice@corp.internal"}),
        );
        let router = build_router(state);

        let response = router.oneshot(user_mint_request(&credential, USER_IDP)).await.unwrap();
        assert_eq!(response.status(), SC::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let token = body["token"].as_str().unwrap();
        let payload_bytes = base64_decode_url_nopad(token.split('.').nth(1).unwrap()).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["user"], "alice@corp.internal");
    }

    #[tokio::test]
    async fn user_mint_rejects_a_credential_signed_by_another_key() {
        let (state, _pem) = user_idp_state();
        let attacker = {
            use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
            rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
                .unwrap()
                .to_pkcs1_pem(LineEnding::LF)
                .unwrap()
                .to_string()
        };
        let exp = zero_trust::now_unix_secs() + 300;
        let forged = sign_idp_credential(
            &attacker,
            "idp-1",
            serde_json::json!({"iss": USER_IDP, "aud": GATEWAY_SELF, "exp": exp, "email": "ceo@corp.internal"}),
        );
        let router = build_router(state);

        let response = router.oneshot(user_mint_request(&forged, USER_IDP)).await.unwrap();
        assert_eq!(response.status(), SC::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn user_mint_rejects_an_untrusted_issuer() {
        let (state, pem) = user_idp_state();
        let exp = zero_trust::now_unix_secs() + 300;
        let credential = sign_idp_credential(
            &pem,
            "idp-1",
            serde_json::json!({"iss": "evil.example", "aud": GATEWAY_SELF, "exp": exp, "email": "a@x"}),
        );
        let router = build_router(state);

        let response = router.oneshot(user_mint_request(&credential, "evil.example")).await.unwrap();
        assert_eq!(response.status(), SC::UNAUTHORIZED);
    }

    #[test]
    fn startup_rejects_a_trusted_issuer_with_no_keys() {
        let yaml = format!(
            "upstream_addr: http://127.0.0.1:8080\nregistry_path: registry.yaml\n\
             protected_workload: spiffe://chakra.internal/ns/inventory/sa/inventory-svc\n\
             user_issuers:\n  - {USER_IDP}\n"
        );
        let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
        assert!(load_user_idps(&config).is_err());
    }

    // --- N12 fix (review 0002): issuer allow-list and JTI replay on the proxy ---

    #[tokio::test]
    async fn proxy_refuses_a_token_from_an_issuer_not_on_the_allow_list() {
        let (upstream_addr, hits) = spawn_test_upstream("ok").await;
        let mut state = test_state(upstream_addr);
        state.trusted_issuers = Arc::new(vec!["spiffe://chakra.internal/ns/other/sa/issuer".to_string()]);
        let issued = state.identity.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();
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

    #[tokio::test]
    async fn proxy_refuses_a_replayed_token_when_jti_replay_is_enabled() {
        let (upstream_addr, hits) = spawn_test_upstream("ok").await;
        let mut state = test_state(upstream_addr);
        state.jti_cache_enabled = true;
        let issued = state.identity.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();
        let router = build_router(state);

        let send = |token: String| {
            Request::builder()
                .method("GET")
                .uri("/some/path")
                .header(HEADER_OBO_TOKEN, token)
                .body(Body::empty())
                .unwrap()
        };
        let first = router.clone().oneshot(send(issued.token.clone())).await.unwrap();
        assert_eq!(first.status(), SC::OK);
        let second = router.oneshot(send(issued.token)).await.unwrap();
        assert_eq!(second.status(), SC::FORBIDDEN, "a replayed jti must be refused");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    // --- F11 fix (review 0002): capability policy on the proxy path ---

    fn policy_state(upstream_addr: String, yaml: &str) -> AppState {
        let mut state = test_state(upstream_addr);
        let policy = CapabilityPolicy::from_yaml_str(yaml, zero_trust::now_unix_secs()).unwrap();
        state.capability_policy = Some(Arc::new(CapabilityPolicyHandle::new(policy)));
        state
    }

    #[tokio::test]
    async fn capability_grant_for_the_verified_caller_reaches_upstream() {
        let (upstream_addr, hits) = spawn_test_upstream("ok").await;
        let yaml = format!("default: deny\nrules:\n  - path: /some/path\n    workloads: [{ORDERS}]\n");
        let state = policy_state(upstream_addr, &yaml);
        let issued = state.identity.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();
        let router = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, issued.token)
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn capability_denial_is_403_and_never_reaches_upstream() {
        let (upstream_addr, hits) = spawn_test_upstream("ok").await;
        // Grants only a different workload, so the verified orders-svc caller
        // matches no rule and the default deny applies.
        let yaml = "default: deny\nrules:\n  - path: /some/path\n    workloads: [spiffe://chakra.internal/ns/billing/sa/billing-svc]\n";
        let state = policy_state(upstream_addr, yaml);
        let issued = state.identity.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();
        let router = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, issued.token)
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::FORBIDDEN);
        assert_eq!(hits.load(Ordering::SeqCst), 0, "a capability-denied request must not be forwarded");
    }

    // --- N9 fix (review 0002): proxy body limits ---

    #[tokio::test]
    async fn oversized_request_body_is_rejected_before_reaching_upstream() {
        let (upstream_addr, hits) = spawn_test_upstream("ok").await;
        let mut state = test_state(upstream_addr);
        state.max_body_bytes = 16;
        let issued = state
            .identity
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();
        let router = build_router(state);

        let request = Request::builder()
            .method("POST")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, issued.token)
            .body(Body::from(vec![b'x'; 64]))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::PAYLOAD_TOO_LARGE);
        assert_eq!(hits.load(Ordering::SeqCst), 0, "an oversized body must never be forwarded");
    }

    #[tokio::test]
    async fn oversized_upstream_response_is_rejected() {
        let (upstream_addr, _hits) = spawn_test_upstream("this upstream body is longer than sixteen bytes").await;
        let mut state = test_state(upstream_addr);
        state.max_body_bytes = 16;
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
        assert_eq!(response.status(), SC::BAD_GATEWAY);
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

    // --- N6 fix (review 0002): production cert-binding issuance ---

    #[tokio::test]
    async fn issue_svid_binds_token_when_caller_presents_a_cert() {
        let state = test_state("http://unused.invalid".to_string());
        // Simulates a caller that completed an mTLS handshake and
        // presented a client certificate -- see `extract_peer_identity`,
        // which populates this same `PeerIdentity` extension from a real
        // TLS connection in production.
        let peer = PeerIdentity {
            spiffe_id: None,
            cert_thumbprint: Some("caller-thumbprint".to_string()),
        };
        let router = build_router(state).layer(Extension(peer));

        let body = r#"{"workload_name":"orders-svc","audience":"spiffe://chakra.internal/ns/inventory/sa/inventory-svc","bootstrap_token":"orders-secret"}"#;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/svid/jwt")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let token = parsed["token"].as_str().unwrap();

        // `state` (and its issuer) was consumed by `build_router` above --
        // decode the JWT payload directly rather than re-deriving a
        // verifier, same as `token_exchange_returns_a_token_with_the_gateway_appended_to_the_chain`
        // does. The point here is the claim *shape* the handler produced
        // (bound by default), not re-proving RS256 signature validity,
        // which `issue_jwt_svid_with_cert_binding_signs_a_token_carrying_the_cnf_claim`
        // (identity.rs) already covers.
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_bytes = base64_decode_url_nopad(payload_b64).expect("jwt payload should be valid base64url");
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["cnf"]["x5t#S256"], "caller-thumbprint");
    }

    #[tokio::test]
    async fn issue_svid_falls_back_to_unbound_when_no_cert_and_binding_not_required() {
        // `test_state()` sets `require_cert_binding: false` -- a caller
        // with no mTLS client certificate at all (no `PeerIdentity`
        // extension layered here, same as a plain-HTTP connection) still
        // gets a token, just an unbound one: the pre-N6 behavior, kept
        // for deployments that haven't turned on mTLS.
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

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let token = parsed["token"].as_str().unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_bytes = base64_decode_url_nopad(payload_b64).expect("jwt payload should be valid base64url");
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert!(payload["cnf"].is_null());
    }

    #[tokio::test]
    async fn issue_svid_rejects_issuance_when_require_cert_binding_and_no_cert_presented() {
        // The strict side of the N6 gate: with `require_cert_binding: true`
        // (what `GatewayConfig::effective_require_cert_binding` defaults
        // to once mTLS is enabled), a caller with no client certificate
        // is refused outright rather than handed an unbound, stealable
        // token.
        let mut state = test_state("http://unused.invalid".to_string());
        state.require_cert_binding = true;
        let router = build_router(state);

        let body = r#"{"workload_name":"orders-svc","audience":"spiffe://chakra.internal/ns/inventory/sa/inventory-svc","bootstrap_token":"orders-secret"}"#;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/svid/jwt")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::FORBIDDEN);
    }

    #[tokio::test]
    async fn issue_svid_binds_token_even_when_require_cert_binding_is_true_and_cert_is_presented() {
        // Binding is unconditional whenever a cert is actually presented
        // -- `require_cert_binding` only ever makes the *missing*-cert
        // case stricter, never the present-cert case looser or redundant.
        let mut state = test_state("http://unused.invalid".to_string());
        state.require_cert_binding = true;
        let peer = PeerIdentity {
            spiffe_id: None,
            cert_thumbprint: Some("caller-thumbprint".to_string()),
        };
        let router = build_router(state).layer(Extension(peer));

        let body = r#"{"workload_name":"orders-svc","audience":"spiffe://chakra.internal/ns/inventory/sa/inventory-svc","bootstrap_token":"orders-secret"}"#;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/svid/jwt")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let token = parsed["token"].as_str().unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_bytes = base64_decode_url_nopad(payload_b64).expect("jwt payload should be valid base64url");
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["cnf"]["x5t#S256"], "caller-thumbprint");
    }

    #[tokio::test]
    async fn issue_x509_svid_returns_501_when_no_ca_is_configured() {
        // test_state()'s ca field is None by construction.
        let state = test_state("http://unused.invalid".to_string());
        let router = build_router(state);

        let body = r#"{"workload_name":"orders-svc","bootstrap_token":"orders-secret","csr_pem":"irrelevant"}"#;
        let request = Request::builder()
            .method("POST")
            .uri("/v1/svid/x509")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn issue_x509_svid_returns_a_cert_for_correct_credentials() {
        use rcgen::{CertificateParams, KeyPair, SanType};

        let mut state = test_state("http://unused.invalid".to_string());
        let ca = zero_trust::LocalCa::generate(test_registry(), 3600).unwrap();
        state.ca = Some(Arc::new(ca));
        let router = build_router(state);

        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![SanType::URI(ORDERS.try_into().unwrap())];
        let csr_pem = params.serialize_request(&key_pair).unwrap().pem().unwrap();

        let body = serde_json::json!({
            "workload_name": "orders-svc",
            "bootstrap_token": "orders-secret",
            "csr_pem": csr_pem,
        })
        .to_string();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/svid/x509")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed["cert_pem"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn token_exchange_returns_a_token_with_the_gateway_appended_to_the_chain() {
        let state = test_state("http://unused.invalid".to_string());
        // N3 fix (review 0002, Task 6): the inbound token's `aud` must now
        // name this gateway's own protected workload (`test_state`'s
        // `protected_workload` is `INVENTORY`) for the exchange to be
        // allowed at all -- a token addressed to some other party (e.g.
        // `API_GATEWAY`, used here before the fix) is exactly the
        // unvalidated-audience hole N3 closes, so it's no longer a valid
        // setup for "the exchange succeeds" tests like this one.
        let issued = state
            .identity
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();
        let router = build_router(state);

        let body = serde_json::json!({
            "subject_token": issued.token,
            "audience": INVENTORY,
        })
        .to_string();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/token-exchange")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["token_type"], "Bearer");
        assert!(parsed["expires_in"].as_u64().unwrap() > 0);
        let new_token = parsed["access_token"].as_str().unwrap();

        // The router (and the `AppState` it consumed) only ever exposes
        // the issuer through the HTTP response here, so this decodes the
        // JWT payload directly (no signature check needed — the point is
        // to confirm the *shape* of the claims the handler produced, not
        // re-derive what `exchange_token`'s own unit tests already prove
        // about signature validity).
        let payload_b64 = new_token.split('.').nth(1).unwrap();
        let payload_bytes =
            base64_decode_url_nopad(payload_b64).expect("jwt payload should be valid base64url");
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["sub"], ORDERS);
        assert_eq!(payload["aud"][0], INVENTORY);
        assert_eq!(payload["act"]["sub"], GATEWAY_SELF);
    }

    /// Minimal base64url (no padding) decoder, just for inspecting a JWT's
    /// payload segment in the test above without pulling in a `base64`
    /// dependency the rest of the crate doesn't otherwise need.
    fn base64_decode_url_nopad(s: &str) -> Option<Vec<u8>> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut lut = [255u8; 256];
        for (i, &c) in ALPHABET.iter().enumerate() {
            lut[c as usize] = i as u8;
        }
        let mut bits: u32 = 0;
        let mut nbits = 0;
        let mut out = Vec::new();
        for c in s.bytes() {
            let v = lut[c as usize];
            if v == 255 {
                return None;
            }
            bits = (bits << 6) | v as u32;
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push((bits >> nbits) as u8);
            }
        }
        Some(out)
    }

    #[tokio::test]
    async fn token_exchange_rejects_an_expired_inbound_token() {
        let mut state = test_state("http://unused.invalid".to_string());
        let registry = test_registry();
        let expired_issuer = LocalIssuer::generate(registry, -1).unwrap();
        let issued = expired_issuer
            .issue_jwt_svid("orders-svc", API_GATEWAY, "orders-secret")
            .unwrap();
        state.identity = Arc::new(expired_issuer);
        let router = build_router(state);

        let body = serde_json::json!({
            "subject_token": issued.token,
            "audience": INVENTORY,
        })
        .to_string();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/token-exchange")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_exchange_rejects_an_invalid_audience() {
        let state = test_state("http://unused.invalid".to_string());
        let issued = state
            .identity
            .issue_jwt_svid("orders-svc", API_GATEWAY, "orders-secret")
            .unwrap();
        let router = build_router(state);

        let body = serde_json::json!({
            "subject_token": issued.token,
            "audience": "not-a-spiffe-id",
        })
        .to_string();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/token-exchange")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::BAD_REQUEST);
    }

    #[tokio::test]
    async fn token_exchange_rejects_a_tampered_token() {
        let state = test_state("http://unused.invalid".to_string());
        let router = build_router(state);

        let body = serde_json::json!({
            "subject_token": "not.a.validtoken",
            "audience": INVENTORY,
        })
        .to_string();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/token-exchange")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::BAD_REQUEST);
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

    // --- N10 fix (review 0002): delegation headers stripped before forward ---

    /// A compromised or merely buggy client could set
    /// `X-SPIFFE-Caller-Chain`/`X-SPIFFE-User-Principal` (and even
    /// `X-SPIFFE-OBO-Token` itself) to anything it likes. Proves none of
    /// those client-supplied values ever reach the backend verbatim, even
    /// on an otherwise-allowed request.
    #[tokio::test]
    async fn delegation_headers_stripped_before_forward() {
        let (upstream_addr, captured) = spawn_header_capturing_upstream().await;
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
            .header(HEADER_CALLER_CHAIN, "spiffe://chakra.internal/ns/forged/sa/forged")
            .header(HEADER_USER_PRINCIPAL, "spiffe://chakra.internal/ns/forged/sa/forged-user")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);

        let received = captured.lock().unwrap().take().expect("upstream should have been hit");
        assert!(
            !received.contains_key(HEADER_OBO_TOKEN),
            "X-SPIFFE-OBO-Token must never reach the backend"
        );
        assert!(
            !received.contains_key(HEADER_CALLER_CHAIN),
            "X-SPIFFE-Caller-Chain must never reach the backend"
        );
        assert!(
            !received.contains_key(HEADER_USER_PRINCIPAL),
            "X-SPIFFE-User-Principal must never reach the backend"
        );
    }

    /// The gateway's own verified identity for this request — not anything
    /// the client sent — is what should show up on the upstream request,
    /// under the gateway-owned `X-ZT-Verified-*` names.
    #[tokio::test]
    async fn verified_headers_added_after_strip() {
        let (upstream_addr, captured) = spawn_header_capturing_upstream().await;
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

        let received = captured.lock().unwrap().take().expect("upstream should have been hit");
        let verified_user = received
            .get(HEADER_VERIFIED_USER)
            .expect("X-ZT-Verified-User should be set on an authenticated request")
            .to_str()
            .unwrap();
        // `orders-svc` is the token's `current_actor` (no delegation chain
        // here, so it's just `sub`) -- the verified immediate caller, which
        // is what N10's gateway-owned header must carry.
        assert_eq!(verified_user, ORDERS);

        let verified_chain = received
            .get(HEADER_VERIFIED_CHAIN)
            .expect("X-ZT-Verified-Chain should be set on an authenticated request")
            .to_str()
            .unwrap();
        assert_eq!(verified_chain, ORDERS);
    }

    /// `Authorization` is whatever bearer credential the *client* presented
    /// to this gateway -- it's this gateway's to consume, never the
    /// backend's to see or replay. Stripped by default, with no per-request
    /// opt-out.
    #[tokio::test]
    async fn authorization_header_stripped_by_default() {
        let (upstream_addr, captured) = spawn_header_capturing_upstream().await;
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
            .header("Authorization", "Bearer client-supplied-credential")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);

        let received = captured.lock().unwrap().take().expect("upstream should have been hit");
        assert!(
            !received.contains_key("authorization"),
            "Authorization must never reach the backend by default"
        );
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

    // --- F14 / Task 1: multi-backend routing wired into `proxy_handler` ---
    //
    // `tests/routing_tests.rs` covers `RouteTable::resolve` itself in
    // isolation; these three exercise `resolve_route`/`proxy_handler`
    // end-to-end through the real `Router`, proving routing decisions
    // actually affect where a request lands and which identity it's
    // validated against.

    #[tokio::test]
    async fn proxy_routes_request_to_matching_route_table_entry() {
        let (default_upstream, default_hits) = spawn_test_upstream("default backend").await;
        let (routed_upstream, routed_hits) = spawn_test_upstream("routed backend").await;

        let mut state = test_state(default_upstream);
        state.route_table = Arc::new(RouteTable::new(vec![Route {
            host_pattern: "*".to_string(),
            path_pattern: "/api/inventory/*".to_string(),
            workload_id: INVENTORY.to_string(),
            upstream_addr: routed_upstream,
        }]));
        let issued = state
            .identity
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();
        let router = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/inventory/items/42")
            .header(HEADER_OBO_TOKEN, issued.token)
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"routed backend");
        assert_eq!(routed_hits.load(Ordering::SeqCst), 1);
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn proxy_falls_back_to_default_upstream_when_no_route_matches() {
        let (default_upstream, default_hits) = spawn_test_upstream("default backend").await;
        let (routed_upstream, routed_hits) = spawn_test_upstream("routed backend").await;

        let mut state = test_state(default_upstream);
        state.route_table = Arc::new(RouteTable::new(vec![Route {
            host_pattern: "*".to_string(),
            path_pattern: "/api/inventory/*".to_string(),
            workload_id: INVENTORY.to_string(),
            upstream_addr: routed_upstream,
        }]));
        let issued = state
            .identity
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();
        let router = build_router(state);

        // Doesn't match the configured route's `/api/inventory/*` pattern,
        // so this falls back to the gateway's single `protected_workload`/
        // `upstream_addr` -- same as if `routes` were never configured.
        let request = Request::builder()
            .method("GET")
            .uri("/completely/unrelated/path")
            .header(HEADER_OBO_TOKEN, issued.token)
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&bytes[..], b"default backend");
        assert_eq!(default_hits.load(Ordering::SeqCst), 1);
        assert_eq!(routed_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn proxy_rejects_a_route_pointing_at_an_unregistered_workload() {
        let (default_upstream, default_hits) = spawn_test_upstream("should never be seen").await;

        let mut state = test_state(default_upstream);
        state.route_table = Arc::new(RouteTable::new(vec![Route {
            host_pattern: "*".to_string(),
            path_pattern: "/api/*".to_string(),
            workload_id: "spiffe://chakra.internal/ns/missing/sa/missing-svc".to_string(),
            upstream_addr: "http://127.0.0.1:1".to_string(),
        }]));
        let router = build_router(state);

        let request = Request::builder()
            .method("GET")
            .uri("/api/whatever")
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::BAD_GATEWAY);
        assert_eq!(default_hits.load(Ordering::SeqCst), 0);
    }

    /// The one test in this project that can't use `tower::oneshot`: TLS is
    /// part of the transport `serve()` wraps around the `Router`, not part
    /// of the `Router`/handler logic itself, so proving it works requires a
    /// real socket and a real TLS handshake on both ends.
    #[tokio::test]
    async fn tls_handshake_succeeds_and_the_proxy_still_denies_without_a_token() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let state = test_state("http://unused.invalid".to_string());
        let router = build_router(state);

        let server_cert =
            ServerCertificate::generate_ephemeral(vec!["localhost".to_string()]).unwrap();
        let trusted_der = server_cert.cert_chain[0].clone();
        let server_config = build_server_config(server_cert, None).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, router, Some(acceptor)));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(trusted_der).unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, tcp).await.unwrap();

        tls_stream
            .write_all(b"GET /some/path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tls_stream.read_to_end(&mut response).await.unwrap();
        let response_text = String::from_utf8_lossy(&response);

        // The TLS handshake succeeded (we got an HTTP response at all) and
        // the request — no X-SPIFFE-OBO-Token — was still denied by the
        // same obo::validate call the plain-HTTP tests exercise.
        assert!(response_text.starts_with("HTTP/1.1 403"), "got: {response_text}");
    }

    /// Builds a client keypair + CSR for `spiffe_id`, has `ca` sign it
    /// (authenticating as `workload_name` via `bootstrap_token`, exactly
    /// the way a real workload would call `POST /v1/svid/x509`), and
    /// returns the signed cert + private key ready to hand to a `rustls`
    /// client config.
    fn build_client_cert(
        ca: &LocalCa,
        workload_name: &str,
        spiffe_id: &str,
        bootstrap_token: &str,
    ) -> (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>) {
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::URI(spiffe_id.try_into().unwrap())];
        let csr_pem = params.serialize_request(&key_pair).unwrap().pem().unwrap();
        let signed = ca.sign_csr(workload_name, &csr_pem, bootstrap_token).unwrap();

        let mut reader = std::io::BufReader::new(signed.cert_pem.as_bytes());
        let cert_der = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            key_pair.serialize_der(),
        ));

        (cert_der, key_der)
    }

    /// Spawns a real TLS-terminating `zt-gateway` instance (mTLS trust root
    /// = `ca.root_cert_der()`) and returns its address plus its own server
    /// certificate DER (for the test client to trust).
    async fn spawn_mtls_server(
        registry: Registry,
        issuer: LocalIssuer,
        ca: &LocalCa,
        protected_workload: &str,
        client_auth: ClientAuth,
        upstream_addr: String,
    ) -> (String, rustls::pki_types::CertificateDer<'static>) {
        let mut state = test_state(upstream_addr);
        state.registry = Arc::new(registry);
        state.identity = Arc::new(issuer);
        state.protected_workload = Arc::new(protected_workload.parse().unwrap());
        let router = build_router(state);

        let server_cert = ServerCertificate::generate_ephemeral(vec!["localhost".to_string()]).unwrap();
        let server_cert_der = server_cert.cert_chain[0].clone();

        let allow_unauthenticated = client_auth == ClientAuth::Optional;
        let verifier = build_client_cert_verifier(ca.root_cert_der(), allow_unauthenticated).unwrap();
        let server_config = build_server_config(server_cert, Some(verifier)).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, router, Some(acceptor)));

        (addr.to_string(), server_cert_der)
    }

    /// Connects over TLS (optionally presenting a client cert), sends one
    /// raw HTTP/1.1 GET carrying `obo_token`, and returns the raw response
    /// text.
    async fn send_request_over_tls(
        addr: &str,
        trusted_server_cert: rustls::pki_types::CertificateDer<'static>,
        client_identity: Option<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>)>,
        obo_token: &str,
    ) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut roots = rustls::RootCertStore::empty();
        roots.add(trusted_server_cert).unwrap();

        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots);

        let client_config = match client_identity {
            Some((cert, key)) => builder.with_client_auth_cert(vec![cert], key).unwrap(),
            None => builder.with_no_client_auth(),
        };

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, tcp).await.unwrap();

        let request = format!(
            "GET /some/path HTTP/1.1\r\nHost: localhost\r\n{HEADER_OBO_TOKEN}: {obo_token}\r\nConnection: close\r\n\r\n"
        );
        tls_stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tls_stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).to_string()
    }

    #[tokio::test]
    async fn mtls_client_cert_matching_obo_subject_is_allowed() {
        let registry = test_registry();
        let ca = LocalCa::generate(registry.clone(), 3600).unwrap();
        let issuer = LocalIssuer::generate(registry.clone(), 300).unwrap();
        let token = issuer.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();
        let (upstream_addr, hits) = spawn_test_upstream("hello from upstream").await;

        let (addr, server_cert_der) =
            spawn_mtls_server(registry, issuer, &ca, INVENTORY, ClientAuth::Optional, upstream_addr).await;
        let (client_cert, client_key) = build_client_cert(&ca, "orders-svc", ORDERS, "orders-secret");

        let response = send_request_over_tls(&addr, server_cert_der, Some((client_cert, client_key)), &token.token).await;
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
        assert!(response.contains("hello from upstream"), "got: {response}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mtls_client_cert_mismatched_with_obo_subject_is_denied() {
        let registry = test_registry();
        let ca = LocalCa::generate(registry.clone(), 3600).unwrap();
        let issuer = LocalIssuer::generate(registry.clone(), 300).unwrap();
        // The OBO token claims to be from orders-svc...
        let token = issuer.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();

        let (addr, server_cert_der) = spawn_mtls_server(
            registry,
            issuer,
            &ca,
            INVENTORY,
            ClientAuth::Optional,
            "http://unused.invalid".to_string(),
        )
        .await;
        // ...but the TLS client cert presented is api-gateway's. Both are
        // legitimately CA-issued — only the mismatch between "who the
        // channel says you are" and "who the token says you are" should be
        // rejected. This is `obo::validate`'s impersonation check, exercised
        // end-to-end for the first time (it's only ever been unit-tested
        // with a directly-constructed `ValidationRequest` before now).
        let (client_cert, client_key) = build_client_cert(&ca, "api-gateway", API_GATEWAY, "api-gateway-secret");

        let response = send_request_over_tls(&addr, server_cert_der, Some((client_cert, client_key)), &token.token).await;
        assert!(response.starts_with("HTTP/1.1 403"), "got: {response}");
        assert!(response.contains("obo_token_subject_mismatch"), "got: {response}");
    }

    // --- Task 8: RFC 8705 certificate-bound tokens (F5), end-to-end over a
    // real mTLS handshake ---

    #[tokio::test]
    async fn f5_cert_bound_token_accepted_when_matching_cert_is_presented() {
        let registry = test_registry();
        let ca = LocalCa::generate(registry.clone(), 3600).unwrap();
        let issuer = LocalIssuer::generate(registry.clone(), 300).unwrap();
        let (upstream_addr, hits) = spawn_test_upstream("hello from upstream").await;

        let (client_cert, client_key) = build_client_cert(&ca, "orders-svc", ORDERS, "orders-secret");
        let cert_thumbprint = compute_cert_thumbprint_x5t_s256(client_cert.as_ref());
        let token = issuer
            .issue_jwt_svid_with_cert_binding("orders-svc", INVENTORY, &cert_thumbprint, "orders-secret")
            .unwrap();

        let (addr, server_cert_der) =
            spawn_mtls_server(registry, issuer, &ca, INVENTORY, ClientAuth::Optional, upstream_addr).await;

        let response =
            send_request_over_tls(&addr, server_cert_der, Some((client_cert, client_key)), &token.token).await;
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
        assert!(response.contains("hello from upstream"), "got: {response}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn f5_cert_bound_token_rejected_when_mismatched_cert_is_presented() {
        let registry = test_registry();
        let ca = LocalCa::generate(registry.clone(), 3600).unwrap();
        let issuer = LocalIssuer::generate(registry.clone(), 300).unwrap();

        // Bind the token to orders-svc's own client cert thumbprint...
        let (orders_cert, _orders_key) = build_client_cert(&ca, "orders-svc", ORDERS, "orders-secret");
        let bound_thumbprint = compute_cert_thumbprint_x5t_s256(orders_cert.as_ref());
        let token = issuer
            .issue_jwt_svid_with_cert_binding("orders-svc", INVENTORY, &bound_thumbprint, "orders-secret")
            .unwrap();

        let (addr, server_cert_der) = spawn_mtls_server(
            registry,
            issuer,
            &ca,
            INVENTORY,
            ClientAuth::Optional,
            "http://unused.invalid".to_string(),
        )
        .await;

        // ...but present a different, legitimately CA-issued client cert
        // (api-gateway's) instead. This is exactly the "stolen token"
        // scenario RFC 8705 defends against: even a validly-signed token
        // is useless off the certificate it was bound to.
        let (api_gateway_cert, api_gateway_key) =
            build_client_cert(&ca, "api-gateway", API_GATEWAY, "api-gateway-secret");

        let response = send_request_over_tls(
            &addr,
            server_cert_der,
            Some((api_gateway_cert, api_gateway_key)),
            &token.token,
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403"), "got: {response}");
        assert!(response.contains("certificate_binding_mismatch"), "got: {response}");
    }

    #[tokio::test]
    async fn f5_cert_bound_token_rejected_when_no_cert_is_presented() {
        let registry = test_registry();
        let ca = LocalCa::generate(registry.clone(), 3600).unwrap();
        let issuer = LocalIssuer::generate(registry.clone(), 300).unwrap();

        let (orders_cert, _orders_key) = build_client_cert(&ca, "orders-svc", ORDERS, "orders-secret");
        let bound_thumbprint = compute_cert_thumbprint_x5t_s256(orders_cert.as_ref());
        let token = issuer
            .issue_jwt_svid_with_cert_binding("orders-svc", INVENTORY, &bound_thumbprint, "orders-secret")
            .unwrap();

        // ClientAuth::Optional -- the handshake itself succeeds with no
        // client cert at all, but the token demands one.
        let (addr, server_cert_der) = spawn_mtls_server(
            registry,
            issuer,
            &ca,
            INVENTORY,
            ClientAuth::Optional,
            "http://unused.invalid".to_string(),
        )
        .await;

        let response = send_request_over_tls(&addr, server_cert_der, None, &token.token).await;
        assert!(response.starts_with("HTTP/1.1 403"), "got: {response}");
        assert!(response.contains("certificate_binding_mismatch"), "got: {response}");
    }

    #[tokio::test]
    async fn mtls_required_rejects_the_handshake_without_a_client_cert() {
        let registry = test_registry();
        let ca = LocalCa::generate(registry.clone(), 3600).unwrap();
        let issuer = LocalIssuer::generate(registry.clone(), 300).unwrap();

        let (addr, server_cert_der) = spawn_mtls_server(
            registry,
            issuer,
            &ca,
            INVENTORY,
            ClientAuth::Required,
            "http://unused.invalid".to_string(),
        )
        .await;

        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_cert_der).unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();

        // Whether the rejection surfaces at `connect()` itself or only once
        // we try to actually use the connection depends on exactly when the
        // client observes the server's fatal alert — both are valid places
        // for a TLS stack to report "the server would not accept this
        // connection," so this test accepts either rather than assuming one.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        match connector.connect(server_name, tcp).await {
            Err(_) => {}
            Ok(mut tls_stream) => {
                let write_result = tls_stream
                    .write_all(b"GET /some/path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .await;
                let mut response = Vec::new();
                let read_result = tls_stream.read_to_end(&mut response).await;

                assert!(
                    write_result.is_err() || read_result.is_err() || response.is_empty(),
                    "expected the connection to be rejected somewhere; got: {}",
                    String::from_utf8_lossy(&response)
                );
            }
        }
    }

    // --- Task 6: admin/proxy listener split, rate limiting, constant-time
    // --- bootstrap token comparison (F7, F10) ---

    /// The core F10 guarantee: `/v1/authorize` (an admin-only route) answers
    /// on the admin listener but is unreachable on the proxy listener — a
    /// request to that path there falls through to `proxy_handler`'s
    /// catch-all instead, which denies it for lacking an OBO token, exactly
    /// like any other unauthenticated proxy request. And the reverse holds
    /// too: the admin listener has no catch-all at all, so a path it
    /// doesn't recognize 404s rather than silently being proxied anywhere.
    #[tokio::test]
    async fn admin_routes_are_unreachable_on_the_proxy_listener() {
        let state = test_state("http://unused.invalid".to_string());
        let admin_router = build_admin_router(state.clone(), 1000, 100, 30, 1000);
        let proxy_router = build_proxy_router(state, 100, 30, 1000);

        let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_addr = admin_listener.local_addr().unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        tokio::spawn(serve(admin_listener, admin_router, None));
        tokio::spawn(serve(proxy_listener, proxy_router, None));

        let client = reqwest::Client::new();
        let authorize_body = serde_json::json!({ "destination": INVENTORY });

        // /v1/authorize answers on the admin listener...
        let admin_resp = client
            .post(format!("http://{admin_addr}/v1/authorize"))
            .json(&authorize_body)
            .send()
            .await
            .unwrap();
        assert_eq!(admin_resp.status(), SC::OK);

        // ...but on the proxy listener the same path is just ordinary
        // (token-less) proxy traffic, and gets denied -- never routed to
        // the authorize handler.
        let proxy_resp = client
            .post(format!("http://{proxy_addr}/v1/authorize"))
            .json(&authorize_body)
            .send()
            .await
            .unwrap();
        assert_eq!(proxy_resp.status(), SC::FORBIDDEN);

        // The admin listener, in turn, never serves proxied traffic -- a
        // path with no matching admin route 404s instead of being
        // forwarded.
        let admin_proxy_attempt = client
            .get(format!("http://{admin_addr}/some/protected/path"))
            .send()
            .await
            .unwrap();
        assert_eq!(admin_proxy_attempt.status(), SC::NOT_FOUND);
    }

    /// Exercises the real production wiring (`ListenerConfig` +
    /// `setup_listeners`, the pair `main` itself calls) end to end, rather
    /// than hand-assembling routers/listeners the way the test above does.
    /// Binds to port `0` on both listeners and reads back the OS-assigned
    /// ports from `ListenerHandles` to stay collision-free under parallel
    /// test execution.
    #[tokio::test]
    async fn setup_listeners_wires_the_admin_and_proxy_routers_onto_separate_sockets() {
        let gateway_config =
            GatewayConfig::test_with_listeners("127.0.0.1:0".parse().unwrap(), "127.0.0.1:0".parse().unwrap());
        let listener_config = ListenerConfig {
            proxy_addr: gateway_config.proxy_addr,
            admin_addr: gateway_config.admin_addr,
            admin_rate_limit_rps: gateway_config.admin_rate_limit,
            max_body_mb: gateway_config.max_body_mb,
            request_timeout_secs: gateway_config.request_timeout_secs,
            max_concurrent_connections: gateway_config.max_concurrent_connections,
        };
        let state = test_state("http://unused.invalid".to_string());

        let handles = setup_listeners(&listener_config, state, None).await.unwrap();

        let client = reqwest::Client::new();

        let admin_resp = client
            .post(format!("http://{}/v1/authorize", handles.admin_addr))
            .json(&serde_json::json!({ "destination": INVENTORY }))
            .send()
            .await
            .unwrap();
        assert_eq!(admin_resp.status(), SC::OK);

        let proxy_resp = client
            .post(format!("http://{}/v1/authorize", handles.proxy_addr))
            .json(&serde_json::json!({ "destination": INVENTORY }))
            .send()
            .await
            .unwrap();
        assert_eq!(proxy_resp.status(), SC::FORBIDDEN);

        handles.admin.abort();
        handles.proxy.abort();
    }

    /// Qualitative rate-limit test (F7): with a deliberately tiny budget
    /// (2 req/s), sending a 2x-budget burst of requests through the admin
    /// router must take meaningfully longer than an unthrottled burst would
    /// (which completes in low single-digit milliseconds in-process) --
    /// proving requests beyond the budget are queued/delayed rather than
    /// all let through immediately. Every clone of `router` below shares
    /// one `tower::buffer::Buffer` worker (see `build_admin_router`'s doc
    /// comment), which is what makes the limit hold across the whole
    /// burst instead of resetting per clone.
    #[tokio::test]
    async fn admin_router_rate_limits_a_burst_of_requests() {
        let state = test_state("http://unused.invalid".to_string());
        let rate_limit_rps: u32 = 2;
        let router = build_admin_router(state, rate_limit_rps, 100, 30, 1000);

        let make_request = || {
            Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"destination":"{INVENTORY}"}}"#)))
                .unwrap()
        };

        let start = std::time::Instant::now();
        for _ in 0..(rate_limit_rps as usize * 2) {
            let response = router.clone().oneshot(make_request()).await.unwrap();
            assert_eq!(response.status(), SC::OK);
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed >= std::time::Duration::from_millis(800),
            "expected a 2x-budget burst to be throttled to more than ~800ms, took {elapsed:?}"
        );
    }

    /// Below the configured rate, requests should sail through without any
    /// imposed delay — the limiter should never slow down traffic that's
    /// already within budget.
    #[tokio::test]
    async fn admin_router_does_not_throttle_requests_within_budget() {
        let state = test_state("http://unused.invalid".to_string());
        let router = build_admin_router(state, 1000, 100, 30, 1000);

        let request = Request::builder()
            .method("POST")
            .uri("/v1/authorize")
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"destination":"{INVENTORY}"}}"#)))
            .unwrap();

        let start = std::time::Instant::now();
        let response = router.oneshot(request).await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(response.status(), SC::OK);
        assert!(elapsed < std::time::Duration::from_millis(500), "got: {elapsed:?}");
    }

    // --- Task 7: body limits and timeouts (F6) ---

    /// Oversized request body is rejected with 413 Payload Too Large.
    #[tokio::test]
    async fn proxy_rejects_oversized_body_with_413() {
        let mut state = test_state("http://unused.invalid".to_string());
        state.max_body_bytes = 100 * 1024 * 1024; // Allow token issuance
        let router_for_token = build_router_with_limits(state.clone(), 100, 30, 1000);

        // First, issue a valid token for the oversized body test
        let issued = router_for_token
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/svid/jwt")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"workload_name":"orders-svc","audience":"{}","bootstrap_token":"orders-secret"}}"#,
                        INVENTORY
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(issued.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let token = parsed["token"].as_str().unwrap().to_string();

        // Now update state with 1 MB limit and try large body
        state.max_body_bytes = 1 * 1024 * 1024;
        let router = build_router_with_limits(state, 1, 30, 1000);

        // 5 MB body (exceeds 1 MB limit)
        let large_body = vec![0u8; 5 * 1024 * 1024];

        let request = Request::builder()
            .method("POST")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, token)
            .body(Body::from(large_body))
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::PAYLOAD_TOO_LARGE);
    }

    /// Slow upstream request times out and returns 504 Gateway Timeout.
    #[tokio::test]
    async fn proxy_returns_504_on_upstream_timeout() {
        // Spawn a fake upstream that accepts connections but never responds
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_upstream_addr = format!("http://{}", listener.local_addr().unwrap());

        // Spawn background task that accepts connections but hangs
        tokio::spawn(async move {
            loop {
                if let Ok((mut _socket, _)) = listener.accept().await {
                    // Accept the connection but never send a response
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            }
        });

        let state = test_state(slow_upstream_addr);
        // Use the client's 1-second timeout (not the TimeoutLayer timeout which applies to the whole request)
        // The reqwest client has a timeout set in main, but in tests we need to handle it
        // First use normal timeout for token issuance, then create a client with short timeout for proxy test
        let router_for_token = build_router_with_limits(state.clone(), 100, 5, 1000);

        let issued = router_for_token
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/svid/jwt")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"workload_name":"orders-svc","audience":"{}","bootstrap_token":"orders-secret"}}"#,
                        INVENTORY
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(issued.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let token = parsed["token"].as_str().unwrap().to_string();

        // Now we need to update the state to have a shorter timeout on the http client
        // Create a new client with 1 second timeout
        let http_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();

        let mut state_with_timeout = state;
        state_with_timeout.http_client = http_client;

        // Use a longer TimeoutLayer timeout so the layer doesn't fire
        let router = build_router_with_limits(state_with_timeout, 100, 10, 1000);

        // Make a proxied request that will timeout on the upstream client
        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, token)
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::GATEWAY_TIMEOUT);
    }

    /// Helper to build a router with custom timeout/limit settings for testing.
    fn build_router_with_limits(state: AppState, max_body_mb: u32, request_timeout_secs: u64, max_concurrent_connections: u32) -> Router {
        let body_limit_bytes = (max_body_mb as usize) * 1024 * 1024;

        Router::new()
            .route("/v1/svid/jwt", post(issue_svid))
            .route("/v1/svid/jwt-with-user", post(issue_svid_with_user))
            .route("/v1/svid/x509", post(issue_x509_svid))
            .route("/v1/authorize", post(authorize))
            .route("/v1/token-exchange", post(handle_token_exchange))
            .fallback(proxy_handler)
            .layer(DefaultBodyLimit::max(body_limit_bytes))
            .layer(TimeoutLayer::new(Duration::from_secs(request_timeout_secs)))
            .layer(ConcurrencyLimitLayer::new(max_concurrent_connections as usize))
            .layer(TraceLayer::new_for_http())
            .with_state(state)
    }

    // --- Task 9: W3C TraceContext propagation (F12) ---

    use opentelemetry_sdk::testing::trace::{InMemorySpanExporter, InMemorySpanExporterBuilder};
    use opentelemetry_sdk::trace::TracerProvider as SdkTracerProvider;
    use std::sync::OnceLock;

    static TEST_SPAN_EXPORTER: OnceLock<InMemorySpanExporter> = OnceLock::new();

    /// Installs one process-wide OTel `TracerProvider` (backed by an
    /// in-memory exporter) and the W3C TraceContext propagator, the first
    /// time any F12 test calls it -- `init_tracing()` itself is never
    /// exercised by this test module (it also installs a global
    /// `tracing_subscriber` default, which can only ever be set once per
    /// process, and none of these tests need it).
    ///
    /// Because this is `cargo test`'s one shared process and tests run in
    /// parallel, the returned exporter accumulates spans from *every* test
    /// that touches `proxy_handler` for the rest of the run, not just the
    /// caller's own request. Every test below copes with that by filtering
    /// spans down to its own, randomly-chosen `traceparent` trace ID rather
    /// than assuming the exporter is empty or reading it positionally.
    fn test_span_exporter() -> InMemorySpanExporter {
        TEST_SPAN_EXPORTER
            .get_or_init(|| {
                let exporter = InMemorySpanExporterBuilder::new().build();
                let provider = SdkTracerProvider::builder()
                    .with_simple_exporter(exporter.clone())
                    .build();
                global::set_tracer_provider(provider);
                global::set_text_map_propagator(TraceContextPropagator::new());
                exporter
            })
            .clone()
    }

    fn traceparent_header(trace_id: &str, span_id: &str) -> String {
        format!("00-{trace_id}-{span_id}-01")
    }

    // Note: `spawn_header_capturing_upstream` is defined once, above, near
    // the N10 header-stripping tests -- this duplicate definition (an
    // artifact of two concurrent edits to this file both adding the same
    // helper) was removed so the module compiles; both the N10 tests and
    // the trace-propagation tests below share that single definition.

    #[tokio::test]
    async fn trace_context_is_propagated_onto_the_response_even_when_denied() {
        let _exporter = test_span_exporter(); // ensures the propagator is installed
        let state = test_state("http://unused.invalid".to_string());
        let router = build_router(state);

        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header("traceparent", traceparent_header(trace_id, "00f067aa0ba902b7"))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        // No OBO token at all -> denied, but the trace ID must still come
        // back: a 403 is exactly as interesting to a trace as a 200.
        assert_eq!(response.status(), SC::FORBIDDEN);
        let traceparent = response
            .headers()
            .get("traceparent")
            .expect("response should carry a traceparent header")
            .to_str()
            .unwrap();
        assert!(traceparent.contains(trace_id), "got: {traceparent}");
    }

    #[tokio::test]
    async fn trace_context_is_injected_into_the_forwarded_upstream_request() {
        let _exporter = test_span_exporter();
        let (upstream_addr, captured_headers) = spawn_header_capturing_upstream().await;
        let state = test_state(upstream_addr);
        let issued = state
            .identity
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();
        let router = build_router(state);

        let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, issued.token)
            .header("traceparent", traceparent_header(trace_id, "00f067aa0ba902b7"))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);

        let headers = captured_headers
            .lock()
            .unwrap()
            .take()
            .expect("upstream should have been hit");
        let forwarded_traceparent = headers
            .get("traceparent")
            .expect("forwarded request should carry a traceparent header")
            .to_str()
            .unwrap();
        assert!(forwarded_traceparent.contains(trace_id), "got: {forwarded_traceparent}");
    }

    #[tokio::test]
    async fn obo_attributes_are_recorded_on_the_span_when_allowed() {
        let exporter = test_span_exporter();
        let (upstream_addr, _hits) = spawn_test_upstream("hello from upstream").await;
        let state = test_state(upstream_addr);
        let issued = state
            .identity
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();
        let router = build_router(state);

        let trace_id = "a1a12f3577b34da6a3ce929d0e0e4736";
        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, issued.token)
            .header("traceparent", traceparent_header(trace_id, "00f067aa0ba902b7"))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|s| s.name == "gateway_request" && s.span_context.trace_id().to_string() == trace_id)
            .expect("expected a gateway_request span recorded for this trace id");

        let attr = |key: &str| -> Option<String> {
            span.attributes
                .iter()
                .find(|kv| kv.key.as_str() == key)
                .map(|kv| kv.value.to_string())
        };

        assert_eq!(attr("obo.immediate_caller").as_deref(), Some(ORDERS));
        assert_eq!(attr("obo.delegation_depth").as_deref(), Some("1"));
        assert_eq!(attr("obo.delegation_chain").as_deref(), Some(ORDERS));
        // No `user` claim on this token -> no obo.user_principal attribute,
        // never falling back to any unverified header.
        assert_eq!(attr("obo.user_principal"), None);
    }

    #[tokio::test]
    async fn obo_user_principal_is_recorded_from_the_signed_claim_not_a_header() {
        let exporter = test_span_exporter();
        let (upstream_addr, _hits) = spawn_test_upstream("hello").await;
        let mut state = test_state(upstream_addr);

        // Mint a token with a signed `user` claim directly (issue_jwt_svid
        // doesn't take one), the same way obo.rs's own tests do.
        let registry = test_registry();
        let (signer, verifier) = {
            use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
            use rsa::{RsaPrivateKey, RsaPublicKey};
            let mut rng = rand::rngs::OsRng;
            let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
            let public_key = RsaPublicKey::from(&private_key);
            let private_pem = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();
            let public_pem = public_key.to_pkcs1_pem(LineEnding::LF).unwrap();
            (
                zero_trust::JwtSigner::from_rsa_pem(private_pem.as_bytes()).unwrap(),
                zero_trust::JwtVerifier::from_rsa_pem(public_pem.as_bytes()).unwrap(),
            )
        };
        const ALICE: &str = "spiffe://chakra.internal/ns/users/sa/alice";
        let claims = zero_trust::OboClaims {
            sub: ORDERS.to_string(),
            aud: vec![INVENTORY.to_string()],
            user: Some(ALICE.to_string()),
            act: None,
            iat: 0,
            exp: now_unix_secs() + 300,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let token = signer.sign(&claims).unwrap();
        state.identity = Arc::new(LocalIssuer::new(registry, signer, verifier, 300));
        let router = build_router(state);

        let trace_id = "b2b22f3577b34da6a3ce929d0e0e4736";
        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, token)
            // Attacker-controlled header claims a different user entirely --
            // must never override the signed claim above (F2).
            .header(HEADER_USER_PRINCIPAL, "spiffe://chakra.internal/ns/users/sa/mallory")
            .header("traceparent", traceparent_header(trace_id, "00f067aa0ba902b7"))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|s| s.name == "gateway_request" && s.span_context.trace_id().to_string() == trace_id)
            .expect("expected a gateway_request span recorded for this trace id");
        let attr = |key: &str| -> Option<String> {
            span.attributes
                .iter()
                .find(|kv| kv.key.as_str() == key)
                .map(|kv| kv.value.to_string())
        };
        assert_eq!(attr("obo.user_principal").as_deref(), Some(ALICE));
    }

    #[tokio::test]
    async fn deny_reason_is_recorded_on_the_span() {
        let exporter = test_span_exporter();
        let state = test_state("http://unused.invalid".to_string());
        let router = build_router(state);

        let trace_id = "c3c32f3577b34da6a3ce929d0e0e4736";
        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header("traceparent", traceparent_header(trace_id, "00f067aa0ba902b7"))
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::FORBIDDEN);

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|s| s.name == "gateway_request" && s.span_context.trace_id().to_string() == trace_id)
            .expect("expected a gateway_request span recorded for this trace id");
        let deny_reason = span
            .attributes
            .iter()
            .find(|kv| kv.key.as_str() == "deny_reason")
            .map(|kv| kv.value.to_string());
        assert_eq!(deny_reason.as_deref(), Some("caller_not_in_allow_list"));
    }

    /// The core F12 acceptance criterion, in miniature: a delegation chain
    /// that crosses multiple independent gateway instances (simulated here
    /// as two separate `AppState`s/routers, the same way the rest of this
    /// suite stands in for separate processes) must still appear as a
    /// single trace -- every hop's `gateway_request` span sharing one trace
    /// ID -- rather than several disconnected ones.
    #[tokio::test]
    async fn delegation_across_two_gateway_hops_shares_one_trace_id() {
        let exporter = test_span_exporter();
        let (upstream_addr, _hits) = spawn_test_upstream("ok").await;

        let trace_id = "d4d42f3577b34da6a3ce929d0e0e4736";
        let traceparent = traceparent_header(trace_id, "00f067aa0ba902b7");

        let state1 = test_state(upstream_addr.clone());
        let token1 = state1
            .identity
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();
        let router1 = build_router(state1);
        let resp1 = router1
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/some/path")
                    .header(HEADER_OBO_TOKEN, token1.token)
                    .header("traceparent", traceparent.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp1.status(), SC::OK);

        let state2 = test_state(upstream_addr);
        let token2 = state2
            .identity
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();
        let router2 = build_router(state2);
        let resp2 = router2
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/some/path")
                    .header(HEADER_OBO_TOKEN, token2.token)
                    .header("traceparent", traceparent)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), SC::OK);

        let spans = exporter.get_finished_spans().unwrap();
        let matching: Vec<_> = spans
            .iter()
            .filter(|s| s.name == "gateway_request" && s.span_context.trace_id().to_string() == trace_id)
            .collect();
        assert_eq!(
            matching.len(),
            2,
            "expected both hops to share one trace id, got {matching:?}"
        );
    }

    // --- Task 12: `obo.chain` in spans comes from the verified token, not
    // the unsigned `X-SPIFFE-Caller-Chain` header (N11, review 0002) ---
    //
    // These exercise the `#[tracing::instrument]`-declared fields on
    // `proxy_handler`'s own span (named "proxy_handler", default from the
    // function name) -- a different span from the hand-rolled OTel
    // "gateway_request" span the F12 tests above assert on via
    // `test_span_exporter`/`record_obo_span_attributes`. Rather than bridge
    // through `tracing-opentelemetry` (which would need its own
    // `TracerProvider` wired as a `tracing_subscriber` layer), a minimal
    // `Layer` captures whatever gets `Span::record`-ed onto the named span
    // directly, keyed by field name.

    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use tracing::field::{Field, Visit};
    use tracing::span::{Id as SpanId, Record as SpanRecord};
    use tracing_subscriber::layer::Context as LayerContext;
    use tracing_subscriber::registry::LookupSpan;

    #[derive(Clone, Default)]
    struct CapturedFields(Arc<StdMutex<HashMap<String, String>>>);

    impl CapturedFields {
        fn get(&self, key: &str) -> Option<String> {
            self.0.lock().unwrap().get(key).cloned()
        }
    }

    struct FieldVisitor<'a>(&'a CapturedFields);

    impl<'a> Visit for FieldVisitor<'a> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0 .0.lock().unwrap().insert(field.name().to_string(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.0 .0.lock().unwrap().insert(field.name().to_string(), value.to_string());
        }
    }

    /// A minimal `tracing_subscriber::Layer` that captures every field
    /// `Span::record`-ed onto the span named `span_name`, keyed by field
    /// name -- just enough to assert on `proxy_handler`'s `obo.chain`/
    /// `obo.chain_unverified` attributes without a real OTEL collector.
    struct FieldCaptureLayer {
        span_name: &'static str,
        captured: CapturedFields,
    }

    impl<S> tracing_subscriber::Layer<S> for FieldCaptureLayer
    where
        S: tracing::Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        fn on_record(&self, id: &SpanId, values: &SpanRecord<'_>, ctx: LayerContext<'_, S>) {
            if let Some(span_ref) = ctx.span(id) {
                if span_ref.name() == self.span_name {
                    values.record(&mut FieldVisitor(&self.captured));
                }
            }
        }
    }

    /// Installs a `FieldCaptureLayer` as *this thread's* tracing
    /// subscriber (via `tracing::subscriber::set_default`, not a process-
    /// wide global) for the lifetime of the returned guard -- scoped per
    /// test, so parallel `cargo test` runs (each on its own OS thread,
    /// same as the rest of this suite) never interfere with each other.
    fn capture_span_fields(span_name: &'static str) -> (CapturedFields, tracing::subscriber::DefaultGuard) {
        let captured = CapturedFields::default();
        let layer = FieldCaptureLayer {
            span_name,
            captured: captured.clone(),
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        let guard = tracing::subscriber::set_default(subscriber);
        (captured, guard)
    }

    #[tokio::test]
    async fn span_records_verified_chain() {
        let (captured, _guard) = capture_span_fields("proxy_handler");
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
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // No `act` claim on a freshly-issued token -> delegation_chain() is
        // just [sub] -- the single verified hop.
        assert_eq!(captured.get("obo.chain").as_deref(), Some(ORDERS));
        // No unsigned X-SPIFFE-Caller-Chain header was sent at all.
        assert_eq!(captured.get("obo.chain_unverified"), None);
    }

    #[tokio::test]
    async fn span_records_unverified_header_separately() {
        let (captured, _guard) = capture_span_fields("proxy_handler");
        let (upstream_addr, hits) = spawn_test_upstream("hello from upstream").await;
        let state = test_state(upstream_addr);
        let issued = state
            .identity
            .issue_jwt_svid("orders-svc", INVENTORY, "orders-secret")
            .unwrap();
        let router = build_router(state);

        // A backend between the caller and this gateway could set this
        // unsigned header to anything -- here, a completely different
        // (spoofed) chain from what the verified token actually says.
        let spoofed_chain = "spiffe://chakra.internal/ns/evil/sa/evil-svc";
        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, issued.token)
            .header(HEADER_CALLER_CHAIN, spoofed_chain)
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // The verified chain (from the signed token) and the unverified
        // header are recorded under distinct attributes, and the spoofed
        // header never overwrites the verified value.
        assert_eq!(captured.get("obo.chain").as_deref(), Some(ORDERS));
        assert_eq!(captured.get("obo.chain_unverified").as_deref(), Some(spoofed_chain));
        assert_ne!(captured.get("obo.chain"), captured.get("obo.chain_unverified"));
    }

    #[tokio::test]
    async fn span_rejects_header_without_token() {
        let (captured, _guard) = capture_span_fields("proxy_handler");
        let (upstream_addr, hits) = spawn_test_upstream("should never be seen").await;
        let state = test_state(upstream_addr);
        let router = build_router(state);

        // Only the unsigned header, no OBO token at all -> denied, and
        // nothing verified for obo.chain to come from.
        let spoofed_chain = "spiffe://chakra.internal/ns/evil/sa/evil-svc";
        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header(HEADER_CALLER_CHAIN, spoofed_chain)
            .body(Body::empty())
            .unwrap();

        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::FORBIDDEN);
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        // The unsigned header is still visible under its own clearly-
        // unverified attribute (for troubleshooting)...
        assert_eq!(captured.get("obo.chain_unverified").as_deref(), Some(spoofed_chain));
        // ...but obo.chain itself was never recorded: the header alone,
        // with no verified token behind it, is never trusted.
        assert_eq!(captured.get("obo.chain"), None);
    }
}
