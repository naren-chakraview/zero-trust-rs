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

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use opentelemetry::trace::TracerProvider as _;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_http::trace::TraceLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use zero_trust::{
    build_client_cert_verifier, build_server_config, load_certs, now_unix_secs, validate, CaError,
    CertificateAuthority, ClientAuth, Decision, GatewayConfig, IdentityError, IdentityProvider,
    LocalCa, LocalIssuer, Registry, ServerCertificate, SpiffeId, ValidationRequest,
    HEADER_CALLER_CHAIN, HEADER_OBO_TOKEN, HEADER_USER_PRINCIPAL,
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
}

/// Sets up structured stdout logs (always) plus, when
/// `OTEL_EXPORTER_OTLP_ENDPOINT` is set, real OTLP trace export (an
/// `opentelemetry_sdk` `TracerProvider` bridged into `tracing` spans via
/// `tracing-opentelemetry`). Returns the provider so `main` can keep it
/// alive for the process lifetime — dropping it would tear down the batch
/// exporter's background flush task.
///
/// Local `cargo run` with no OTLP endpoint configured behaves exactly as
/// before: `Option<Layer>` is itself a no-op `Layer` when `None`, so the
/// OTEL half of the pipeline simply isn't there.
fn init_tracing() -> Option<opentelemetry_sdk::trace::TracerProvider> {
    let otel_provider = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok().map(|_| {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()
            .expect("failed to build OTLP span exporter");

        let resource = opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new(
            "service.name",
            "zt-gateway",
        )]);

        let provider = opentelemetry_sdk::trace::TracerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(resource)
            .build();

        opentelemetry::global::set_tracer_provider(provider.clone());
        provider
    });

    let otel_layer = otel_provider
        .as_ref()
        .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("zt-gateway")));

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .init();

    otel_provider
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

    let state = AppState {
        identity: Arc::new(issuer),
        ca,
        registry: Arc::new(registry),
        http_client: reqwest::Client::new(),
        upstream_addr: config.upstream_addr.clone(),
        protected_workload: Arc::new(protected_workload),
    };

    let router = build_router(state);
    let listener = TcpListener::bind(&config.listen_addr).await?;
    tracing::info!(
        addr = %config.listen_addr,
        upstream = %config.upstream_addr,
        tls = tls_acceptor.is_some(),
        "zt-gateway listening"
    );
    serve(listener, router, tls_acceptor).await;

    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/svid/jwt", post(issue_svid))
        .route("/v1/svid/x509", post(issue_x509_svid))
        .route("/v1/authorize", post(authorize))
        .fallback(proxy_handler)
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

/// A connection's verified client-certificate identity, if any. Always
/// present as a request extension (see `serve()`) regardless of whether
/// TLS or client auth is in use at all — `None` in every case where there
/// isn't a verified identity, so handlers never need to distinguish
/// "no TLS," "TLS but no client cert," and "client cert with no SPIFFE
/// SAN" — they all just mean "no source_principal."
#[derive(Clone)]
struct PeerIdentity(Option<SpiffeId>);

/// Pulls the verified peer certificate's SPIFFE ID (a URI SAN entry) out of
/// a just-completed TLS handshake, if the caller presented one.
fn extract_peer_identity(tls_stream: &tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> PeerIdentity {
    let (_io, connection) = tls_stream.get_ref();
    let spiffe_id = connection
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| extract_spiffe_id_from_der(cert));
    PeerIdentity(spiffe_id)
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
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let peer_identity = extract_peer_identity(&tls_stream);
                        let hyper_service = TowerToHyperService::new(router.layer(Extension(peer_identity)));
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(tls_stream), hyper_service)
                            .await
                    }
                    Err(error) => {
                        tracing::debug!(%error, %remote_addr, "TLS handshake failed");
                        return;
                    }
                },
                None => {
                    let hyper_service = TowerToHyperService::new(router.layer(Extension(PeerIdentity(None))));
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
    let source_principal = peer_identity.and_then(|Extension(PeerIdentity(id))| id);

    let request = ValidationRequest {
        destination: &destination,
        source_principal: source_principal.as_ref(),
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

// Field names deliberately match the blueprint's ADR-0008 OTEL span
// attributes (`obo.caller_principal`, `obo.chain`, `obo.user_principal`,
// `obo.token_ttl_seconds`) so traces from this project line up with what
// the original blueprint's OTEL Collector pipeline expects. Declared as
// `Empty` here (rather than just passed at the `tracing::info!` call site
// below) because a `tracing` span's field set is fixed at creation time —
// `Span::record` can only fill in a value for a field that was already
// declared, never add a new one.
#[tracing::instrument(
    skip_all,
    fields(
        obo.caller_principal = tracing::field::Empty,
        obo.chain = tracing::field::Empty,
        obo.user_principal = tracing::field::Empty,
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
    let source_principal = peer_identity.and_then(|Extension(PeerIdentity(id))| id);
    let obo_token = header_str(req.headers(), HEADER_OBO_TOKEN);
    let caller_chain = header_str(req.headers(), HEADER_CALLER_CHAIN);
    let user_principal = header_str(req.headers(), HEADER_USER_PRINCIPAL);

    let request = ValidationRequest {
        destination: &state.protected_workload,
        source_principal: source_principal.as_ref(),
        obo_token: obo_token.as_deref(),
        caller_chain: caller_chain.as_deref(),
    };
    let decision = validate(&state.registry, state.identity.verifier(), &request, now_unix_secs());

    let span = tracing::Span::current();
    span.record("allow", decision.is_allow());
    span.record("deny_reason", decision.deny_reason_str());
    span.record("obo.chain", caller_chain.as_deref().unwrap_or(""));
    if let Some(up) = &user_principal {
        span.record("obo.user_principal", up.as_str());
    }
    // Only meaningful once the decision is Allow -- re-verifying the token
    // here is purely to read its claims for tracing (obo::validate doesn't
    // expose them), not a second authorization decision.
    if decision.is_allow() {
        if let Some(token) = obo_token.as_deref() {
            if let Ok(claims) = state.identity.verifier().verify_signature(token) {
                span.record("obo.caller_principal", claims.sub.as_str());
                span.record("obo.token_ttl_seconds", claims.exp - now_unix_secs());
            }
        } else if let Some(sp) = &source_principal {
            span.record("obo.caller_principal", sp.to_string().as_str());
        }
    }

    // Structured fields deliberately mirror the blueprint Rego policies'
    // decision_log shape (allow, destination, obo_present, obo_chain,
    // deny_reason) -- kept as a plain log line alongside the span
    // attributes above, since stdout logs and OTEL traces serve different
    // consumers (grep/kubectl logs vs. a tracing UI).
    tracing::info!(
        allow = decision.is_allow(),
        destination = %state.protected_workload,
        source_principal = source_principal.as_ref().map(|id| id.to_string()),
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
}
