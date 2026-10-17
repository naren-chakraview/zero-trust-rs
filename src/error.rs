//! Error types for every fallible operation in the crate.

/// Errors from parsing or constructing a [`crate::SpiffeId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpiffeIdError {
    #[error("missing or invalid spiffe:// scheme")]
    InvalidScheme,
    #[error("trust domain component is empty")]
    EmptyTrustDomain,
    #[error("path does not match /ns/<namespace>/sa/<service_account>")]
    InvalidPathShape,
    #[error("namespace component is empty")]
    EmptyNamespace,
    #[error("service account component is empty")]
    EmptyServiceAccount,
}

/// Errors from loading a [`crate::Registry`] from YAML.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("failed to parse registry YAML: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("failed to read registry: {0}")]
    Io(#[from] std::io::Error),
    #[error("workload '{name}' has invalid spiffe_id: {source}")]
    InvalidSpiffeId {
        name: String,
        #[source]
        source: SpiffeIdError,
    },
    #[error("workload '{name}' has invalid allowed_caller entry '{caller}': {source}")]
    InvalidAllowedCaller {
        name: String,
        caller: String,
        #[source]
        source: SpiffeIdError,
    },
    #[error("duplicate spiffe_id in registry: {0}")]
    DuplicateSpiffeId(String),
}

/// Errors from JWT SVID signing or signature verification.
#[derive(Debug, thiserror::Error)]
pub enum JwtError {
    #[error("invalid RSA key material: {0}")]
    InvalidKey(String),
    #[error("token decode/signature error: {0}")]
    Decode(#[from] jsonwebtoken::errors::Error),
    /// The token has no `kid` header, but the verifier holds more than one
    /// registered key — there's no safe way to guess which one applies.
    #[error("token header is missing 'kid', and multiple keys are registered")]
    MissingKeyId,
    /// The token's `kid` header doesn't match any key the verifier trusts.
    #[error("no registered key matches kid '{0}'")]
    UnknownKeyId(String),
}

/// Errors from JWT SVID issuance.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("unknown workload: {0}")]
    UnknownWorkload(String),
    #[error("bootstrap token does not match the requesting workload")]
    InvalidBootstrapToken,
    #[error("audience is not a valid SPIFFE ID: {0}")]
    InvalidAudience(#[from] SpiffeIdError),
    #[error(transparent)]
    Jwt(#[from] JwtError),
    /// [`crate::LocalIssuer::with_jwks`]'s `active_kid` doesn't match any
    /// `kid` present in the supplied JWKS document.
    #[error("active_kid '{0}' is not present in the supplied JWKS")]
    InvalidKeyId(String),
    /// The JWKS document passed to [`crate::LocalIssuer::with_jwks`] isn't
    /// valid JSON, or doesn't match the expected `{"keys": [...]}` shape.
    #[error("failed to parse JWKS document: {0}")]
    InvalidJwks(String),

    /// An error from [`crate::SpireProvider`] talking to a SPIRE agent's
    /// Workload API (Task 5 / F13) -- connection failures, malformed
    /// responses, or an operation the Workload API has no RPC for at all
    /// (arbitrary claim signing, or bootstrap-token-authenticated issuance
    /// for a third-party workload). See `src/spire_provider.rs`'s module
    /// doc comment for which of `IdentityProvider`'s methods this can show
    /// up from and why.
    #[error("SPIRE workload API error: {0}")]
    Spire(String),

    /// N5 fix (review 0002): [`crate::LocalIssuer::issue_jwt_svid_with_user`]
    /// refuses to mint a token vouching for a human principal from an IdP
    /// that isn't named in the deployment's configured
    /// `GatewayConfig::user_issuers` -- this gateway never signs a `user`
    /// claim on behalf of an issuer it hasn't been told to trust.
    #[error("untrusted user issuer: {0}")]
    UntrustedUserIssuer(String),
}

/// Errors from loading a [`crate::config::GatewayConfig`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to parse gateway config YAML: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("failed to read gateway config: {0}")]
    Io(#[from] std::io::Error),
    #[error("protected_workload is not a valid SPIFFE ID: {0}")]
    InvalidProtectedWorkload(#[from] SpiffeIdError),
    /// [`crate::GatewayConfig::gateway_id`]'s value doesn't parse as a
    /// SPIFFE ID. Kept distinct from `InvalidProtectedWorkload` (rather
    /// than sharing a `#[from]`) since both wrap the same underlying
    /// [`SpiffeIdError`] type and a derive can't disambiguate which field
    /// failed from the source type alone.
    #[error("gateway_id '{value}' is not a valid SPIFFE ID: {source}")]
    InvalidGatewayId {
        value: String,
        #[source]
        source: SpiffeIdError,
    },
}

/// Errors from loading/generating TLS server certificate material or
/// building a `rustls::ServerConfig`.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("failed to read TLS certificate/key file: {0}")]
    Io(#[from] std::io::Error),
    #[error("no certificates found in {0}")]
    NoCertsFound(String),
    #[error("no private key found in {0}")]
    NoKeyFound(String),
    #[error("failed to generate an ephemeral certificate: {0}")]
    Generation(String),
    #[error("failed to build rustls server config: {0}")]
    RustlsConfig(#[from] rustls::Error),
}

/// Errors from X.509 SVID issuance ([`crate::CertificateAuthority::sign_csr`]).
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("unknown workload: {0}")]
    UnknownWorkload(String),
    #[error("bootstrap token does not match the requesting workload")]
    InvalidBootstrapToken,
    #[error("malformed certificate signing request: {0}")]
    MalformedCsr(String),
    #[error("CSR requests identity '{requested}' but the authenticated workload is '{expected}'")]
    SanMismatch { requested: String, expected: String },
    /// Per the X.509-SVID spec, a CSR may only carry URI SANs — the CA
    /// builds the leaf's identity from the registry, not from DNS/IP/email
    /// SANs a workload might try to smuggle in.
    #[error("CSR contains a non-URI SAN; only a single URI SAN is permitted")]
    NonUriSanInCsr,
    /// Per the X.509-SVID spec, a leaf must carry exactly one URI SAN.
    #[error("CSR requests more than one URI SAN; exactly one is required")]
    MultipleUriSans,
    #[error("failed to sign certificate: {0}")]
    Signing(String),
}
