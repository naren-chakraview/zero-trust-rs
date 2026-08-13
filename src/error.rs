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
    #[error("failed to sign certificate: {0}")]
    Signing(String),
}
