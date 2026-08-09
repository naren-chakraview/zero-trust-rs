//! Core SPIFFE identity and On-Behalf-Of (OBO) delegation logic backing the
//! `zt-gateway` binary. Ported from the validation semantics of the
//! chakraview-zero-trust-blueprint's Rego policies, minus the OPA/Envoy/K8s
//! infrastructure they normally run inside.

mod config;
mod error;
mod headers;
mod identity;
mod jwt;
mod obo;
mod registry;
mod spiffe_id;

pub use config::GatewayConfig;
pub use error::{ConfigError, IdentityError, JwtError, RegistryError, SpiffeIdError};
pub use headers::{
    build_outbound_headers, CallerChain, OutboundHeaders, HEADER_CALLER_CHAIN, HEADER_OBO_TOKEN,
    HEADER_USER_PRINCIPAL,
};
pub use identity::{IdentityProvider, IssuedToken, LocalIssuer};
pub use jwt::{JwtSigner, JwtVerifier, OboClaims};
pub use obo::{validate, Decision, DenyReason, ValidationRequest, Validator};
pub use registry::{Registry, WorkloadEntry, DEFAULT_MAX_OBO_CHAIN_DEPTH};
pub use spiffe_id::SpiffeId;

/// Current time as Unix seconds. A thin wrapper so call sites don't reach
/// for a date/time crate just to compare against a JWT `exp`/`iat`.
pub fn now_unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs() as i64
}
