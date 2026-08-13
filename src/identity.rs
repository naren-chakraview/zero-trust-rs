//! Workload identity issuance — the seam where "how do we get a JWT SVID"
//! is decided, kept separate from `obo.rs` (which only ever consumes
//! already-issued tokens) and from the HTTP layer.

use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};

use crate::error::{IdentityError, JwtError};
use crate::jwt::{JwtSigner, JwtVerifier, OboClaims};
use crate::registry::{CredentialCheck, Registry};
use crate::spiffe_id::SpiffeId;

/// A freshly minted JWT SVID and when it expires (Unix seconds).
#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub token: String,
    pub expires_at: i64,
}

/// How the gateway obtains workload identity. `obo.rs` and the HTTP layer
/// depend only on this trait, never on [`LocalIssuer`] directly — a future
/// provider backed by a real SPIRE server's Workload API can be dropped in
/// by writing a new impl of this trait, with no change anywhere else.
pub trait IdentityProvider {
    /// Issues a JWT SVID to `requester_workload_name`, scoped to `audience`,
    /// after checking `credential` against that workload's configured
    /// bootstrap token.
    fn issue_jwt_svid(
        &self,
        requester_workload_name: &str,
        audience: &str,
        credential: &str,
    ) -> Result<IssuedToken, IdentityError>;

    /// The verifier for tokens this provider issues.
    fn verifier(&self) -> &JwtVerifier;
}

/// v0.1's only [`IdentityProvider`]: this process holds its own RSA
/// keypair and is the sole authority on who gets a token. Requesters
/// authenticate with a shared `bootstrap_token` configured per-workload in
/// the registry — a stand-in for real SPIRE node attestation, not a
/// replacement for it.
pub struct LocalIssuer {
    registry: Registry,
    signer: JwtSigner,
    verifier: JwtVerifier,
    ttl_seconds: i64,
}

impl LocalIssuer {
    pub fn new(registry: Registry, signer: JwtSigner, verifier: JwtVerifier, ttl_seconds: i64) -> Self {
        Self {
            registry,
            signer,
            verifier,
            ttl_seconds,
        }
    }

    /// Generates a fresh 2048-bit RSA keypair and builds a `LocalIssuer`
    /// from it. Convenient when no key material is configured yet — but
    /// the key does not survive a restart, so every previously issued
    /// token becomes unverifiable. Fine for a learning/dev setup; a real
    /// deployment should load a persistent key (or use a real SPIRE-backed
    /// provider) instead.
    pub fn generate(registry: Registry, ttl_seconds: i64) -> Result<Self, IdentityError> {
        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|source| IdentityError::Jwt(JwtError::InvalidKey(source.to_string())))?;
        let public_key = RsaPublicKey::from(&private_key);

        let private_pem = private_key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|source| IdentityError::Jwt(JwtError::InvalidKey(source.to_string())))?;
        let public_pem = public_key
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|source| IdentityError::Jwt(JwtError::InvalidKey(source.to_string())))?;

        let signer = JwtSigner::from_rsa_pem(private_pem.as_bytes())?;
        let verifier = JwtVerifier::from_rsa_pem(public_pem.as_bytes())?;

        Ok(Self::new(registry, signer, verifier, ttl_seconds))
    }

    /// Builds a `LocalIssuer` from an existing RSA private key (PKCS#1 PEM),
    /// e.g. loaded from `GatewayConfig::signing_key_path`. The matching
    /// public key is derived from it for the verifier — callers only need
    /// to manage one file, the private key.
    pub fn from_rsa_private_pem(
        registry: Registry,
        private_key_pem: &[u8],
        ttl_seconds: i64,
    ) -> Result<Self, IdentityError> {
        let to_key_err = |source: rsa::pkcs1::Error| IdentityError::Jwt(JwtError::InvalidKey(source.to_string()));

        let pem_str = std::str::from_utf8(private_key_pem)
            .map_err(|source| IdentityError::Jwt(JwtError::InvalidKey(source.to_string())))?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(pem_str).map_err(to_key_err)?;
        let public_key = RsaPublicKey::from(&private_key);
        let public_pem = public_key.to_pkcs1_pem(LineEnding::LF).map_err(to_key_err)?;

        let signer = JwtSigner::from_rsa_pem(private_key_pem)?;
        let verifier = JwtVerifier::from_rsa_pem(public_pem.as_bytes())?;

        Ok(Self::new(registry, signer, verifier, ttl_seconds))
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }
}

impl IdentityProvider for LocalIssuer {
    fn issue_jwt_svid(
        &self,
        requester_workload_name: &str,
        audience: &str,
        credential: &str,
    ) -> Result<IssuedToken, IdentityError> {
        let requester = match self.registry.check_bootstrap_token(requester_workload_name, credential) {
            CredentialCheck::Ok(entry) => entry,
            CredentialCheck::UnknownWorkload => {
                return Err(IdentityError::UnknownWorkload(requester_workload_name.to_string()))
            }
            CredentialCheck::InvalidCredential => return Err(IdentityError::InvalidBootstrapToken),
        };

        let audience_id: SpiffeId = audience.parse()?;

        let now = crate::now_unix_secs();
        let claims = OboClaims {
            sub: requester.spiffe_id.to_string(),
            aud: vec![audience_id.to_string()],
            iat: now,
            exp: now + self.ttl_seconds,
        };

        let token = self.signer.sign(&claims)?;
        Ok(IssuedToken {
            token,
            expires_at: claims.exp,
        })
    }

    fn verifier(&self) -> &JwtVerifier {
        &self.verifier
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> Registry {
        Registry::from_yaml_str(
            r#"
trust_domain: chakra.internal
workloads:
  - name: orders-svc
    spiffe_id: spiffe://chakra.internal/ns/orders/sa/orders-svc
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: orders-secret
"#,
        )
        .unwrap()
    }

    #[test]
    fn issues_a_verifiable_token_for_a_correct_bootstrap_token() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();

        let issued = issuer
            .issue_jwt_svid(
                "orders-svc",
                "spiffe://chakra.internal/ns/inventory/sa/inventory-svc",
                "orders-secret",
            )
            .unwrap();

        let claims = issuer.verifier().verify_signature(&issued.token).unwrap();
        assert_eq!(claims.sub, "spiffe://chakra.internal/ns/orders/sa/orders-svc");
        assert_eq!(
            claims.aud,
            vec!["spiffe://chakra.internal/ns/inventory/sa/inventory-svc".to_string()]
        );
        assert_eq!(claims.exp, issued.expires_at);
        assert_eq!(claims.exp - claims.iat, 300);
    }

    #[test]
    fn rejects_a_wrong_bootstrap_token() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        let err = issuer
            .issue_jwt_svid(
                "orders-svc",
                "spiffe://chakra.internal/ns/inventory/sa/inventory-svc",
                "not-the-secret",
            )
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidBootstrapToken));
    }

    #[test]
    fn rejects_an_unknown_workload() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        let err = issuer
            .issue_jwt_svid(
                "ghost-svc",
                "spiffe://chakra.internal/ns/inventory/sa/inventory-svc",
                "anything",
            )
            .unwrap_err();
        assert!(matches!(err, IdentityError::UnknownWorkload(name) if name == "ghost-svc"));
    }

    #[test]
    fn from_rsa_private_pem_derives_a_working_verifier() {
        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_pem = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();

        let issuer = LocalIssuer::from_rsa_private_pem(test_registry(), private_pem.as_bytes(), 300).unwrap();

        let issued = issuer
            .issue_jwt_svid(
                "orders-svc",
                "spiffe://chakra.internal/ns/inventory/sa/inventory-svc",
                "orders-secret",
            )
            .unwrap();

        // The derived verifier must actually match the loaded private key.
        assert!(issuer.verifier().verify_signature(&issued.token).is_ok());
    }

    #[test]
    fn rejects_a_malformed_audience() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        let err = issuer
            .issue_jwt_svid("orders-svc", "not-a-spiffe-id", "orders-secret")
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidAudience(_)));
    }
}
