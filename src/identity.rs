//! Workload identity issuance — the seam where "how do we get a JWT SVID"
//! is decided, kept separate from `obo.rs` (which only ever consumes
//! already-issued tokens) and from the HTTP layer.

use jsonwebtoken::DecodingKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;

use crate::error::{IdentityError, JwtError};
use crate::jwt::{CertBinding, JwtSigner, JwtVerifier, OboClaims};
use crate::registry::{CredentialCheck, Registry};
use crate::spiffe_id::SpiffeId;

/// One entry of a JWKS document loaded by [`LocalIssuer::with_jwks`].
///
/// A real-world JWKS carries only public key material (`n`, `e`) because
/// it's meant to be published for anyone to fetch. This project has no
/// such external fetch path — every gateway in a trust domain instead
/// loads the *same* document from a file (or secret store) side-by-side,
/// so it additionally embeds the PKCS#1 private key PEM for each `kid`.
/// That's what lets each gateway both sign with its own `active_kid` and
/// verify every other key in the set — including keys it never signs
/// with itself, which is exactly what cross-gateway verification needs.
#[derive(Debug, Deserialize)]
struct JwksKeyEntry {
    kid: String,
    private_key_pem: String,
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<JwksKeyEntry>,
}

fn parse_jwks(jwks_data: &str) -> Result<Vec<JwksKeyEntry>, IdentityError> {
    let document: JwksDocument =
        serde_json::from_str(jwks_data).map_err(|source| IdentityError::InvalidJwks(source.to_string()))?;
    Ok(document.keys)
}

/// A fresh, random JWT ID (`jti`) for a newly issued token (Task 3): a v4
/// UUID, unique enough that two independently issued tokens are never
/// expected to collide. Used by both [`LocalIssuer::issue_jwt_svid`] and
/// [`LocalIssuer::issue_jwt_svid_with_cert_binding`] so every token this
/// provider mints carries one, for downstream replay-cache tracking.
fn generate_jti() -> String {
    use uuid::Uuid;
    Uuid::new_v4().to_string()
}

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

    /// Signs already-built [`OboClaims`] directly with this provider's
    /// active signing key, bypassing `issue_jwt_svid`'s bootstrap-token
    /// authentication entirely.
    ///
    /// This exists for RFC 8693 token exchange
    /// ([`crate::token_exchange::exchange_token`]): the caller has already
    /// independently verified the *inbound* token via [`Self::verifier`]
    /// and is re-minting its claims (new `aud`, extended `act` chain, fresh
    /// `iat`/`exp`/`jti`) for the next hop — there is no bootstrap token to
    /// check because nothing new is being authenticated, only re-signed.
    fn sign_claims(&self, claims: &OboClaims) -> Result<String, IdentityError>;
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

    /// Builds a `LocalIssuer` from a JWKS document (see [`JwksKeyEntry`] for
    /// its shape) shared across every gateway in a trust domain: this
    /// instance signs with the key named `active_kid`, but its verifier
    /// trusts *every* key in the document, so it can verify tokens signed
    /// by another gateway's differently-chosen `active_kid` — the
    /// cross-gateway verification this task exists for.
    ///
    /// Fails fast — before issuing a single token — if `jwks_data` isn't
    /// valid JSON in the expected shape, or if `active_kid` doesn't name a
    /// key actually present in it.
    pub fn with_jwks(
        registry: Registry,
        jwks_data: &str,
        active_kid: String,
        ttl_seconds: i64,
    ) -> Result<Self, IdentityError> {
        let entries = parse_jwks(jwks_data)?;
        if !entries.iter().any(|entry| entry.kid == active_kid) {
            return Err(IdentityError::InvalidKeyId(active_kid));
        }

        let to_key_err =
            |source: rsa::pkcs1::Error| IdentityError::Jwt(JwtError::InvalidKey(source.to_string()));

        let mut decoding_entries = Vec::with_capacity(entries.len());
        let mut active_signer = None;

        for entry in &entries {
            let private_key = RsaPrivateKey::from_pkcs1_pem(&entry.private_key_pem).map_err(to_key_err)?;
            let public_key = RsaPublicKey::from(&private_key);
            let public_pem = public_key.to_pkcs1_pem(LineEnding::LF).map_err(to_key_err)?;
            let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
                .map_err(|source| IdentityError::Jwt(JwtError::InvalidKey(source.to_string())))?;
            decoding_entries.push((entry.kid.clone(), decoding_key));

            if entry.kid == active_kid {
                active_signer = Some(JwtSigner::from_rsa_pem_with_kid(
                    entry.private_key_pem.as_bytes(),
                    active_kid.clone(),
                )?);
            }
        }

        let verifier = JwtVerifier::from_jwks_entries(decoding_entries);
        // `active_kid`'s presence was checked above, so this always succeeds.
        let signer = active_signer.expect("active_kid was verified to be present in entries");

        Ok(Self::new(registry, signer, verifier, ttl_seconds))
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Like [`IdentityProvider::issue_jwt_svid`], but the issued token also
    /// carries a signed `cnf.x5t#S256` claim (RFC 8705, Task 8) binding it
    /// to `cert_thumbprint` — the thumbprint of the TLS client certificate
    /// this token is meant to be presented alongside. Authentication
    /// (`credential` against the requester's configured bootstrap token)
    /// works identically to `issue_jwt_svid`; the only difference is the
    /// extra signed claim on the resulting token, which later lets
    /// `obo::validate_with_cert_binding` reject the token outright if it's
    /// ever replayed from a connection presenting a different (or no)
    /// client certificate.
    pub fn issue_jwt_svid_with_cert_binding(
        &self,
        requester_workload_name: &str,
        audience: &str,
        cert_thumbprint: &str,
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
            user: None,
            act: None,
            iat: now,
            exp: now + self.ttl_seconds,
            nbf: Some(now),
            jti: Some(generate_jti()),
            cnf: Some(CertBinding {
                x5t_s256: cert_thumbprint.to_string(),
            }),
            iss: Some(format!("spiffe://{}", self.registry.trust_domain())),
        };

        let token = self.signer.sign(&claims)?;
        Ok(IssuedToken {
            token,
            expires_at: claims.exp,
        })
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
            user: None,
            act: None,
            iat: now,
            exp: now + self.ttl_seconds,
            nbf: Some(now),
            jti: Some(generate_jti()),
            cnf: None,
            iss: Some(format!("spiffe://{}", self.registry.trust_domain())),
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

    fn sign_claims(&self, claims: &OboClaims) -> Result<String, IdentityError> {
        Ok(self.signer.sign(claims)?)
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

    /// Builds a JWKS-style document (`{"keys": [...]}`) containing a fresh
    /// 2048-bit RSA keypair per `kid`. This is the same JSON every gateway
    /// in a trust domain would load `LocalIssuer::with_jwks` from.
    fn generate_jwks_json(kids: &[&str]) -> String {
        let mut rng = rand::rngs::OsRng;
        let keys: Vec<_> = kids
            .iter()
            .map(|kid| {
                let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
                let pem = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();
                serde_json::json!({ "kid": kid, "kty": "RSA", "private_key_pem": pem.to_string() })
            })
            .collect();
        serde_json::json!({ "keys": keys }).to_string()
    }

    #[test]
    fn with_jwks_loads_multiple_keys_and_signs_with_the_active_one() {
        let jwks_json = generate_jwks_json(&["key-1", "key-2"]);
        let issuer = LocalIssuer::with_jwks(test_registry(), &jwks_json, "key-1".to_string(), 300).unwrap();

        let issued = issuer
            .issue_jwt_svid(
                "orders-svc",
                "spiffe://chakra.internal/ns/inventory/sa/inventory-svc",
                "orders-secret",
            )
            .unwrap();

        // The signed token must carry the active kid in its header.
        let header = jsonwebtoken::decode_header(&issued.token).unwrap();
        assert_eq!(header.kid, Some("key-1".to_string()));

        // And it must verify against this same issuer's verifier.
        assert!(issuer.verifier().verify_signature(&issued.token).is_ok());
    }

    #[test]
    fn with_jwks_rejects_an_active_kid_not_present_in_the_set() {
        let jwks_json = generate_jwks_json(&["key-1"]);
        // `LocalIssuer` doesn't implement `Debug`, so `unwrap_err()` isn't
        // available (it requires the `Ok` side to be `Debug` too) — match
        // instead.
        let err = match LocalIssuer::with_jwks(test_registry(), &jwks_json, "does-not-exist".to_string(), 300) {
            Err(err) => err,
            Ok(_) => panic!("expected with_jwks to reject an unknown active_kid"),
        };
        assert!(matches!(err, IdentityError::InvalidKeyId(kid) if kid == "does-not-exist"));
    }

    #[test]
    fn with_jwks_rejects_malformed_jwks_json() {
        let err = match LocalIssuer::with_jwks(test_registry(), "not valid json", "key-1".to_string(), 300) {
            Err(err) => err,
            Ok(_) => panic!("expected with_jwks to reject malformed JWKS JSON"),
        };
        assert!(matches!(err, IdentityError::InvalidJwks(_)));
    }

    #[test]
    fn cross_gateway_verification_with_a_shared_jwks() {
        // Two independent gateways load the *same* JWKS, but each signs
        // with a different active key — the whole point of distributing a
        // shared key set rather than each gateway generating its own.
        let jwks_json = generate_jwks_json(&["key-1", "key-2"]);

        let issuer1 = LocalIssuer::with_jwks(test_registry(), &jwks_json, "key-1".to_string(), 300).unwrap();
        let issuer2 = LocalIssuer::with_jwks(test_registry(), &jwks_json, "key-2".to_string(), 300).unwrap();

        let issued = issuer1
            .issue_jwt_svid(
                "orders-svc",
                "spiffe://chakra.internal/ns/inventory/sa/inventory-svc",
                "orders-secret",
            )
            .unwrap();

        // issuer2's active signing key is key-2, but its verifier trusts
        // every key in the shared JWKS — including key-1, which actually
        // signed this token.
        let claims = issuer2.verifier().verify_signature(&issued.token).unwrap();
        assert_eq!(claims.sub, "spiffe://chakra.internal/ns/orders/sa/orders-svc");

        // And the reverse holds too.
        let issued2 = issuer2
            .issue_jwt_svid(
                "orders-svc",
                "spiffe://chakra.internal/ns/inventory/sa/inventory-svc",
                "orders-secret",
            )
            .unwrap();
        assert!(issuer1.verifier().verify_signature(&issued2.token).is_ok());
    }

    // --- RFC 8705 certificate-bound issuance (Task 8, F5) ---

    #[test]
    fn issue_jwt_svid_with_cert_binding_signs_a_token_carrying_the_cnf_claim() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();

        let issued = issuer
            .issue_jwt_svid_with_cert_binding(
                "orders-svc",
                "spiffe://chakra.internal/ns/inventory/sa/inventory-svc",
                "cert-a-thumbprint",
                "orders-secret",
            )
            .unwrap();

        let claims = issuer.verifier().verify_signature(&issued.token).unwrap();
        assert_eq!(claims.sub, "spiffe://chakra.internal/ns/orders/sa/orders-svc");
        assert_eq!(
            claims.cnf,
            Some(CertBinding {
                x5t_s256: "cert-a-thumbprint".to_string(),
            })
        );
    }

    #[test]
    fn issue_jwt_svid_with_cert_binding_rejects_a_wrong_bootstrap_token() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        let err = issuer
            .issue_jwt_svid_with_cert_binding(
                "orders-svc",
                "spiffe://chakra.internal/ns/inventory/sa/inventory-svc",
                "cert-a-thumbprint",
                "not-the-secret",
            )
            .unwrap_err();
        assert!(matches!(err, IdentityError::InvalidBootstrapToken));
    }

    #[test]
    fn verifier_rejects_a_token_with_an_unknown_kid() {
        let jwks_json = generate_jwks_json(&["key-1"]);
        let issuer = LocalIssuer::with_jwks(test_registry(), &jwks_json, "key-1".to_string(), 300).unwrap();

        // A token signed by some other key entirely, not in this JWKS.
        let mut rng = rand::rngs::OsRng;
        let rogue_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let rogue_pem = rogue_key.to_pkcs1_pem(LineEnding::LF).unwrap();
        let rogue_signer =
            crate::jwt::JwtSigner::from_rsa_pem_with_kid(rogue_pem.as_bytes(), "unregistered".to_string()).unwrap();
        let claims = crate::jwt::OboClaims {
            sub: "spiffe://chakra.internal/ns/orders/sa/orders-svc".to_string(),
            aud: vec!["spiffe://chakra.internal/ns/inventory/sa/inventory-svc".to_string()],
            user: None,
            act: None,
            iat: 0,
            exp: 9_999_999_999,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let rogue_token = rogue_signer.sign(&claims).unwrap();

        assert!(issuer.verifier().verify_signature(&rogue_token).is_err());
    }
}
