//! Workload identity issuance — the seam where "how do we get a JWT SVID"
//! is decided, kept separate from `obo.rs` (which only ever consumes
//! already-issued tokens) and from the HTTP layer.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::DecodingKey;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

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

/// One public RSA key in a [`JsonWebKeySet`]: only the RFC 7517 public
/// members (`kty`, `kid`, `n`, `e`). There is deliberately no field for
/// private material, so a serialized set can never carry it (N7, F4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicJwk {
    pub kty: String,
    pub kid: String,
    pub n: String,
    pub e: String,
}

/// The public verification set shared by every gateway in a trust domain
/// (N7, review 0002 / F4). Unlike the legacy [`LocalIssuer::with_jwks`]
/// document, this carries no private keys: each issuer loads its own
/// private signing key separately (see [`LocalIssuer::with_separated_keys`])
/// and every verifier loads only this public set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonWebKeySet {
    pub keys: Vec<PublicJwk>,
}

impl JsonWebKeySet {
    /// Derives the public half of an RSA private key (PKCS#1 PEM) and wraps
    /// it as a one-key set under `kid`. The private key itself is not kept.
    pub fn from_rsa_private_pem(kid: String, private_key_pem: &[u8]) -> Result<Self, IdentityError> {
        let to_key_err = |source: rsa::pkcs1::Error| IdentityError::Jwt(JwtError::InvalidKey(source.to_string()));

        let pem_str = std::str::from_utf8(private_key_pem)
            .map_err(|source| IdentityError::Jwt(JwtError::InvalidKey(source.to_string())))?;
        let private_key = RsaPrivateKey::from_pkcs1_pem(pem_str).map_err(to_key_err)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            keys: vec![PublicJwk {
                kty: "RSA".to_string(),
                kid,
                n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            }],
        })
    }

    /// Adds every key in `other` to this set, e.g. to publish several
    /// gateways' keys in one document during rotation.
    pub fn extend(&mut self, other: JsonWebKeySet) {
        self.keys.extend(other.keys);
    }

    /// Serializes to the JSON document a verifier loads from `jwks_path`.
    /// The output contains only public members by construction.
    pub fn to_json(&self) -> Result<String, IdentityError> {
        serde_json::to_string_pretty(self).map_err(|source| IdentityError::InvalidJwks(source.to_string()))
    }

    /// Parses a public JWKS document. Any private-key members present in the
    /// input are ignored, so a verifier never holds private material even if
    /// it is pointed at a file that contains some.
    pub fn from_json(jwks_data: &str) -> Result<Self, IdentityError> {
        serde_json::from_str(jwks_data).map_err(|source| IdentityError::InvalidJwks(source.to_string()))
    }

    /// The RSA verification key registered under `kid`, for checking a
    /// third-party token (see `user_auth`). Errors if no key carries that
    /// `kid` or the key isn't RSA.
    pub fn decoding_key(&self, kid: &str) -> Result<DecodingKey, IdentityError> {
        let jwk = self
            .keys
            .iter()
            .find(|jwk| jwk.kid == kid)
            .ok_or_else(|| IdentityError::InvalidKeyId(kid.to_string()))?;
        if jwk.kty != "RSA" {
            return Err(IdentityError::InvalidJwks(format!("unsupported kty {:?} for kid {:?}", jwk.kty, jwk.kid)));
        }
        DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|source| IdentityError::Jwt(JwtError::InvalidKey(source.to_string())))
    }

    /// Builds a verify-only [`JwtVerifier`] trusting every key in this set.
    pub fn to_verifier(&self) -> Result<JwtVerifier, IdentityError> {
        let mut entries = Vec::with_capacity(self.keys.len());
        for jwk in &self.keys {
            if jwk.kty != "RSA" {
                return Err(IdentityError::InvalidJwks(format!("unsupported kty {:?} for kid {:?}", jwk.kty, jwk.kid)));
            }
            let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
                .map_err(|source| IdentityError::Jwt(JwtError::InvalidKey(source.to_string())))?;
            entries.push((jwk.kid.clone(), decoding_key));
        }
        Ok(JwtVerifier::from_jwks_entries(entries))
    }
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

    /// The `iss` value this provider stamps into the tokens it signs (R6 fix,
    /// review 0003): the identity of the signing gateway. `None` when the provider
    /// can't sign, so exchange has nothing to stamp.
    fn issuer_claim(&self) -> Option<String> {
        None
    }

    /// Like [`Self::issue_jwt_svid`], but the issued token also carries a
    /// signed `cnf.x5t#S256` claim (RFC 8705) binding it to
    /// `cert_thumbprint` (N6 fix, review 0002): this is what
    /// `POST /v1/svid/jwt` calls by default whenever the caller presented
    /// an mTLS client certificate, so a token that leaks off that
    /// connection (a compromised log, SSRF, a replay from a different
    /// host) is useless without also presenting the same certificate on
    /// the connection that uses it. See
    /// [`LocalIssuer::issue_jwt_svid_with_cert_binding`] for the concrete
    /// claim shape.
    ///
    /// The default implementation always refuses, for the same reason
    /// [`Self::issue_jwt_svid_with_user`]'s does: producing this specific
    /// signed claim shape requires holding this provider's signing key
    /// material directly, which not every `IdentityProvider` does (e.g.
    /// [`crate::SpireProvider`] issues JWT-SVIDs through SPIRE's own
    /// Workload API, with no way to ask it to embed an arbitrary `cnf`
    /// claim). [`LocalIssuer`] is the only provider that overrides this.
    fn issue_jwt_svid_with_cert_binding(
        &self,
        _requester_workload_name: &str,
        _audience: &str,
        _cert_thumbprint: &str,
        _credential: &str,
    ) -> Result<IssuedToken, IdentityError> {
        Err(IdentityError::Spire(
            "issue_jwt_svid_with_cert_binding is not supported by this identity provider".to_string(),
        ))
    }

    /// Edge mint path for a human user principal (N5 fix, review 0002):
    /// mints a token whose `sub` is `gateway_id` and whose `user` claim
    /// carries a human principal string (e.g. `user@corp.internal`), not a
    /// SPIFFE ID -- the entry point into the mesh for human-originated
    /// requests, letting a downstream verifier attribute an action to a
    /// human rather than only to the service identity that made the call.
    /// `user_issuer` must be present in `trusted_user_issuers`
    /// (the deployment's configured `GatewayConfig::user_issuers`) or this
    /// fails with [`IdentityError::UntrustedUserIssuer`].
    ///
    /// The default implementation always refuses: minting a token requires
    /// direct access to signing key material, which not every
    /// `IdentityProvider` holds (see [`crate::SpireProvider::sign_claims`]'s
    /// doc comment for the same limitation). [`LocalIssuer`] is the only
    /// provider that overrides this.
    fn issue_jwt_svid_with_user(
        &self,
        _gateway_id: &SpiffeId,
        _user_principal: &str,
        _user_issuer: &str,
        _trusted_user_issuers: &[String],
    ) -> Result<IssuedToken, IdentityError> {
        Err(IdentityError::Spire(
            "issue_jwt_svid_with_user is not supported by this identity provider".to_string(),
        ))
    }
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
    /// `true` only when built by [`Self::with_separated_keys`], i.e. the
    /// private signing key was loaded on its own and never came from a
    /// shared JWKS document (N7).
    separated_signing_key: bool,
}

impl LocalIssuer {
    pub fn new(registry: Registry, signer: JwtSigner, verifier: JwtVerifier, ttl_seconds: i64) -> Self {
        Self {
            registry,
            signer,
            verifier,
            ttl_seconds,
            separated_signing_key: false,
        }
    }

    /// Whether this issuer's private key was loaded separately from the
    /// public verification set (see [`Self::with_separated_keys`]).
    pub fn has_separated_signing_key(&self) -> bool {
        self.separated_signing_key
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

    /// **Deprecated (R10, review 0003).** Builds a `LocalIssuer` from a JWKS
    /// document that holds a private key for every `kid`, so every gateway that
    /// loads it can sign as any of them. The binary doesn't use it. Use
    /// [`Self::with_separated_keys`] with a public [`JsonWebKeySet`].
    ///
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
        // R10 fix (review 0003): this document carries a private key for every kid, so
        // any gateway that loads it can mint as any other. The binary no longer uses it.
        // Use LocalIssuer::with_separated_keys with a public JsonWebKeySet.
        tracing::warn!(
            "LocalIssuer::with_jwks loads a private key for every kid; use with_separated_keys and a public JsonWebKeySet"
        );
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

    /// Builds a `LocalIssuer` that signs with a private key loaded from
    /// `signing_key_pem` (this issuer's only private material) and verifies
    /// against the public `public_jwks` set (N7, review 0002 / F4). Unlike
    /// [`Self::with_jwks`], the verifier never sees a private key.
    ///
    /// `active_kid` names which key in `public_jwks` this issuer signs with.
    /// It may be `None` only when the set holds exactly one key. The private
    /// key must match that key's published public half, so a misconfigured
    /// pairing fails at startup instead of minting tokens nobody can verify.
    pub fn with_separated_keys(
        registry: Registry,
        signing_key_pem: &[u8],
        active_kid: Option<String>,
        public_jwks: &JsonWebKeySet,
        ttl_seconds: i64,
    ) -> Result<Self, IdentityError> {
        let kid = match active_kid {
            Some(kid) => kid,
            None if public_jwks.keys.len() == 1 => public_jwks.keys[0].kid.clone(),
            None => {
                return Err(IdentityError::InvalidJwks(
                    "active_kid is required when the public key set holds more than one key".to_string(),
                ))
            }
        };

        let published = public_jwks
            .keys
            .iter()
            .find(|jwk| jwk.kid == kid)
            .ok_or_else(|| IdentityError::InvalidKeyId(kid.clone()))?;

        let derived = JsonWebKeySet::from_rsa_private_pem(kid.clone(), signing_key_pem)?;
        let derived = &derived.keys[0];
        if derived.n != published.n || derived.e != published.e {
            return Err(IdentityError::InvalidJwks(format!(
                "signing key does not match the public key published for kid {kid:?}"
            )));
        }

        let signer = JwtSigner::from_rsa_pem_with_kid(signing_key_pem, kid)?;
        let verifier = public_jwks.to_verifier()?;

        let mut issuer = Self::new(registry, signer, verifier, ttl_seconds);
        issuer.separated_signing_key = true;
        Ok(issuer)
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// The SPIFFE ID of the gateway that signs with this issuer's key:
    /// `spiffe://<trust_domain>/ns/zt-gateway/sa/<kid>`. Every token this issuer
    /// mints carries it as `iss`, so an operator can see which key signed it.
    pub fn gateway_iss(&self) -> String {
        let kid = self.signer.kid().unwrap_or("default");
        format!("spiffe://{}/ns/zt-gateway/sa/{}", self.registry.trust_domain(), kid)
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
            user_iss: None,
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
            iss: Some(self.gateway_iss()),
        };

        let token = self.signer.sign(&claims)?;
        Ok(IssuedToken {
            token,
            expires_at: claims.exp,
        })
    }

    /// Edge mint path for a human user principal (N5 fix, review 0002).
    /// See [`IdentityProvider::issue_jwt_svid_with_user`] for the full
    /// contract. `aud` is self-scoped to `gateway_id` -- this method mints
    /// a self-identity token carrying the human principal, which
    /// `POST /v1/token-exchange` (`token_exchange::exchange_token`) then
    /// re-scopes to each real downstream audience while preserving `user`
    /// and `iss` verbatim, so the human principal and its trusted issuer
    /// survive every hop.
    ///
    /// Unlike [`Self::issue_jwt_svid`]/[`Self::issue_jwt_svid_with_cert_binding`],
    /// there is no bootstrap-token credential to check against the
    /// workload registry here -- no workload is being authenticated, only
    /// a human credential whose issuer this call validates directly
    /// against `trusted_user_issuers`.
    pub fn issue_jwt_svid_with_user(
        &self,
        gateway_id: &SpiffeId,
        user_principal: &str,
        user_issuer: &str,
        trusted_user_issuers: &[String],
    ) -> Result<IssuedToken, IdentityError> {
        if !trusted_user_issuers.iter().any(|trusted| trusted == user_issuer) {
            return Err(IdentityError::UntrustedUserIssuer(user_issuer.to_string()));
        }

        let now = crate::now_unix_secs();
        let claims = OboClaims {
            sub: gateway_id.to_string(),
            aud: vec![gateway_id.to_string()],
            user: Some(user_principal.to_string()),
            act: None,
            iat: now,
            exp: now + self.ttl_seconds,
            nbf: Some(now),
            jti: Some(generate_jti()),
            cnf: None,
            // The trusted IdP that vouched for `user_principal`, not this
            // gateway's own trust domain -- see
            // `obo::validate_with_user_issuers`, which checks exactly this
            // claim against `GatewayConfig::user_issuers` to decide
            // whether to accept the non-SPIFFE-ID `user` claim above.
            // R6 fix (review 0003): the gateway signs this token, so `iss` names it.
            // The IdP that vouched for the user is recorded in `user_iss`.
            iss: Some(self.gateway_iss()),
            user_iss: Some(user_issuer.to_string()),
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
            user_iss: None,
            sub: requester.spiffe_id.to_string(),
            aud: vec![audience_id.to_string()],
            user: None,
            act: None,
            iat: now,
            exp: now + self.ttl_seconds,
            nbf: Some(now),
            jti: Some(generate_jti()),
            cnf: None,
            iss: Some(self.gateway_iss()),
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

    fn issuer_claim(&self) -> Option<String> {
        Some(self.gateway_iss())
    }

    fn sign_claims(&self, claims: &OboClaims) -> Result<String, IdentityError> {
        Ok(self.signer.sign(claims)?)
    }

    /// Delegates to the inherent [`Self::issue_jwt_svid_with_cert_binding`]
    /// -- kept as a separate trait override (rather than relying on the
    /// default) so a caller holding only `&dyn IdentityProvider` (e.g.
    /// `zt-gateway`'s `AppState::identity`, which is exactly what
    /// `POST /v1/svid/jwt` calls through, N6 fix) can still reach it --
    /// the same pattern [`Self::issue_jwt_svid_with_user`] below already
    /// uses.
    fn issue_jwt_svid_with_cert_binding(
        &self,
        requester_workload_name: &str,
        audience: &str,
        cert_thumbprint: &str,
        credential: &str,
    ) -> Result<IssuedToken, IdentityError> {
        self.issue_jwt_svid_with_cert_binding(requester_workload_name, audience, cert_thumbprint, credential)
    }

    /// Delegates to the inherent [`Self::issue_jwt_svid_with_user`] -- kept
    /// as a separate trait override (rather than relying on the default)
    /// so a caller holding only `&dyn IdentityProvider` (e.g.
    /// `zt-gateway`'s `AppState::identity`) can still reach it.
    fn issue_jwt_svid_with_user(
        &self,
        gateway_id: &SpiffeId,
        user_principal: &str,
        user_issuer: &str,
        trusted_user_issuers: &[String],
    ) -> Result<IssuedToken, IdentityError> {
        self.issue_jwt_svid_with_user(gateway_id, user_principal, user_issuer, trusted_user_issuers)
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
            user_iss: None,
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
