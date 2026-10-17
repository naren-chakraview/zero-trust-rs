//! SPIRE Workload API `IdentityProvider` (Task 5 / F13): fetches X.509 and
//! JWT identity material from a locally running SPIRE agent over its
//! Workload API, instead of this process minting its own tokens the way
//! [`crate::LocalIssuer`] does. See `IdentityProvider`'s doc comment in
//! `src/identity.rs` -- this is exactly the "future provider backed by a
//! real SPIRE server" it anticipated: no change to that trait, `obo.rs`,
//! or the HTTP layer was needed to add this.
//!
//! ## Where this *isn't* a drop-in replacement for `LocalIssuer`
//!
//! `LocalIssuer` is simultaneously an *issuer* (anyone can ask it to mint a
//! token for any registered workload, authenticated by a shared bootstrap
//! token) and a *verifier*. SPIRE's Workload API is deliberately not that:
//! a workload connecting to it can only ever fetch *its own* identity, as
//! attested by the SPIRE agent via node/workload attestation over the Unix
//! domain socket connection itself -- there is no RPC for "mint a token for
//! workload X, authenticated by secret Y", and no RPC that hands back raw
//! signing key material at all (that's the point of SPIRE: a workload
//! never holds a private key it can sign arbitrary data with).
//!
//! Concretely, this means:
//! - [`SpireProvider::issue_jwt_svid`] ignores `requester_workload_name`
//!   and `credential` -- there's nothing to check them against. Trust
//!   comes from the Workload API connection itself (this process's
//!   attested identity), which is a *stronger* authentication mechanism
//!   than `LocalIssuer`'s shared bootstrap token, not a weaker one. The
//!   token returned is always *this process's own* SVID for the requested
//!   `audience`, never a token "on behalf of" `requester_workload_name`.
//! - [`SpireProvider::sign_claims`] has no SPIRE equivalent at all and
//!   always returns `Err` -- RFC 8693 token exchange
//!   ([`crate::token_exchange::exchange_token`]) cannot be supported while
//!   a gateway runs with `SpireProvider` as its `IdentityProvider`. See
//!   this module's write-up in the Task 5 report for the follow-up this
//!   implies.
//! - [`SpireProvider::verifier`] only trusts RSA JWT authorities out of
//!   whatever JWT bundle SPIRE hands back at construction time -- this
//!   crate's [`crate::jwt::JwtVerifier`]/[`crate::jwt::JwtSigner`] are
//!   RS256-only today, while a real SPIRE server's default JWT-SVID key
//!   type is EC (ES256). An EC-only trust domain builds a `verifier()`
//!   with zero usable keys; every signature check then fails closed
//!   (`JwtError::UnknownKeyId`/`MissingKeyId`), never open. Adding ES256
//!   support to `jwt.rs` is a prerequisite for this to work against a real
//!   default-configured SPIRE deployment.

use spiffe::{JwtBundleSet, WorkloadApiClient, X509Svid};

use crate::error::IdentityError;
use crate::identity::{IdentityProvider, IssuedToken};
use crate::jwt::{JwtVerifier, OboClaims};

/// An [`IdentityProvider`] backed by a running SPIRE agent, reached over
/// its Workload API Unix domain socket (e.g.
/// `unix:/tmp/spire-agent/public/api.sock`). See the module doc comment
/// for exactly which `IdentityProvider` behaviors this can and can't
/// faithfully provide.
pub struct SpireProvider {
    client: WorkloadApiClient,
    verifier: JwtVerifier,
    /// Bridges this trait's synchronous methods
    /// ([`IdentityProvider::issue_jwt_svid`]) onto the underlying Workload
    /// API client's `async` RPCs. A dedicated runtime (rather than reusing
    /// whatever runtime called [`Self::new`]) so that blocking on it from
    /// inside, say, `zt-gateway`'s own multi-threaded runtime never
    /// re-enters that same runtime -- tokio only forbids `block_on`-ing a
    /// runtime from one of its own worker threads, not blocking on a
    /// second, independent one. The tradeoff: a call to `issue_jwt_svid`
    /// still ties up whichever thread calls it for the RPC's duration,
    /// same as any other blocking I/O would -- acceptable for this scope,
    /// but a candidate to revisit (e.g. making `IdentityProvider` itself
    /// `async`) before this carries real production traffic.
    rt: tokio::runtime::Runtime,
}

impl SpireProvider {
    /// Connects to the SPIRE agent at `socket_path` (e.g.
    /// `unix:/tmp/spire-agent/public/api.sock`) and fetches the current
    /// JWT bundle set to seed [`Self::verifier`]. Fails -- rather than
    /// constructing a provider that would only fail later -- if either the
    /// connection or that initial fetch doesn't succeed, which is exactly
    /// what happens when no SPIRE agent is listening on `socket_path` at
    /// all (this constructor's primary "fails gracefully" case, exercised
    /// by `tests/spire_provider_tests.rs`).
    pub async fn new(socket_path: &str) -> Result<Self, IdentityError> {
        let client = WorkloadApiClient::connect_to(socket_path)
            .await
            .map_err(|source| IdentityError::Spire(format!("failed to connect to {socket_path}: {source}")))?;

        let bundles = client
            .fetch_jwt_bundles()
            .await
            .map_err(|source| IdentityError::Spire(format!("failed to fetch JWT bundles: {source}")))?;
        let verifier = verifier_from_jwt_bundles(&bundles);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|source| IdentityError::Spire(format!("failed to start bridging runtime: {source}")))?;

        Ok(Self { client, verifier, rt })
    }

    /// Fetches this workload's default X.509 SVID directly from SPIRE.
    pub async fn fetch_x509_svid(&self) -> Result<X509Svid, IdentityError> {
        self.client
            .fetch_x509_svid()
            .await
            .map_err(|source| IdentityError::Spire(format!("failed to fetch X.509 SVID: {source}")))
    }

    /// Fetches the current JWT verification bundle set directly from
    /// SPIRE -- the same data [`Self::new`] used to seed [`Self::verifier`],
    /// exposed here so a caller can observe the live, current set (e.g.
    /// after key rotation) rather than the snapshot taken at construction
    /// time.
    pub async fn fetch_jwt_bundles(&self) -> Result<JwtBundleSet, IdentityError> {
        self.client
            .fetch_jwt_bundles()
            .await
            .map_err(|source| IdentityError::Spire(format!("failed to fetch JWT bundles: {source}")))
    }
}

/// Builds a [`JwtVerifier`] trusting every *RSA* JWT authority across every
/// trust domain in `bundles` -- see the module doc comment's third bullet
/// for why non-RSA (e.g. SPIRE's default ES256) authorities are silently
/// skipped rather than this failing outright: an EC-only trust domain still
/// produces *a* verifier, just one with no keys, which fails closed on
/// every verification rather than refusing to start at all.
fn verifier_from_jwt_bundles(bundles: &JwtBundleSet) -> JwtVerifier {
    let mut entries = Vec::new();
    for (_trust_domain, bundle) in bundles.iter() {
        for authority in bundle.jwt_authorities() {
            if let Some(decoding_key) = rsa_decoding_key_from_jwk(authority.jwk_json()) {
                entries.push((authority.key_id().to_string(), decoding_key));
            }
        }
    }
    JwtVerifier::from_jwks_entries(entries)
}

/// Parses `jwk_json` (a single JWK, as SPIRE's JWT bundle hands back per
/// authority) into a [`jsonwebtoken::DecodingKey`], or `None` if it isn't
/// an RSA key -- a JWK's `n`/`e` fields are already base64url-encoded, the
/// exact form [`jsonwebtoken::DecodingKey::from_rsa_components`] expects.
fn rsa_decoding_key_from_jwk(jwk_json: &[u8]) -> Option<jsonwebtoken::DecodingKey> {
    let jwk: serde_json::Value = serde_json::from_slice(jwk_json).ok()?;
    if jwk.get("kty")?.as_str()? != "RSA" {
        return None;
    }
    let n = jwk.get("n")?.as_str()?;
    let e = jwk.get("e")?.as_str()?;
    jsonwebtoken::DecodingKey::from_rsa_components(n, e).ok()
}

impl IdentityProvider for SpireProvider {
    /// See the module doc comment's first bullet: `requester_workload_name`
    /// and `credential` are accepted (for signature compatibility with
    /// `LocalIssuer`) but not used -- SPIRE has already authenticated
    /// *this* process via the Workload API connection itself, and
    /// `audience` is issued against that identity.
    fn issue_jwt_svid(
        &self,
        _requester_workload_name: &str,
        audience: &str,
        _credential: &str,
    ) -> Result<IssuedToken, IdentityError> {
        let svid = self
            .rt
            .block_on(self.client.fetch_jwt_svid(std::iter::once(audience), None))
            .map_err(|source| IdentityError::Spire(format!("failed to fetch JWT-SVID for {audience}: {source}")))?;

        Ok(IssuedToken {
            token: svid.token().to_string(),
            expires_at: svid.claims().exp(),
        })
    }

    fn verifier(&self) -> &JwtVerifier {
        &self.verifier
    }

    /// Always `Err` -- see the module doc comment's second bullet. SPIRE
    /// never hands a workload raw signing key material, so there is no way
    /// to satisfy this trait method's "sign these exact claims" contract.
    fn sign_claims(&self, _claims: &OboClaims) -> Result<String, IdentityError> {
        Err(IdentityError::Spire(
            "sign_claims is not supported by SpireProvider: the SPIRE Workload API never \
             exposes private signing key material to a workload, so RFC 8693 token exchange \
             is unavailable while SpireProvider is the configured IdentityProvider"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::{general_purpose, Engine as _};
    use rsa::traits::PublicKeyParts;

    #[test]
    fn rsa_decoding_key_from_jwk_accepts_an_rsa_jwk() {
        // A real (but arbitrary) RSA public key's JWK representation --
        // n/e taken from a freshly generated 2048-bit key so this doesn't
        // depend on any fixture file.
        let mut rng = rand::rngs::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let n = general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
        let jwk = serde_json::json!({ "kty": "RSA", "n": n, "e": e, "kid": "key-1" }).to_string();

        assert!(rsa_decoding_key_from_jwk(jwk.as_bytes()).is_some());
    }

    #[test]
    fn rsa_decoding_key_from_jwk_rejects_an_ec_jwk() {
        // SPIRE's default JWT-SVID key type -- exactly the case the module
        // doc comment's third bullet describes as currently unsupported.
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "kid": "key-1"
        })
        .to_string();

        assert!(rsa_decoding_key_from_jwk(jwk.as_bytes()).is_none());
    }

    #[test]
    fn rsa_decoding_key_from_jwk_rejects_malformed_json() {
        assert!(rsa_decoding_key_from_jwk(b"not json").is_none());
    }

    #[test]
    fn verifier_from_jwt_bundles_skips_non_rsa_authorities_and_keeps_an_empty_but_valid_verifier() {
        // No live SPIRE agent needed for this -- an empty JwtBundleSet is
        // the degenerate case of "every authority was non-RSA", and proves
        // `verifier_from_jwt_bundles` degrades to an empty (not absent)
        // verifier, exactly as the module doc comment describes.
        let bundles = JwtBundleSet::default();
        let verifier = verifier_from_jwt_bundles(&bundles);
        // An empty verifier still exists and simply rejects every token --
        // "fails closed", not a panic or an unwrap at the trait boundary.
        assert!(verifier.verify_signature("not.a.token").is_err());
    }
}
