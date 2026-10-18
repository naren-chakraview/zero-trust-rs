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
//! - [`SpireProvider::verifier`] trusts both RSA (RS256) and EC/P-256
//!   (ES256) JWT authorities out of whatever JWT bundle SPIRE hands back
//!   at construction time (Task 11 / N8 -- see
//!   [`crate::jwt::JwtVerifier::from_jwks_entries_with_algorithms`]). A
//!   real SPIRE server's default JWT-SVID key type is EC (ES256), so this
//!   is what makes a default-configured SPIRE deployment actually work
//!   out-of-the-box: before this, an EC-only trust domain built a
//!   `verifier()` with zero usable keys, and every signature check failed
//!   closed (`JwtError::UnknownKeyId`/`MissingKeyId`), never open. Any
//!   other key type (anything that's neither RSA nor EC/P-256) is still
//!   silently skipped the same way RSA-only skipped EC before this.

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

        Ok(Self { client, verifier })
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

/// Builds a [`JwtVerifier`] trusting every *RSA* (RS256) or *EC/P-256*
/// (ES256) JWT authority across every trust domain in `bundles` (Task 11 /
/// N8) -- any other key type is silently skipped rather than this failing
/// outright: a trust domain whose authorities are all unsupported key
/// types still produces *a* verifier, just one with no keys, which fails
/// closed on every verification rather than refusing to start at all.
fn verifier_from_jwt_bundles(bundles: &JwtBundleSet) -> JwtVerifier {
    let mut entries = Vec::new();
    for (_trust_domain, bundle) in bundles.iter() {
        for authority in bundle.jwt_authorities() {
            if let Some(decoding_key) = rsa_decoding_key_from_jwk(authority.jwk_json()) {
                entries.push((authority.key_id().to_string(), decoding_key, jsonwebtoken::Algorithm::RS256));
            } else if let Some(decoding_key) = ec_decoding_key_from_jwk(authority.jwk_json()) {
                entries.push((authority.key_id().to_string(), decoding_key, jsonwebtoken::Algorithm::ES256));
            }
        }
    }
    JwtVerifier::from_jwks_entries_with_algorithms(entries)
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

/// Parses `jwk_json` into a [`jsonwebtoken::DecodingKey`], or `None` if it
/// isn't a P-256 EC key -- Task 11 / N8, this is SPIRE's *default*
/// JWT-SVID key type, so this is the branch that makes a
/// default-configured SPIRE deployment actually produce usable keys. Only
/// `"kty": "EC"` with `"crv": "P-256"` is recognized (other curves, e.g.
/// P-384/P-521, aren't supported by this crate's ES256-only EC support and
/// are treated the same as any other unrecognized key type). A JWK's
/// `x`/`y` fields are already base64url-encoded, the exact form
/// [`jsonwebtoken::DecodingKey::from_ec_components`] expects.
fn ec_decoding_key_from_jwk(jwk_json: &[u8]) -> Option<jsonwebtoken::DecodingKey> {
    let jwk: serde_json::Value = serde_json::from_slice(jwk_json).ok()?;
    if jwk.get("kty")?.as_str()? != "EC" {
        return None;
    }
    if jwk.get("crv")?.as_str()? != "P-256" {
        return None;
    }
    let x = jwk.get("x")?.as_str()?;
    let y = jwk.get("y")?.as_str()?;
    jsonwebtoken::DecodingKey::from_ec_components(x, y).ok()
}

impl IdentityProvider for SpireProvider {
    /// See the module doc comment's first bullet: `requester_workload_name`
    /// and `credential` are accepted (for signature compatibility with
    /// `LocalIssuer`) but not used -- SPIRE has already authenticated
    /// *this* process via the Workload API connection itself, and
    /// `audience` is issued against that identity.
    ///
    /// ## Sync/async bridging
    ///
    /// This trait method is `&self`-sync (matching `LocalIssuer`), but the
    /// underlying `spiffe` Workload API client is `async`. Fix-round-1:
    /// this used to bridge via a dedicated, independent
    /// `tokio::runtime::Runtime` and `rt.block_on(...)`, on the theory that
    /// tokio only forbids `block_on`-ing *the same* runtime from one of its
    /// own worker threads, not a second, independent one. That theory is
    /// wrong: tokio tracks "is this thread currently driving async tasks"
    /// as a thread-local flag checked by *every* runtime's `block_on`
    /// (confirmed empirically -- a second, independent runtime's
    /// `block_on`, called from inside a `#[tokio::main]` multi-threaded
    /// runtime's worker thread with no `spawn_blocking` in between, panics
    /// with the exact same "Cannot start a runtime from within a runtime"
    /// either way). Since `zt-gateway`'s async `issue_svid` HTTP handler
    /// calls this method directly (no `spawn_blocking`), the old code
    /// panicked on every real request.
    ///
    /// The fix is [`tokio::task::block_in_place`] wrapping
    /// `Handle::current().block_on(...)`: `block_in_place` tells the
    /// multi-threaded runtime "this worker thread is about to block; move
    /// its other queued tasks to a different worker first," which is
    /// exactly what makes blocking here safe instead of starving the
    /// runtime. This requires the calling runtime to be the `multi_thread`
    /// flavor (true for `zt-gateway`'s `#[tokio::main]`, and for any
    /// `#[tokio::test(flavor = "multi_thread")]` test) -- `block_in_place`
    /// itself panics on a `current_thread` runtime, which is an explicit,
    /// documented tokio restriction, not something this method can work
    /// around.
    fn issue_jwt_svid(
        &self,
        _requester_workload_name: &str,
        audience: &str,
        _credential: &str,
    ) -> Result<IssuedToken, IdentityError> {
        let svid = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.client.fetch_jwt_svid(std::iter::once(audience), None))
        })
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
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
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

    // --- ES256 (Task 11 / N8) ---

    /// Generates a fresh P-256 TEST-ONLY EC keypair: a PKCS#8 PEM private
    /// key (what [`crate::jwt::JwtSigner::from_ec_pem_with_kid`] expects)
    /// and the matching `(x, y)` base64url JWK components -- the exact
    /// shape SPIRE's JWT bundle hands back per EC authority. Never do this
    /// in production code -- a real SPIRE deployment hands over
    /// already-formed JWKS, not raw EC scalars.
    fn generate_ec_keypair_with_jwk_xy() -> (Vec<u8>, String, String) {
        use p256::elliptic_curve::pkcs8::{EncodePrivateKey, LineEnding as EcLineEnding};
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let secret_key = p256::SecretKey::random(&mut rand::rngs::OsRng);
        let private_pem = secret_key.to_pkcs8_pem(EcLineEnding::LF).expect("encode ec private key");
        let encoded_point = secret_key.public_key().to_encoded_point(false);
        let x = general_purpose::URL_SAFE_NO_PAD.encode(encoded_point.x().expect("x coordinate"));
        let y = general_purpose::URL_SAFE_NO_PAD.encode(encoded_point.y().expect("y coordinate"));

        (private_pem.as_bytes().to_vec(), x, y)
    }

    #[test]
    fn ec_decoding_key_from_jwk_accepts_a_p256_jwk() {
        // Mirrors `rsa_decoding_key_from_jwk_accepts_an_rsa_jwk` above, but
        // for SPIRE's *default* JWT-SVID key type: EC/P-256.
        let (_private_pem, x, y) = generate_ec_keypair_with_jwk_xy();
        let jwk = serde_json::json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": "ec-key-1" }).to_string();

        assert!(ec_decoding_key_from_jwk(jwk.as_bytes()).is_some());
    }

    #[test]
    fn ec_decoding_key_from_jwk_rejects_a_non_p256_curve() {
        // `crv` values other than P-256 aren't supported by this crate's
        // ES256-only EC support -- same "silently skip, don't fail" policy
        // as any other unrecognized key type.
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-384",
            "x": "ngLYQnlfF6GsojUwqtcEE3WgTNG2RUlsGhK73RNEl5k",
            "y": "tKbiDSUSsQ3F1P7wteeHNXIcU-cx6CgSbroeQrQHTLM",
            "kid": "ec-key-1"
        })
        .to_string();

        assert!(ec_decoding_key_from_jwk(jwk.as_bytes()).is_none());
    }

    #[test]
    fn ec_decoding_key_from_jwk_rejects_an_rsa_jwk() {
        let mut rng = rand::rngs::OsRng;
        let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let n = general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e = general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
        let jwk = serde_json::json!({ "kty": "RSA", "n": n, "e": e, "kid": "key-1" }).to_string();

        assert!(ec_decoding_key_from_jwk(jwk.as_bytes()).is_none());
    }

    /// Test 1/3 required by the Task 11 / N8 brief: a mock ES256 (EC
    /// P-256) key, loaded exactly the way [`Self::new`] would load it from
    /// a live SPIRE JWT bundle (via [`JwtBundle::from_jwt_authorities`] +
    /// [`verifier_from_jwt_bundles`]), is recognized and produces a usable
    /// key -- proven here by successfully verifying a token signed by the
    /// matching private key.
    #[test]
    fn es256_keys_loaded_from_spire() {
        let (private_pem, x, y) = generate_ec_keypair_with_jwk_xy();
        let jwks = serde_json::json!({
            "keys": [
                { "kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": "spire-ec-key" }
            ]
        })
        .to_string();

        let trust_domain = spiffe::TrustDomain::new("example.org").unwrap();
        let bundle = spiffe::JwtBundle::from_jwt_authorities(trust_domain, jwks.as_bytes()).unwrap();
        let mut bundles = JwtBundleSet::default();
        bundles.add_bundle(bundle);

        let verifier = verifier_from_jwt_bundles(&bundles);

        let signer = crate::jwt::JwtSigner::from_ec_pem_with_kid(&private_pem, "spire-ec-key".to_string()).unwrap();
        let claims = crate::jwt::OboClaims {
            sub: "spiffe://example.org/ns/orders/sa/orders-svc".to_string(),
            aud: vec!["spiffe://example.org/ns/inventory/sa/inventory-svc".to_string()],
            user: None,
            act: None,
            exp: 9_999_999_999,
            iat: 0,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let token = signer.sign(&claims).unwrap();

        assert!(
            verifier.verify_signature(&token).is_ok(),
            "ES256 key loaded from a SPIRE-shaped JWT bundle should be recognized and usable"
        );
    }

    /// Test 2/3 required by the Task 11 / N8 brief: a token signed with
    /// ES256 verifies successfully against a [`SpireProvider`]-style
    /// verifier (i.e. one built by [`verifier_from_jwt_bundles`]).
    #[test]
    fn es256_token_verified() {
        let (private_pem, x, y) = generate_ec_keypair_with_jwk_xy();
        let jwks = serde_json::json!({
            "keys": [
                { "kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": "es256-kid" }
            ]
        })
        .to_string();

        let trust_domain = spiffe::TrustDomain::new("chakra.internal").unwrap();
        let bundle = spiffe::JwtBundle::from_jwt_authorities(trust_domain, jwks.as_bytes()).unwrap();
        let mut bundles = JwtBundleSet::default();
        bundles.add_bundle(bundle);
        let verifier = verifier_from_jwt_bundles(&bundles);

        let signer = crate::jwt::JwtSigner::from_ec_pem_with_kid(&private_pem, "es256-kid".to_string()).unwrap();
        let token = signer
            .sign(&crate::jwt::OboClaims {
                sub: "spiffe://chakra.internal/ns/orders/sa/orders-svc".to_string(),
                aud: vec!["spiffe://chakra.internal/ns/inventory/sa/inventory-svc".to_string()],
                user: None,
                act: None,
                exp: 9_999_999_999,
                iat: 0,
                nbf: None,
                jti: None,
                cnf: None,
                iss: None,
            })
            .unwrap();

        let decoded = verifier.verify_signature(&token).unwrap();
        assert_eq!(decoded.sub, "spiffe://chakra.internal/ns/orders/sa/orders-svc");
    }

    /// Test 3/3 required by the Task 11 / N8 brief: a JWT bundle
    /// containing *both* an RSA and an EC/P-256 authority loads both key
    /// types, and each verifies only tokens signed with its own matching
    /// key/algorithm.
    #[test]
    fn mixed_rs256_and_es256_keys() {
        let mut rng = rand::rngs::OsRng;
        let rsa_private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let rsa_public_key = rsa::RsaPublicKey::from(&rsa_private_key);
        let n = general_purpose::URL_SAFE_NO_PAD.encode(rsa_public_key.n().to_bytes_be());
        let e = general_purpose::URL_SAFE_NO_PAD.encode(rsa_public_key.e().to_bytes_be());
        let rsa_private_pem = rsa_private_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("encode rsa private key")
            .to_string();

        let (ec_private_pem, x, y) = generate_ec_keypair_with_jwk_xy();

        let jwks = serde_json::json!({
            "keys": [
                { "kty": "RSA", "n": n, "e": e, "kid": "rsa-kid" },
                { "kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": "ec-kid" }
            ]
        })
        .to_string();

        let trust_domain = spiffe::TrustDomain::new("mixed.test").unwrap();
        let bundle = spiffe::JwtBundle::from_jwt_authorities(trust_domain, jwks.as_bytes()).unwrap();
        let mut bundles = JwtBundleSet::default();
        bundles.add_bundle(bundle);
        let verifier = verifier_from_jwt_bundles(&bundles);

        let sample_claims = || crate::jwt::OboClaims {
            sub: "spiffe://mixed.test/workload".to_string(),
            aud: vec!["spiffe://mixed.test/aud".to_string()],
            user: None,
            act: None,
            exp: 9_999_999_999,
            iat: 0,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };

        let rsa_signer =
            crate::jwt::JwtSigner::from_rsa_pem_with_kid(rsa_private_pem.as_bytes(), "rsa-kid".to_string()).unwrap();
        let rsa_token = rsa_signer.sign(&sample_claims()).unwrap();
        assert!(verifier.verify_signature(&rsa_token).is_ok(), "RSA key from a mixed bundle should verify");

        let ec_signer = crate::jwt::JwtSigner::from_ec_pem_with_kid(&ec_private_pem, "ec-kid".to_string()).unwrap();
        let ec_token = ec_signer.sign(&sample_claims()).unwrap();
        assert!(verifier.verify_signature(&ec_token).is_ok(), "EC key from a mixed bundle should verify");
    }

    /// Fix-round-1 regression: `issue_jwt_svid` used to bridge onto a
    /// dedicated `tokio::runtime::Runtime` via `rt.block_on(...)`, which
    /// panics ("Cannot start a runtime from within a runtime") whenever
    /// called from a thread that's already driving async tasks for *any*
    /// runtime -- which is exactly what `zt-gateway`'s async `issue_svid`
    /// HTTP handler does, by calling this sync trait method directly (no
    /// `spawn_blocking` in between). This test reproduces that call shape:
    /// a `multi_thread`-flavored runtime (matching `zt-gateway`'s
    /// `#[tokio::main]`) calling `issue_jwt_svid` synchronously from
    /// inside an `async fn`.
    ///
    /// No live SPIRE agent is needed: `Endpoint::from_static(..).
    /// connect_lazy()` builds a channel that performs no I/O at
    /// construction time, so building the `SpireProvider` below can't
    /// itself fail or block. The actual connection attempt -- and its
    /// failure, since nothing listens on `127.0.0.1:1` -- happens inside
    /// the RPC itself, which is what lets this test prove the old panic
    /// happened *before* any RPC was attempted: if the sync/async bridge
    /// were still broken, this test would panic, not return a clean `Err`.
    #[tokio::test(flavor = "multi_thread")]
    async fn issue_jwt_svid_does_not_panic_when_called_synchronously_from_an_async_context() {
        let endpoint = spiffe::transport::Endpoint::Tcp {
            host: "127.0.0.1".parse().unwrap(),
            port: 1,
        };
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let client = WorkloadApiClient::new_with_channel(endpoint, channel);
        let provider = SpireProvider {
            client,
            verifier: JwtVerifier::from_jwks_entries(Vec::new()),
        };

        // Direct, synchronous call from inside this `async fn` -- no
        // `spawn_blocking` -- is the part that used to panic.
        let result = provider.issue_jwt_svid("workload", "aud", "cred");

        assert!(
            result.is_err(),
            "expected the RPC against a refused connection to fail cleanly (not panic, and not succeed)"
        );
    }
}
