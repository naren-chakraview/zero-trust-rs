//! RFC 8693 token exchange: a gateway holding an already-verified inbound
//! OBO token re-mints it for the next hop, appending *itself* to the
//! signed `act` delegation chain rather than forwarding the original
//! token to the backend.
//!
//! This is the mechanism that lets a chain of gateways build up a
//! verifiable record of every hop a request passed through
//! (`[originator, gw-a, gw-b, ...]`, see [`crate::jwt::OboClaims::delegation_chain`])
//! without any hop ever needing to trust the next one with its own
//! long-lived credentials — each hop only ever sees a token scoped to the
//! audience it's about to call.
//!
//! Deliberately *not* re-run here: full `obo::validate` access-control
//! checks (chain depth, allow-listing, user-principal shape). Per the
//! brief, token exchange only re-mints a token whose signature is valid
//! and whose `exp` hasn't passed — the destination backend (or the next
//! gateway) is responsible for running `obo::validate` against its own
//! registry when the re-minted token actually arrives.

use serde::{Deserialize, Serialize};

use crate::identity::IdentityProvider;
use crate::jwt::{ActClaim, JwtVerifier, OboClaims};
use crate::spiffe_id::SpiffeId;

/// Why [`exchange_token`] refused to re-mint a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenExchangeError {
    /// The inbound token's signature didn't verify — tampered, or signed
    /// by a key this verifier doesn't trust.
    InvalidToken,
    /// The inbound token's `exp` is at or before `now_secs`.
    ExpiredToken,
    /// `next_audience` is not a well-formed SPIFFE ID.
    InvalidAudience,
    /// Signing the re-minted claims failed.
    InternalError,
}

impl std::fmt::Display for TokenExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken => write!(f, "invalid or tampered inbound token"),
            Self::ExpiredToken => write!(f, "inbound token has expired"),
            Self::InvalidAudience => write!(f, "requested audience is not a valid SPIFFE ID"),
            Self::InternalError => write!(f, "internal error during token exchange"),
        }
    }
}

impl std::error::Error for TokenExchangeError {}

/// Exchanges `inbound_token` for a new token scoped to `next_audience`,
/// appending `gateway_id` to the signed delegation chain.
///
/// New token's claims:
/// - `sub`: unchanged — the end-to-end originator binding never moves.
/// - `aud`: replaced with `next_audience`.
/// - `user`: preserved verbatim from the inbound token.
/// - `act`: `{sub: gateway_id, act: <inbound act, if any>}` — this hop is
///   prepended to the chain as the *new* immediate actor, pushing whatever
///   was already there one level deeper.
/// - `cnf`: preserved verbatim (cert binding survives re-minting).
/// - `iat`/`exp`: fresh, `now_secs` .. `now_secs + ttl_secs`.
/// - `jti`: freshly generated, unique per call.
///
/// Returns the signed token and its TTL in seconds.
///
/// Fails with [`TokenExchangeError::InvalidToken`] if the inbound token's
/// signature doesn't verify against `verifier`, [`TokenExchangeError::ExpiredToken`]
/// if `now_secs >= inbound token's exp` (expiry is checked strictly, same
/// convention as `obo::validate`), or [`TokenExchangeError::InvalidAudience`]
/// if `next_audience` doesn't parse as a [`SpiffeId`]. The audience check
/// runs independently of inbound-token validity, so a well-formed but
/// expired token and a malformed audience each report their own distinct
/// reason.
pub fn exchange_token(
    inbound_token: &str,
    next_audience: &str,
    issuer: &dyn IdentityProvider,
    verifier: &JwtVerifier,
    gateway_id: &SpiffeId,
    ttl_secs: u64,
    now_secs: i64,
) -> Result<(String, u64), TokenExchangeError> {
    // Step 1: verify the inbound token's signature. Never trust a claim on
    // an unverified token, including its own `exp`.
    let inbound_claims = verifier
        .verify_signature(inbound_token)
        .map_err(|_| TokenExchangeError::InvalidToken)?;

    // Step 2: expiry, checked the same way `obo::validate` does (now >= exp
    // means expired, not just now > exp).
    if now_secs >= inbound_claims.exp {
        return Err(TokenExchangeError::ExpiredToken);
    }

    // Step 3: the next audience must itself be a well-formed SPIFFE ID —
    // checked regardless of inbound-token validity so each failure mode
    // reports its own distinct reason.
    let next_aud: SpiffeId = next_audience
        .parse()
        .map_err(|_| TokenExchangeError::InvalidAudience)?;

    // Step 4: re-mint. `sub`/`user`/`cnf` carry over unchanged; this
    // gateway is appended at the *end* of the existing `act` chain (not
    // wrapped around its outside) — `delegation_chain()` reads
    // `[sub, act.sub, act.act.sub, ...]`, and `sub` never changes here, so
    // the only way two successive exchanges produce the chronologically
    // correct order `[originator, hop_1, hop_2]` is for each new hop to
    // land at the deepest nesting level, consistent with this crate's
    // "each hop appending itself" delegation-chain semantics (see
    // `OboClaims`'s doc comment).
    let new_claims = OboClaims {
        sub: inbound_claims.sub.clone(),
        aud: vec![next_aud.to_string()],
        user: inbound_claims.user.clone(),
        act: append_hop(inbound_claims.act.clone(), gateway_id.to_string()),
        iat: now_secs,
        exp: now_secs + ttl_secs as i64,
        nbf: Some(now_secs),
        jti: Some(generate_jti()),
        cnf: inbound_claims.cnf.clone(),
    };

    let new_token = issuer
        .sign_claims(&new_claims)
        .map_err(|_| TokenExchangeError::InternalError)?;

    Ok((new_token, ttl_secs))
}

/// Appends `new_sub` as a new hop at the end (deepest nesting) of an `act`
/// chain, preserving every hop already recorded. With `act` `None` (no
/// prior delegation), this is simply the first hop.
fn append_hop(act: Option<Box<ActClaim>>, new_sub: String) -> Option<Box<ActClaim>> {
    match act {
        None => Some(Box::new(ActClaim { sub: new_sub, act: None })),
        Some(mut hop) => {
            hop.act = append_hop(hop.act, new_sub);
            Some(hop)
        }
    }
}

/// A short, random, hex-encoded JWT ID — unique per exchanged token, for
/// replay-cache purposes downstream. 16 bytes of OS randomness is
/// collision-resistant enough that uniqueness is never the gating factor
/// here; nothing downstream parses this value's shape, so plain hex avoids
/// pulling in a base64 dependency just for this.
fn generate_jti() -> String {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn default_subject_token_type() -> String {
    "urn:ietf:params:oauth:token-type:jwt".to_string()
}

/// `POST /v1/token-exchange` request body, per RFC 8693 §2.1's token
/// exchange request parameters (only the subset this gateway acts on).
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    /// The inbound OBO token to exchange.
    pub subject_token: String,
    /// Always `urn:ietf:params:oauth:token-type:jwt` for this gateway, but
    /// accepted (and defaulted) rather than rejected if the caller omits
    /// it — this endpoint only ever understands JWTs.
    #[serde(default = "default_subject_token_type")]
    pub subject_token_type: String,
    /// The SPIFFE ID of the next hop this token should be scoped to.
    pub audience: String,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// `POST /v1/token-exchange` response body, per RFC 8693 §2.2.1.
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::LocalIssuer;
    use crate::registry::Registry;

    fn test_registry() -> Registry {
        Registry::from_yaml_str(
            r#"
trust_domain: chakra.internal
workloads:
  - name: placeholder
    spiffe_id: spiffe://chakra.internal/ns/placeholder/sa/placeholder
    max_obo_chain_depth: 3
    allowed_callers: []
"#,
        )
        .unwrap()
    }

    fn gw(id: &str) -> SpiffeId {
        id.parse().unwrap()
    }

    #[test]
    fn test_token_exchange_single_hop() {
        let reg = test_registry();
        let issuer = LocalIssuer::generate(reg, 300).unwrap();

        // Step 1: Issuer creates initial token (originator -> backend A).
        let initial_claims = OboClaims {
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/backend-a/sa/backend-a".into()],
            user: Some("spiffe://chakra.internal/ns/alice/sa/alice".into()),
            act: None,
            iat: 1000,
            exp: 1300,
            nbf: None,
            jti: Some("jti-1".into()),
            cnf: None,
        };
        let initial_token = issuer.sign_claims(&initial_claims).unwrap();

        // Step 2: Gateway A exchanges the token for the next hop (backend B).
        let (new_token, ttl) = exchange_token(
            &initial_token,
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &issuer,
            issuer.verifier(),
            &gw("spiffe://chakra.internal/ns/gateway-a/sa/gateway-a"),
            300,
            1000,
        )
        .unwrap();

        // Step 3: Verify the new token's structure.
        let new_claims = issuer.verifier().verify_signature(&new_token).unwrap();
        assert_eq!(new_claims.sub, "spiffe://chakra.internal/ns/originator/sa/originator"); // preserved
        assert_eq!(new_claims.aud, vec!["spiffe://chakra.internal/ns/backend-b/sa/backend-b".to_string()]); // new audience
        assert_eq!(
            new_claims.user,
            Some("spiffe://chakra.internal/ns/alice/sa/alice".to_string())
        ); // preserved
        assert_eq!(new_claims.delegation_depth(), 1); // gateway-a added
        let chain = new_claims.delegation_chain();
        assert_eq!(chain[0], "spiffe://chakra.internal/ns/originator/sa/originator");
        assert_eq!(chain[1], "spiffe://chakra.internal/ns/gateway-a/sa/gateway-a");
        assert_eq!(ttl, 300);
        // Fresh jti, not the inbound one.
        assert_ne!(new_claims.jti, Some("jti-1".to_string()));
        assert!(new_claims.jti.is_some());
        // Fresh iat/exp at the TTL passed in.
        assert_eq!(new_claims.iat, 1000);
        assert_eq!(new_claims.exp, 1300);
    }

    /// Builds a JWKS-style document (see [`LocalIssuer::with_jwks`]) with a
    /// fresh 2048-bit RSA keypair per `kid` — the shared key set every
    /// gateway in a trust domain loads side-by-side in production, each
    /// signing with its own `active_kid` but able to verify every other
    /// gateway's tokens too.
    fn generate_jwks_json(kids: &[&str]) -> String {
        use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
        use rsa::RsaPrivateKey;

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
    fn f3_three_hop_delegation_chain() {
        // Three independent gateways, each fronting its own hop, share one
        // JWKS document — the real deployment shape for cross-gateway
        // verification (Task 4's `LocalIssuer::with_jwks`). Each signs with
        // its own key but all three verifiers trust every key in the set,
        // so gateway B can verify a token gateway A signed, and so on.
        let jwks_json = generate_jwks_json(&["gw-a-key", "gw-b-key", "gw-c-key"]);
        let reg = test_registry();
        let gw_a = LocalIssuer::with_jwks(reg.clone(), &jwks_json, "gw-a-key".to_string(), 300).unwrap();
        let gw_b = LocalIssuer::with_jwks(reg.clone(), &jwks_json, "gw-b-key".to_string(), 300).unwrap();
        let gw_c = LocalIssuer::with_jwks(reg, &jwks_json, "gw-c-key".to_string(), 300).unwrap();

        let now = 1000i64;

        // Step 1: user originates a call to gateway A.
        let initial_claims = OboClaims {
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/gateway-a/sa/gateway-a".into()],
            user: Some("spiffe://chakra.internal/ns/alice/sa/alice".into()),
            act: None,
            iat: now,
            exp: now + 300,
            nbf: None,
            jti: Some("jti-0".into()),
            cnf: None,
        };
        let token_for_a = gw_a.sign_claims(&initial_claims).unwrap();

        // Step 2: gateway A exchanges for the hop via gateway B.
        let (token_for_b, _) = exchange_token(
            &token_for_a,
            "spiffe://chakra.internal/ns/gateway-b/sa/gateway-b",
            &gw_a,
            gw_a.verifier(),
            &gw("spiffe://chakra.internal/ns/gateway-a/sa/gateway-a"),
            300,
            now,
        )
        .unwrap();

        // Step 3: gateway B exchanges for the hop to gateway C — the final,
        // terminal gateway in this path, which receives this token and
        // validates it directly (via `obo::validate`); it does not forward
        // any further, so it never calls `exchange_token` on its own
        // behalf. (If it *did* go on to call some other backend, that
        // further exchange would append gateway-c too — the chain only
        // ever records hops that actually exchanged the token onward.)
        let (final_token, _) = exchange_token(
            &token_for_b,
            "spiffe://chakra.internal/ns/gateway-c/sa/gateway-c",
            &gw_b,
            gw_b.verifier(),
            &gw("spiffe://chakra.internal/ns/gateway-b/sa/gateway-b"),
            300,
            now,
        )
        .unwrap();

        // Step 4: gateway C independently verifies the token that finally
        // reaches it (shared JWKS, so it needs no special-casing to trust a
        // signature produced by gateway B) and confirms the signed chain
        // is exactly [originator, gw-a, gw-b].
        let final_claims = gw_c.verifier().verify_signature(&final_token).unwrap();
        assert_eq!(final_claims.sub, "spiffe://chakra.internal/ns/originator/sa/originator");
        assert_eq!(final_claims.aud, vec!["spiffe://chakra.internal/ns/gateway-c/sa/gateway-c".to_string()]);
        assert_eq!(final_claims.delegation_depth(), 2);
        let chain = final_claims.delegation_chain();
        assert_eq!(chain[0], "spiffe://chakra.internal/ns/originator/sa/originator");
        assert_eq!(chain[1], "spiffe://chakra.internal/ns/gateway-a/sa/gateway-a");
        assert_eq!(chain[2], "spiffe://chakra.internal/ns/gateway-b/sa/gateway-b");
        // The user principal survives both hops.
        assert_eq!(
            final_claims.user,
            Some("spiffe://chakra.internal/ns/alice/sa/alice".to_string())
        );
    }

    #[test]
    fn test_token_exchange_preserves_cnf() {
        use crate::jwt::CertBinding;

        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        let claims = OboClaims {
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/backend/sa/backend".into()],
            user: None,
            act: None,
            iat: 1000,
            exp: 1300,
            nbf: None,
            jti: None,
            cnf: Some(CertBinding {
                x5t_s256: "thumbprint".to_string(),
            }),
        };
        let token = issuer.sign_claims(&claims).unwrap();

        let (new_token, _) = exchange_token(
            &token,
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &issuer,
            issuer.verifier(),
            &gw("spiffe://chakra.internal/ns/gateway-a/sa/gateway-a"),
            300,
            1000,
        )
        .unwrap();

        let new_claims = issuer.verifier().verify_signature(&new_token).unwrap();
        assert_eq!(
            new_claims.cnf,
            Some(CertBinding {
                x5t_s256: "thumbprint".to_string()
            })
        );
    }

    #[test]
    fn test_token_exchange_rejects_expired_token() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();

        let expired_claims = OboClaims {
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/backend/sa/backend".into()],
            user: None,
            act: None,
            iat: 500,
            exp: 999, // expired at now=1000
            nbf: None,
            jti: None,
            cnf: None,
        };
        let expired_token = issuer.sign_claims(&expired_claims).unwrap();

        let result = exchange_token(
            &expired_token,
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &issuer,
            issuer.verifier(),
            &gw("spiffe://chakra.internal/ns/gateway-a/sa/gateway-a"),
            300,
            1000,
        );

        assert_eq!(result.unwrap_err(), TokenExchangeError::ExpiredToken);
    }

    #[test]
    fn test_token_exchange_rejects_invalid_audience() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();

        let claims = OboClaims {
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/backend/sa/backend".into()],
            user: None,
            act: None,
            iat: 1000,
            exp: 1300,
            nbf: None,
            jti: None,
            cnf: None,
        };
        let token = issuer.sign_claims(&claims).unwrap();

        let result = exchange_token(
            &token,
            "not-a-spiffe-id", // invalid!
            &issuer,
            issuer.verifier(),
            &gw("spiffe://chakra.internal/ns/gateway-a/sa/gateway-a"),
            300,
            1000,
        );

        assert_eq!(result.unwrap_err(), TokenExchangeError::InvalidAudience);
    }

    #[test]
    fn test_token_exchange_rejects_tampered_token() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        let other_issuer = LocalIssuer::generate(test_registry(), 300).unwrap();

        let claims = OboClaims {
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/backend/sa/backend".into()],
            user: None,
            act: None,
            iat: 1000,
            exp: 1300,
            nbf: None,
            jti: None,
            cnf: None,
        };
        // Signed by a *different* issuer's key than the one we try to
        // verify with below — same shape as a tampered/forged token.
        let token = other_issuer.sign_claims(&claims).unwrap();

        let result = exchange_token(
            &token,
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &issuer,
            issuer.verifier(), // trusts only `issuer`'s key, not `other_issuer`'s
            &gw("spiffe://chakra.internal/ns/gateway-a/sa/gateway-a"),
            300,
            1000,
        );

        assert_eq!(result.unwrap_err(), TokenExchangeError::InvalidToken);
    }

    #[test]
    fn test_token_exchange_rejects_malformed_token() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();

        let result = exchange_token(
            "not.a.jwt",
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &issuer,
            issuer.verifier(),
            &gw("spiffe://chakra.internal/ns/gateway-a/sa/gateway-a"),
            300,
            1000,
        );

        assert_eq!(result.unwrap_err(), TokenExchangeError::InvalidToken);
    }

    #[test]
    fn exchanged_jti_is_unique_per_call() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        let claims = OboClaims {
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/backend/sa/backend".into()],
            user: None,
            act: None,
            iat: 1000,
            exp: 1300,
            nbf: None,
            jti: None,
            cnf: None,
        };
        let token = issuer.sign_claims(&claims).unwrap();

        let (token_1, _) = exchange_token(
            &token,
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &issuer,
            issuer.verifier(),
            &gw("spiffe://chakra.internal/ns/gateway-a/sa/gateway-a"),
            300,
            1000,
        )
        .unwrap();
        let (token_2, _) = exchange_token(
            &token,
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &issuer,
            issuer.verifier(),
            &gw("spiffe://chakra.internal/ns/gateway-a/sa/gateway-a"),
            300,
            1000,
        )
        .unwrap();

        let jti_1 = issuer.verifier().verify_signature(&token_1).unwrap().jti;
        let jti_2 = issuer.verifier().verify_signature(&token_2).unwrap().jti;
        assert_ne!(jti_1, jti_2);
    }

    #[test]
    fn token_exchange_request_defaults_subject_token_type() {
        let json = r#"{"subject_token":"abc","audience":"spiffe://chakra.internal/ns/backend/sa/backend"}"#;
        let req: TokenExchangeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.subject_token_type, "urn:ietf:params:oauth:token-type:jwt");
        assert!(req.resource.is_none());
        assert!(req.scope.is_none());
    }
}
