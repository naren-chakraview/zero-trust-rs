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
//! checks (allow-listing, user-principal shape). The destination backend
//! (or the next gateway) is responsible for running `obo::validate`
//! against its own registry when the re-minted token actually arrives.
//!
//! Task 6 (N3 fix, review 0002): what token exchange *does* check, before
//! ever re-minting anything, is that the inbound token is actually
//! entitled to be exchanged *here*: its signature must verify, its `exp`
//! must not have passed, its `nbf` (if any) must not be in the future, its
//! `aud` must name this gateway's own protected workload (not some other
//! gateway's), and its already-signed delegation chain must not already
//! be at or past this gateway's configured `max_chain_depth`. Without the
//! `aud`/depth checks, a token minted for gateway A could be replayed
//! through gateway B's exchange endpoint and rescoped to an audience
//! gateway A never intended, or a chain could be bounced through more hops
//! than the destination's registry entry allows before this gateway even
//! appends itself as the next one.

use serde::{Deserialize, Serialize};

use crate::identity::IdentityProvider;
use crate::jwt::{ActClaim, CertBinding, JwtVerifier, OboClaims};
use crate::obo::{cert_binding_matches, current_actor};
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
    /// N2 fix (review 0002): the inbound token carries a signed
    /// `cnf.x5t#S256` claim, but it doesn't match the thumbprint of the
    /// certificate the exchanging caller actually presented (or no
    /// certificate was presented at all) — only ever produced by
    /// [`exchange_token_with_cert_binding`]; [`exchange_token`] never
    /// checks cert binding.
    CertificateBindingMismatch,
    /// Task 6 fix (N3, review 0002): the inbound token's `nbf` is in the
    /// future — reaffirming, at exchange time, the same not-yet-valid
    /// check `obo::validate`/`validate_with_clock_skew` already perform at
    /// request-validation time. No clock-skew allowance here (exchange
    /// happens hop-to-hop, immediately after the previous mint, so skew
    /// tolerance isn't needed the way it is for a token that may have
    /// travelled over the wire).
    NotYetValid,
    /// Task 6 fix (N3, review 0002): the inbound token's `aud` does not
    /// contain this gateway's protected workload identity
    /// (`destination_workload`) — this token was never addressed to this
    /// gateway, so it has no business being exchanged here. Without this
    /// check, a token minted for one gateway could be replayed through an
    /// unrelated gateway's `/v1/token-exchange` endpoint and rescoped to
    /// an audience its original issuer never intended.
    AudienceMismatch,
    /// Task 6 fix (N3, review 0002): the inbound token's signed delegation
    /// chain (`OboClaims::delegation_chain`) is already as long as, or
    /// longer than, `max_chain_depth` — exchanging it onward would let the
    /// chain grow past the limit this gateway (or its destination's
    /// registry entry) is configured to enforce.
    ChainDepthExceeded,
    /// Signing the re-minted claims failed.
    InternalError,
}

impl std::fmt::Display for TokenExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidToken => write!(f, "invalid or tampered inbound token"),
            Self::ExpiredToken => write!(f, "inbound token has expired"),
            Self::InvalidAudience => write!(f, "requested audience is not a valid SPIFFE ID"),
            Self::CertificateBindingMismatch => {
                write!(f, "inbound token's certificate binding does not match the caller's presented certificate")
            }
            Self::NotYetValid => write!(f, "inbound token is not yet valid (nbf is in the future)"),
            Self::AudienceMismatch => {
                write!(f, "inbound token's audience does not name this gateway's protected workload")
            }
            Self::ChainDepthExceeded => write!(f, "inbound token's delegation chain already exceeds the maximum allowed depth"),
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
/// - `act`: `{sub: gateway_id, act: <inbound act, if any>}` — per RFC 8693
///   §4.1, `act` identifies the party to whom authority has been
///   *currently* delegated, so this hop becomes the new outermost `act`
///   (the current actor), with whatever was already there nested one
///   level deeper as the prior actor.
/// - `cnf`: preserved verbatim (cert binding survives re-minting).
/// - `iat`/`exp`: fresh `iat`; `exp` is `now_secs + ttl_secs`, capped at the
///   inbound token's `exp` (R3, review 0003).
/// - `jti`: freshly generated, unique per call.
///
/// Returns the signed token and its TTL in seconds.
///
/// Fails with [`TokenExchangeError::InvalidToken`] if the inbound token's
/// signature doesn't verify against `verifier`, [`TokenExchangeError::ExpiredToken`]
/// if `now_secs >= inbound token's exp` (expiry is checked strictly, same
/// convention as `obo::validate`), [`TokenExchangeError::NotYetValid`] if
/// the inbound token's `nbf` is in the future, or
/// [`TokenExchangeError::InvalidAudience`] if `next_audience` doesn't parse
/// as a [`SpiffeId`]. The audience check runs independently of
/// inbound-token validity, so a well-formed but expired token and a
/// malformed audience each report their own distinct reason.
///
/// Task 6 (N3 fix, review 0002): also fails with
/// [`TokenExchangeError::AudienceMismatch`] if the inbound token's `aud`
/// does not contain `destination_workload` (this gateway's own protected
/// workload identity — the inbound token must have been addressed to
/// *this* gateway, not some other one), or
/// [`TokenExchangeError::ChainDepthExceeded`] if the inbound token's
/// already-signed delegation chain (`OboClaims::delegation_chain`) is
/// already as long as, or longer than, `max_chain_depth`.
pub fn exchange_token(
    inbound_token: &str,
    next_audience: &str,
    destination_workload: &SpiffeId,
    max_chain_depth: u32,
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

    // Step 2b (N3 fix): `nbf`, reaffirmed here the same way `obo::validate`
    // checks it at request-validation time. No clock-skew allowance -- see
    // `TokenExchangeError::NotYetValid`'s doc comment for why.
    if let Some(nbf) = inbound_claims.nbf {
        if nbf > now_secs {
            return Err(TokenExchangeError::NotYetValid);
        }
    }

    // Step 3: the next audience must itself be a well-formed SPIFFE ID —
    // checked regardless of inbound-token validity so each failure mode
    // reports its own distinct reason.
    let next_aud: SpiffeId = next_audience
        .parse()
        .map_err(|_| TokenExchangeError::InvalidAudience)?;

    // Step 3b (N3 fix): the inbound token must actually be addressed to
    // *this* gateway's protected workload -- otherwise a token minted for
    // one gateway could be exchanged through an unrelated one and
    // rescoped to an audience its issuer never intended.
    let destination_str = destination_workload.to_string();
    if !inbound_claims.aud.iter().any(|aud| aud == &destination_str) {
        return Err(TokenExchangeError::AudienceMismatch);
    }

    // Step 3c (N3 fix): the signed chain so far must not already be at (or
    // past) this gateway's configured maximum -- `delegation_chain()`'s
    // length already counts every hop recorded up to and including the
    // immediate caller, so `> max_chain_depth` (not `>=`) is the correct
    // comparison: a chain *at* the limit may still take its next hop, same
    // convention `obo::validate`'s own chain-depth check uses.
    // R5 fix (review 0003): the minted token's chain is the inbound chain plus this
    // hop, so refuse once the inbound chain already fills the limit.
    if inbound_claims.delegation_chain().len() + 1 > max_chain_depth as usize {
        return Err(TokenExchangeError::ChainDepthExceeded);
    }

    // Step 4: re-mint. `sub`/`user`/`cnf` carry over unchanged; per RFC
    // 8693 §4.1, `act` names the party currently exercising delegated
    // authority, so this gateway is prepended as the new *outermost* `act`
    // — pushing whatever hop was previously outermost one level deeper, as
    // the prior actor. `delegation_chain()` reads `[sub, act.sub,
    // act.act.sub, ...]` but internally un-reverses this nesting so its
    // *output* order stays chronological (`[originator, hop_1, hop_2]`)
    // even though the signed `act` nesting itself is newest-first.
    // R6 fix (review 0003): `iss` names the gateway that signs the new token,
    // not the originator. The IdP that vouched for `user` is carried in `user_iss`.
    let gateway_iss = issuer.issuer_claim().ok_or(TokenExchangeError::InternalError)?;
    let new_claims = OboClaims { user_attributes: inbound_claims.user_attributes.clone(), roles: inbound_claims.roles.clone(),
        user_iss: inbound_claims.user_iss.clone(),
        sub: inbound_claims.sub.clone(),
        aud: vec![next_aud.to_string()],
        user: inbound_claims.user.clone(),
        act: next_act(&inbound_claims, gateway_id),
        iat: now_secs,
        // R3 fix (review 0003): never outlive the token this was derived from.
        exp: (now_secs + ttl_secs as i64).min(inbound_claims.exp),
        nbf: Some(now_secs),
        jti: Some(generate_jti()),
        cnf: inbound_claims.cnf.clone(),
        iss: Some(gateway_iss),
    };

    let new_token = issuer
        .sign_claims(&new_claims)
        .map_err(|_| TokenExchangeError::InternalError)?;

    Ok((new_token, ttl_secs))
}

/// Like [`exchange_token`], but additionally implements the N2 fix (review
/// 0002): the new token is bound to the **exchanging hop's own
/// certificate** (`caller_cert_thumbprint` — the thumbprint of whatever TLS
/// client certificate the caller presented to the admin listener, if any)
/// instead of blindly copying forward whatever `cnf` the inbound token
/// happened to carry.
///
/// Before re-minting, this also validates that the inbound token's `cnf`
/// claim (if present) matches `caller_cert_thumbprint` — using the same
/// [`cert_binding_matches`] logic [`crate::obo::validate_with_cert_binding`]
/// uses at request-validation time — and fails with
/// [`TokenExchangeError::CertificateBindingMismatch`] if it doesn't. This
/// closes the N2 hole: without it, a bound token presented by anyone other
/// than the party it's bound to could still be exchanged onward.
///
/// The new token's `cnf`:
/// - `caller_cert_thumbprint: Some(thumbprint)` — the new token is bound to
///   `CertBinding { x5t_s256: thumbprint.to_string() }`, **replacing**
///   whatever `cnf` the inbound token carried (including `None`). Every hop
///   re-binds to its own cert; binding never survives an exchange
///   unchanged.
/// - `caller_cert_thumbprint: None` — no certificate was presented at
///   exchange time (e.g. mTLS not enabled on the admin listener), so the
///   new token is left unbound (`cnf: None`), same as [`exchange_token`].
///   This only succeeds when the inbound token itself had no `cnf` to
///   check — a bound inbound token with no presented cert is a mismatch,
///   per [`cert_binding_matches`]'s fail-closed semantics.
///
/// All other fields (`sub`, `aud`, `user`, `act`, `iat`/`exp`, `jti`,
/// `iss`) behave exactly as documented on [`exchange_token`].
///
/// Task 6 (N3 fix, review 0002): also validates `destination_workload` and
/// `max_chain_depth` exactly as [`exchange_token`] does — see that
/// function's doc comment for [`TokenExchangeError::NotYetValid`],
/// [`TokenExchangeError::AudienceMismatch`], and
/// [`TokenExchangeError::ChainDepthExceeded`].
pub fn exchange_token_with_cert_binding(
    inbound_token: &str,
    next_audience: &str,
    destination_workload: &SpiffeId,
    max_chain_depth: u32,
    issuer: &dyn IdentityProvider,
    verifier: &JwtVerifier,
    gateway_id: &SpiffeId,
    ttl_secs: u64,
    now_secs: i64,
    caller_cert_thumbprint: Option<&str>,
) -> Result<(String, u64), TokenExchangeError> {
    // Step 1: verify the inbound token's signature.
    let inbound_claims = verifier
        .verify_signature(inbound_token)
        .map_err(|_| TokenExchangeError::InvalidToken)?;

    // Step 2: expiry, same convention as `exchange_token`/`obo::validate`.
    if now_secs >= inbound_claims.exp {
        return Err(TokenExchangeError::ExpiredToken);
    }

    // Step 2b (N3 fix): `nbf`, reaffirmed the same way `exchange_token`
    // does -- see that function's doc comment on
    // `TokenExchangeError::NotYetValid`.
    if let Some(nbf) = inbound_claims.nbf {
        if nbf > now_secs {
            return Err(TokenExchangeError::NotYetValid);
        }
    }

    // Step 3: the next audience must be a well-formed SPIFFE ID.
    let next_aud: SpiffeId = next_audience
        .parse()
        .map_err(|_| TokenExchangeError::InvalidAudience)?;

    // Step 3b (N3 fix): the inbound token must be addressed to this
    // gateway's protected workload -- see `exchange_token`'s doc comment
    // on `TokenExchangeError::AudienceMismatch`.
    let destination_str = destination_workload.to_string();
    if !inbound_claims.aud.iter().any(|aud| aud == &destination_str) {
        return Err(TokenExchangeError::AudienceMismatch);
    }

    // Step 3c (N3 fix): the signed chain so far must not already be at (or
    // past) this gateway's configured maximum -- see `exchange_token`'s
    // doc comment on `TokenExchangeError::ChainDepthExceeded`.
    // R5 fix (review 0003): the minted token's chain is the inbound chain plus this
    // hop, so refuse once the inbound chain already fills the limit.
    if inbound_claims.delegation_chain().len() + 1 > max_chain_depth as usize {
        return Err(TokenExchangeError::ChainDepthExceeded);
    }

    // Step 4 (N2 fix): the inbound token's `cnf`, if any, must match the
    // cert the exchanging caller actually presented. A missing `cnf` on
    // the inbound token always passes this check (nothing to validate);
    // a present `cnf` with no matching presented cert fails closed.
    if !cert_binding_matches(inbound_claims.cnf.as_ref(), caller_cert_thumbprint) {
        return Err(TokenExchangeError::CertificateBindingMismatch);
    }

    // Step 5: re-mint, re-binding `cnf` to the exchanging hop's own
    // certificate (not the inbound token's) — the core of the N2 fix.
    let new_cnf = caller_cert_thumbprint.map(|thumbprint| CertBinding {
        x5t_s256: thumbprint.to_string(),
    });

    // R6 fix (review 0003): `iss` names the gateway that signs the new token,
    // not the originator. The IdP that vouched for `user` is carried in `user_iss`.
    let gateway_iss = issuer.issuer_claim().ok_or(TokenExchangeError::InternalError)?;
    let new_claims = OboClaims { user_attributes: inbound_claims.user_attributes.clone(), roles: inbound_claims.roles.clone(),
        user_iss: inbound_claims.user_iss.clone(),
        sub: inbound_claims.sub.clone(),
        aud: vec![next_aud.to_string()],
        user: inbound_claims.user.clone(),
        act: next_act(&inbound_claims, gateway_id),
        iat: now_secs,
        // R3 fix (review 0003): never outlive the token this was derived from.
        exp: (now_secs + ttl_secs as i64).min(inbound_claims.exp),
        nbf: Some(now_secs),
        jti: Some(generate_jti()),
        cnf: new_cnf,
        iss: Some(gateway_iss),
    };

    let new_token = issuer
        .sign_claims(&new_claims)
        .map_err(|_| TokenExchangeError::InternalError)?;

    Ok((new_token, ttl_secs))
}

/// Prepends `new_sub` as the new outermost hop of an `act` chain, nesting
/// whatever was already there one level deeper as the prior actor. This is
/// RFC 8693 §4.1's convention: the outermost `act` is always the *current*
/// actor, so a fresh hop replaces that position rather than burying itself
/// at the bottom of the chain. With `act` `None` (no prior delegation),
/// this is simply the first hop.
/// The `act` for a re-minted token. Normally this gateway is prepended. But when
/// the inbound token's current actor is already this gateway (an edge-minted
/// token has `sub` = the gateway that minted it), the hop is already recorded,
/// so the chain is left alone. This keeps a chain from listing the same hop
/// twice (review 0003, design 0002).
fn next_act(inbound: &OboClaims, gateway_id: &SpiffeId) -> Option<Box<ActClaim>> {
    if current_actor(inbound) == *gateway_id {
        return inbound.act.clone();
    }
    append_hop(inbound.act.clone(), gateway_id.to_string())
}

fn append_hop(act: Option<Box<ActClaim>>, new_sub: String) -> Option<Box<ActClaim>> {
    Some(Box::new(ActClaim { sub: new_sub, act }))
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

/// Rebinds an inbound token to this workload's own certificate, the proxy-side
/// step of design 0002 (option A). The result differs from exchange in four ways:
///
/// - `act` and `sub` are unchanged, so no hop is added. Delegation to the next
///   hop still happens through [`exchange_token_with_cert_binding`], which the
///   backend calls.
/// - `aud` is `workload` (this gateway's own identity), not a next hop.
/// - `cnf` is the thumbprint of the workload's delegation certificate, which the
///   co-located backend holds and presents when it exchanges the token.
/// - `exp` is the earlier of the inbound `exp` and `now + ttl_secs`, so the
///   rebound token never outlives its source.
///
/// The inbound token must verify, be unexpired, and be addressed to `workload`.
/// If it carries a `cnf`, that must match `peer_cert_thumbprint`, the certificate
/// the proxy verified on this connection. A mismatch fails with
/// [`TokenExchangeError::CertificateBindingMismatch`] before anything is signed.
#[allow(clippy::too_many_arguments)]
pub fn rebind_token(
    inbound_token: &str,
    workload: &SpiffeId,
    issuer: &dyn IdentityProvider,
    verifier: &JwtVerifier,
    delegation_thumbprint: &str,
    peer_cert_thumbprint: Option<&str>,
    ttl_secs: u64,
    now_secs: i64,
) -> Result<(String, u64), TokenExchangeError> {
    let inbound = verifier
        .verify_signature(inbound_token)
        .map_err(|_| TokenExchangeError::InvalidToken)?;
    if now_secs >= inbound.exp {
        return Err(TokenExchangeError::ExpiredToken);
    }
    if inbound.nbf.is_some_and(|nbf| nbf > now_secs) {
        return Err(TokenExchangeError::NotYetValid);
    }
    let workload_str = workload.to_string();
    if !inbound.aud.iter().any(|aud| aud == &workload_str) {
        return Err(TokenExchangeError::AudienceMismatch);
    }
    if !cert_binding_matches(inbound.cnf.as_ref(), peer_cert_thumbprint) {
        return Err(TokenExchangeError::CertificateBindingMismatch);
    }
    let gateway_iss = issuer.issuer_claim().ok_or(TokenExchangeError::InternalError)?;

    let exp = (now_secs + ttl_secs as i64).min(inbound.exp);
    let claims = OboClaims { user_attributes: inbound.user_attributes.clone(), roles: inbound.roles.clone(),
        user_iss: inbound.user_iss.clone(),
        sub: inbound.sub.clone(),
        aud: vec![workload_str],
        user: inbound.user.clone(),
        act: inbound.act.clone(),
        iat: now_secs,
        exp,
        nbf: Some(now_secs),
        jti: Some(generate_jti()),
        cnf: Some(CertBinding {
            x5t_s256: delegation_thumbprint.to_string(),
        }),
        iss: Some(gateway_iss),
    };
    let token = issuer.sign_claims(&claims).map_err(|_| TokenExchangeError::InternalError)?;
    Ok((token, (exp - now_secs).max(0) as u64))

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
        let initial_claims = OboClaims { user_attributes: None, roles: None,
            user_iss: None,
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/backend-a/sa/backend-a".into()],
            user: Some("spiffe://chakra.internal/ns/alice/sa/alice".into()),
            act: None,
            iat: 1000,
            exp: 1300,
            nbf: None,
            jti: Some("jti-1".into()),
            cnf: None,
            iss: None,
        };
        let initial_token = issuer.sign_claims(&initial_claims).unwrap();

        // Step 2: Gateway A exchanges the token for the next hop (backend B).
        let (new_token, ttl) = exchange_token(
            &initial_token,
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &gw("spiffe://chakra.internal/ns/backend-a/sa/backend-a"),
            5,
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
        let initial_claims = OboClaims { user_attributes: None, roles: None,
            user_iss: None,
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/gateway-a/sa/gateway-a".into()],
            user: Some("spiffe://chakra.internal/ns/alice/sa/alice".into()),
            act: None,
            iat: now,
            exp: now + 300,
            nbf: None,
            jti: Some("jti-0".into()),
            cnf: None,
            iss: None,
        };
        let token_for_a = gw_a.sign_claims(&initial_claims).unwrap();

        // Step 2: gateway A exchanges for the hop via gateway B.
        let (token_for_b, _) = exchange_token(
            &token_for_a,
            "spiffe://chakra.internal/ns/gateway-b/sa/gateway-b",
            &gw("spiffe://chakra.internal/ns/gateway-a/sa/gateway-a"),
            5,
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
            &gw("spiffe://chakra.internal/ns/gateway-b/sa/gateway-b"),
            5,
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
        let claims = OboClaims { user_attributes: None, roles: None,
            user_iss: None,
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
            iss: None,
        };
        let token = issuer.sign_claims(&claims).unwrap();

        let (new_token, _) = exchange_token(
            &token,
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &gw("spiffe://chakra.internal/ns/backend/sa/backend"),
            5,
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

        let expired_claims = OboClaims { user_attributes: None, roles: None,
            user_iss: None,
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/backend/sa/backend".into()],
            user: None,
            act: None,
            iat: 500,
            exp: 999, // expired at now=1000
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let expired_token = issuer.sign_claims(&expired_claims).unwrap();

        let result = exchange_token(
            &expired_token,
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &gw("spiffe://chakra.internal/ns/backend/sa/backend"),
            5,
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

        let claims = OboClaims { user_attributes: None, roles: None,
            user_iss: None,
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/backend/sa/backend".into()],
            user: None,
            act: None,
            iat: 1000,
            exp: 1300,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let token = issuer.sign_claims(&claims).unwrap();

        let result = exchange_token(
            &token,
            "not-a-spiffe-id", // invalid!
            &gw("spiffe://chakra.internal/ns/backend/sa/backend"),
            5,
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

        let claims = OboClaims { user_attributes: None, roles: None,
            user_iss: None,
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/backend/sa/backend".into()],
            user: None,
            act: None,
            iat: 1000,
            exp: 1300,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        // Signed by a *different* issuer's key than the one we try to
        // verify with below — same shape as a tampered/forged token.
        let token = other_issuer.sign_claims(&claims).unwrap();

        let result = exchange_token(
            &token,
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &gw("spiffe://chakra.internal/ns/backend/sa/backend"),
            5,
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
            &gw("spiffe://chakra.internal/ns/backend/sa/backend"),
            5,
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
        let claims = OboClaims { user_attributes: None, roles: None,
            user_iss: None,
            sub: "spiffe://chakra.internal/ns/originator/sa/originator".into(),
            aud: vec!["spiffe://chakra.internal/ns/backend/sa/backend".into()],
            user: None,
            act: None,
            iat: 1000,
            exp: 1300,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let token = issuer.sign_claims(&claims).unwrap();

        let (token_1, _) = exchange_token(
            &token,
            "spiffe://chakra.internal/ns/backend-b/sa/backend-b",
            &gw("spiffe://chakra.internal/ns/backend/sa/backend"),
            5,
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
            &gw("spiffe://chakra.internal/ns/backend/sa/backend"),
            5,
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
    // --- design 0002, option A: proxy-side rebind; duplicate-free act ---

    const GW_ID: &str = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway";
    const ORDERS_ID: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";
    const DELEG: &str = "DELEGATION-CERT-THUMB";

    /// A token bound to the client's certificate, addressed to the gateway, as
    /// the edge or the client would present it.
    fn bound_token(issuer: &LocalIssuer, now: i64, exp: i64) -> String {
        let claims = OboClaims { user_attributes: None, roles: None,
            user_iss: None,
            sub: "spiffe://chakra.internal/ns/client/sa/client".into(),
            aud: vec![GW_ID.into()],
            user: None,
            act: None,
            iat: now,
            exp,
            nbf: Some(now),
            jti: Some("bound-jti".into()),
            cnf: Some(CertBinding { x5t_s256: "CLIENT-CERT".into() }),
            iss: Some("spiffe://chakra.internal/ns/client/sa/client".into()),
        };
        issuer.sign_claims(&claims).unwrap()
    }

    #[test]
    fn rebind_binds_to_the_delegation_cert_and_keeps_the_chain() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        let now = 10_000;
        let inbound = bound_token(&issuer, now, now + 300);
        let (rebound, _) = rebind_token(
            &inbound, &gw(GW_ID), &issuer, issuer.verifier(), DELEG, Some("CLIENT-CERT"), 60, now,
        )
        .unwrap();
        let c = issuer.verifier().verify_signature(&rebound).unwrap();
        assert_eq!(c.cnf.unwrap().x5t_s256, DELEG, "bound to this workload's delegation cert");
        assert_eq!(c.sub, "spiffe://chakra.internal/ns/client/sa/client", "originator unchanged");
        assert!(c.act.is_none(), "rebind adds no chain entry");
        assert_eq!(c.aud, vec![GW_ID.to_string()]);
        assert_eq!(c.iss.as_deref(), Some(issuer.gateway_iss().as_str()), "iss names the gateway");
        assert!(c.jti.is_some());
    }

    #[test]
    fn rebind_never_outlives_the_inbound_token() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        let now = 10_000;
        let inbound = bound_token(&issuer, now, now + 10);
        let (rebound, _) = rebind_token(
            &inbound, &gw(GW_ID), &issuer, issuer.verifier(), DELEG, Some("CLIENT-CERT"), 300, now,
        )
        .unwrap();
        let c = issuer.verifier().verify_signature(&rebound).unwrap();
        assert_eq!(c.exp, now + 10, "exp is capped at the inbound exp, not now + ttl");
    }

    #[test]
    fn rebind_refuses_a_peer_that_does_not_hold_the_bound_cert() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        let now = 10_000;
        let inbound = bound_token(&issuer, now, now + 300);
        let err = rebind_token(
            &inbound, &gw(GW_ID), &issuer, issuer.verifier(), DELEG, Some("SOMEONE-ELSE"), 60, now,
        )
        .unwrap_err();
        assert_eq!(err, TokenExchangeError::CertificateBindingMismatch);
    }

    #[test]
    fn rebind_refuses_a_token_addressed_to_another_workload() {
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        let now = 10_000;
        let inbound = bound_token(&issuer, now, now + 300);
        let err = rebind_token(
            &inbound, &gw(ORDERS_ID), &issuer, issuer.verifier(), DELEG, Some("CLIENT-CERT"), 60, now,
        )
        .unwrap_err();
        assert_eq!(err, TokenExchangeError::AudienceMismatch);
    }

    #[test]
    fn an_edge_token_exchanged_at_its_own_gateway_does_not_repeat_the_hop() {
        // The edge token's sub is the gateway that minted it, so that gateway is
        // already the current actor. Exchanging it there must not add a second entry.
        let issuer = LocalIssuer::generate(test_registry(), 300).unwrap();
        // Build an edge-shaped token: sub = this gateway, aud = this gateway, no act.
        let now = crate::now_unix_secs();
        let edge = issuer
            .sign_claims(&OboClaims { user_attributes: None, roles: None,
                user_iss: None,
                sub: GW_ID.into(),
                aud: vec![GW_ID.into()],
                user: Some("alice@corp.internal".into()),
                act: None,
                iat: now,
                exp: now + 300,
                nbf: Some(now),
                jti: Some("edge-jti".into()),
                cnf: None,
                iss: Some(issuer.gateway_iss()),
            })
            .unwrap();
        let (exchanged, _) = exchange_token(
            &edge, ORDERS_ID, &gw(GW_ID), 3, &issuer, issuer.verifier(), &gw(GW_ID), 300, now,
        )
        .unwrap();
        let c = issuer.verifier().verify_signature(&exchanged).unwrap();
        assert!(c.act.is_none(), "the gateway is already the current actor; no duplicate entry");
        assert_eq!(c.delegation_chain(), vec![GW_ID.to_string()]);
    }

}


