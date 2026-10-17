//! The core decision engine: given a destination, an optional mTLS-verified
//! source principal, and an optional OBO token + caller chain, decide
//! `Allow` or `Deny(reason)`.
//!
//! Ported from two near-identical Rego policies in the blueprint
//! (`policy/opa/policies/validate-obo-chain.rego`, package `chakra.authz`,
//! and `identity/obo-token-policy.rego`, package `chakra.identity.obo`).
//! Where they differ, this module follows `validate-obo-chain.rego` — the
//! one actually wired into the runtime `ext_authz` path — including its
//! "no impersonation" check (the OBO token's *current actor* — see the N1
//! fix below — must match an independently-verified `source_principal`,
//! when one is available).
//!
//! Deliberate additions with no Rego equivalent:
//! - [`DenyReason::UnknownDestination`]: Rego's `data.spiffe_registry[dest]`
//!   lookup just goes undefined on a miss (implicit deny, no named reason).
//!   `validate` is a total function and needs a reason for every path.
//! - [`DenyReason::OboTokenSignatureInvalid`]: in the real deployment,
//!   Envoy's `jwt_authn` filter verifies the signature *before* Rego ever
//!   runs — Rego only ever sees already-verified claims. This crate has no
//!   upstream filter doing that, so `validate` verifies the signature
//!   itself and needs a reason when that fails.
//!
//! ## F1 / F2 fix (review 0001)
//!
//! Chain depth, chain membership and the originating user principal used to
//! be read from unsigned headers (`X-SPIFFE-Caller-Chain`,
//! `X-SPIFFE-User-Principal`), which any caller could forge or omit. They
//! are now read exclusively from the *signed* `act`/`user` claims on the
//! verified OBO token (`OboClaims::delegation_chain`,
//! `OboClaims::extract_user_principal`, from Task 3). `request.caller_chain`
//! remains on [`ValidationRequest`] only for callers that want to log or
//! trace the raw header value — `validate` never reads it.
//!
//! ## N1 fix (review 0002)
//!
//! `validate` used to authorize the delegation chain's *originator*
//! (`claims.sub`) against the destination's allow-list and against the
//! transport-verified peer. That's wrong for a multi-hop chain: `sub`
//! never moves across a token exchange, so after two hops (say,
//! api-gateway -> orders -> inventory) the token presented to inventory
//! still carries `sub = api-gateway`, even though orders is the workload
//! actually calling inventory. Checking `sub` meant inventory's allow-list
//! had to name api-gateway (the originator) rather than orders (its real,
//! immediate caller) — any hop could borrow the originator's standing
//! simply by forwarding its token onward.
//!
//! `validate` now computes [`current_actor`] (the outermost `act.sub`, or
//! `sub` itself when there's no delegation) and checks *that* identity
//! against both the allow-list and `source_principal` instead.
//! `claims.sub`/`claims.user` keep their original meaning — "on whose
//! behalf" the request is made — and are never themselves checked against
//! an allow-list.

use crate::jwt::{JwtVerifier, OboClaims};
use crate::registry::Registry;
use crate::spiffe_id::SpiffeId;

/// N1 fix (review 0002): the workload *currently* exercising delegated
/// authority — the outermost `act.sub` on `claims` (the most recent hop to
/// act, per RFC 8693 §4.1 and [`crate::token_exchange::exchange_token`]'s
/// newest-first nesting, Task 1 / N4), or `claims.sub` itself when there is
/// no `act` claim at all (no delegation has happened, so the originator
/// *is* the current actor).
///
/// This is deliberately different from `claims.sub`, which never moves
/// across a delegation chain — it always names the party that *started*
/// the chain, not the party presenting the token at this hop. Authorizing
/// against `sub` lets every downstream hop skip its own allow-list check by
/// hiding behind the originator's identity; authorizing against
/// `current_actor` instead means each hop must itself be allow-listed by
/// the destination it's calling.
///
/// Example: after two exchanges (api-gateway -> orders -> inventory), the
/// token's `sub` is still api-gateway (the originator) but
/// `current_actor()` is orders (the immediate caller presenting the token
/// to inventory) — `orders`, not `api-gateway`, is what inventory's
/// allow-list must name.
///
/// # Panics
///
/// Panics if the outermost chain entry (or `sub`, when there's no `act`
/// claim) isn't a well-formed SPIFFE ID. Every caller in this module calls
/// this only after [`validate_with_clock_skew`]'s chain-entry check (the F1
/// fix) has already confirmed every hop in `claims.delegation_chain()`
/// parses as a [`SpiffeId`], so that can't happen on any path reachable
/// through `validate`/`validate_with_clock_skew`.
pub fn current_actor(claims: &OboClaims) -> SpiffeId {
    let chain = claims.delegation_chain();
    chain
        .last()
        .expect("delegation_chain() always returns at least [sub]")
        .parse::<SpiffeId>()
        .expect("chain entries must already be validated as well-formed SpiffeIds before calling current_actor")
}

/// Default `nbf` clock-skew allowance (seconds) used by [`validate`] and
/// [`validate_with_cert_binding`] — the two call sites that don't take an
/// explicit skew. [`GatewayConfig::clock_skew_tolerance_secs`] (Task 3)
/// defaults to this same value, but a deployment that widens or narrows it
/// reaches `validate` through [`validate_with_clock_skew`] /
/// [`validate_with_cert_binding_and_clock_skew`] instead, never through this
/// constant.
///
/// [`GatewayConfig::clock_skew_tolerance_secs`]: crate::config::GatewayConfig::clock_skew_tolerance_secs
pub const DEFAULT_CLOCK_SKEW_SECS: i64 = 60;

/// Inputs to a single authorization decision. Mirrors the fields Envoy's
/// `ext_authz` call would carry: who the request claims to be for
/// (`destination`), who the transport layer says the direct peer is
/// (`source_principal`, `None` when there's no independently-verified
/// channel identity — the case for v0.1's plain-HTTP proxy), and the OBO
/// delegation headers, if present.
///
/// `caller_chain` is **advisory only**: it used to drive the chain-depth
/// decision (the F1 gap), but `validate` now computes depth and chain
/// membership from the signed `act` claim on `obo_token` instead. The field
/// is kept here purely so callers have somewhere to carry the raw
/// `X-SPIFFE-Caller-Chain` header through for logging/tracing — `validate`
/// never reads it.
#[derive(Debug, Clone)]
pub struct ValidationRequest<'a> {
    pub destination: &'a SpiffeId,
    pub source_principal: Option<&'a SpiffeId>,
    pub obo_token: Option<&'a str>,
    pub caller_chain: Option<&'a str>,
}

/// The outcome of a validation, always paired with a reason on denial —
/// mirrors the Rego policies' `decision_log.deny_reason` field, which is
/// consumed downstream for audit logging (ADR-0008).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    pub fn deny_reason_str(&self) -> &'static str {
        match self {
            Decision::Allow => "none",
            Decision::Deny(reason) => reason.as_str(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    UnknownDestination,
    CallerNotInAllowList,
    OboChainDepthExceeded,
    OboTokenExpired,
    OboTokenInvalidAudience,
    OboTokenSignatureInvalid,
    OboTokenSubjectMismatch,
    /// F1 fix: a hop recorded in the signed delegation chain (`sub`, or any
    /// `act.sub`) is not a well-formed SPIFFE ID.
    InvalidChainEntry,
    /// F2 fix: the signed `user` claim is present but is not a well-formed
    /// SPIFFE ID.
    InvalidUserPrincipal,
    /// The token's `nbf` is in the future, beyond the clock-skew allowance.
    OboTokenNotYetValid,
    /// RFC 8705 (Task 8): the token carries a signed `cnf.x5t#S256` claim,
    /// but the presented TLS client certificate's thumbprint doesn't match
    /// it — or no client certificate was presented at all. Only ever
    /// produced by [`validate_with_cert_binding`]; `validate` itself never
    /// looks at certificate binding.
    CertificateBindingMismatch,
    /// Task 2 (F15): the token carries a signed `iss` claim, but it isn't a
    /// well-formed SPIFFE ID (doesn't start with `spiffe://`). A *missing*
    /// `iss` is **not** this — see the module doc on `validate` for the
    /// backward-compat rationale.
    IssuerInvalid,
    /// Reserved for a future trusted-issuer registry check: `iss` is a
    /// well-formed SPIFFE ID but isn't among the issuers this gateway
    /// trusts. Not yet produced by `validate` — no such registry exists
    /// yet — but the variant is added now so `DenyReason` and any
    /// downstream exhaustive `match`/logging already account for it.
    IssuerNotTrusted,
}

impl DenyReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            DenyReason::UnknownDestination => "unknown_destination",
            DenyReason::CallerNotInAllowList => "caller_not_in_allow_list",
            DenyReason::OboChainDepthExceeded => "obo_chain_depth_exceeded",
            DenyReason::OboTokenExpired => "obo_token_expired",
            DenyReason::OboTokenInvalidAudience => "obo_token_invalid_audience",
            DenyReason::OboTokenSignatureInvalid => "obo_token_signature_invalid",
            DenyReason::OboTokenSubjectMismatch => "obo_token_subject_mismatch",
            DenyReason::InvalidChainEntry => "invalid_chain_entry",
            DenyReason::InvalidUserPrincipal => "invalid_user_principal",
            DenyReason::OboTokenNotYetValid => "obo_token_not_yet_valid",
            DenyReason::CertificateBindingMismatch => "certificate_binding_mismatch",
            DenyReason::IssuerInvalid => "issuer_invalid",
            DenyReason::IssuerNotTrusted => "issuer_not_trusted",
        }
    }
}

/// Decides whether `request` may reach `request.destination`.
///
/// A total function — it never returns `Err`. Every failure mode is a
/// `Decision::Deny(reason)`, mirroring OPA/Rego's "undefined evaluates to
/// deny" philosophy: callers always get an auditable decision + reason,
/// never a try/catch branch to remember.
///
/// Uses [`DEFAULT_CLOCK_SKEW_SECS`] for the `nbf` check — a caller that
/// wants a configured tolerance (e.g. from
/// [`GatewayConfig::clock_skew_tolerance_secs`][skew]) should call
/// [`validate_with_clock_skew`] instead.
///
/// [skew]: crate::config::GatewayConfig::clock_skew_tolerance_secs
pub fn validate(
    registry: &Registry,
    verifier: &JwtVerifier,
    request: &ValidationRequest<'_>,
    now_unix_secs: i64,
) -> Decision {
    validate_with_clock_skew(registry, verifier, request, now_unix_secs, DEFAULT_CLOCK_SKEW_SECS)
}

/// Like [`validate`], but with an explicit `nbf` clock-skew allowance
/// (seconds) instead of [`DEFAULT_CLOCK_SKEW_SECS`] — this is what lets
/// [`GatewayConfig::clock_skew_tolerance_secs`][skew] (Task 3) actually
/// reach the decision, rather than the fixed default every other caller of
/// `validate` gets.
///
/// [skew]: crate::config::GatewayConfig::clock_skew_tolerance_secs
pub fn validate_with_clock_skew(
    registry: &Registry,
    verifier: &JwtVerifier,
    request: &ValidationRequest<'_>,
    now_unix_secs: i64,
    clock_skew_secs: i64,
) -> Decision {
    let Some(destination_entry) = registry.get(request.destination) else {
        return Decision::Deny(DenyReason::UnknownDestination);
    };

    let Some(token) = request.obo_token else {
        // Direct-call path: no OBO token, so the transport-verified peer
        // (if any) must itself be allow-listed for this destination. No
        // delegation chain exists to check depth or membership on.
        return match request.source_principal {
            Some(source) if destination_entry.allowed_callers.contains(source) => Decision::Allow,
            _ => Decision::Deny(DenyReason::CallerNotInAllowList),
        };
    };

    // OBO path.
    let Ok(claims) = verifier.verify_signature(token) else {
        return Decision::Deny(DenyReason::OboTokenSignatureInvalid);
    };

    // --- F1 fix: signed chain depth + membership, not the header --------
    // `delegation_chain()` is `[sub, act.sub, act.act.sub, ...]` — the
    // immediate caller plus every hop recorded before it in the signed
    // `act` nesting — so its length is the same quantity the old
    // header-based check compared against `max_obo_chain_depth` (the
    // header, too, included the immediate sender as its last-appended
    // entry). The difference is entirely about *where the number comes
    // from*: `request.caller_chain` (unsigned, attacker-controlled) is
    // never read here.
    let chain = claims.delegation_chain();
    if chain.len() > destination_entry.max_obo_chain_depth as usize {
        return Decision::Deny(DenyReason::OboChainDepthExceeded);
    }
    for entry in &chain {
        if entry.parse::<SpiffeId>().is_err() {
            return Decision::Deny(DenyReason::InvalidChainEntry);
        }
    }

    // --- F2 fix: signed user principal, not the header -------------------
    // `request.caller_chain`'s unsigned sibling header
    // (`X-SPIFFE-User-Principal`) is never consulted here at all — only
    // the signed `user` claim, if the token carries one.
    if let Some(user) = claims.extract_user_principal() {
        if user.parse::<SpiffeId>().is_err() {
            return Decision::Deny(DenyReason::InvalidUserPrincipal);
        }
    }

    // --- Task 2 / F15: issuer claim validation ---------------------------
    // A signed `iss` claim, if present, must be a well-formed SPIFFE ID
    // (`spiffe://...`). A *missing* `iss` is explicitly allowed here for
    // backward compatibility with tokens minted before this claim existed
    // — tightening that (e.g. requiring `iss` and checking it against a
    // trusted-issuer registry, which is what `DenyReason::IssuerNotTrusted`
    // is reserved for) is left to a future task.
    if let Some(iss) = &claims.iss {
        if !iss.starts_with("spiffe://") {
            return Decision::Deny(DenyReason::IssuerInvalid);
        }
    }

    if now_unix_secs >= claims.exp {
        return Decision::Deny(DenyReason::OboTokenExpired);
    }

    // Not-before, with a clock-skew allowance (unlike `exp` above, which is
    // checked strictly, with none). Equivalent to `now_unix_secs < nbf -
    // clock_skew_secs`, just rearranged to avoid subtracting into
    // `i64::MIN` territory on pathological `nbf` values.
    if let Some(nbf) = claims.nbf {
        if nbf > now_unix_secs + clock_skew_secs {
            return Decision::Deny(DenyReason::OboTokenNotYetValid);
        }
    }

    // `jti` (JWT ID, Task 3): tracked for replay-cache purposes elsewhere,
    // not enforced here. A missing `jti` is never a deny — only tokens
    // minted after this task carry one at all, and older tokens must keep
    // validating exactly as before. Logged (not denied) purely so an
    // operator can see, over time, whether any pre-Task-3 tokens are still
    // in circulation.
    if claims.jti.is_none() {
        tracing::debug!("OBO token has no jti claim (pre-Task-3 token, or minted by a provider that omits it)");
    }

    let destination_str = request.destination.to_string();
    if !claims.aud.iter().any(|aud| aud == &destination_str) {
        return Decision::Deny(DenyReason::OboTokenInvalidAudience);
    }

    // --- N1 fix (review 0002): authorize the CURRENT actor, not the
    // originator. `claims.sub`/`claims.user` remain "on whose behalf" this
    // request is made (never checked against the allow-list below) --
    // `current_actor` is the party actually presenting this token at this
    // hop, and it's that identity the destination's allow-list and
    // transport-verified peer must agree with. See `current_actor`'s doc
    // comment for why: `sub` never moves across a delegation chain, so
    // checking it here would authorize the chain's originator at every
    // hop instead of the immediate caller.
    let actor = current_actor(&claims);

    // No-impersonation check: when the transport layer independently
    // verified a peer identity, the current actor must match it.
    if let Some(source) = request.source_principal {
        if &actor != source {
            return Decision::Deny(DenyReason::OboTokenSubjectMismatch);
        }
    }

    if destination_entry.allowed_callers.contains(&actor) {
        Decision::Allow
    } else {
        Decision::Deny(DenyReason::CallerNotInAllowList)
    }
}

/// Like [`validate`], but additionally enforces RFC 8705 certificate
/// binding (Task 8): if the token carries a signed `cnf.x5t#S256` claim,
/// `peer_cert_thumbprint` — the thumbprint of whatever TLS client
/// certificate (if any) the caller presented — must match it exactly, or
/// the request is denied with [`DenyReason::CertificateBindingMismatch`].
/// That includes the case where no certificate was presented at all
/// (`peer_cert_thumbprint: None`): a token that demands cert binding and a
/// missing cert both fail closed, never open.
///
/// Tokens with no `cnf` claim are completely unaffected — this check is
/// simply skipped, and the decision falls straight through to [`validate`]
/// — which is what makes old, unbound tokens (and every direct-call
/// request, which never has a `cnf` claim to check) behave identically to
/// before this function existed.
///
/// The cert-binding check runs first, independently of every other check
/// `validate` performs, so a bound token presented with the wrong (or no)
/// certificate is always reported as `CertificateBindingMismatch`, never
/// shadowed by some other `DenyReason` that would otherwise have applied
/// first (e.g. an expired token also presented with the wrong cert still
/// reports the cert mismatch, not `OboTokenExpired`).
///
/// An invalid signature is deliberately *not* special-cased here: if
/// `verify_signature` fails, this function skips the cert-binding check
/// (there are no trustworthy claims to read a `cnf` from) and defers
/// entirely to `validate`, which performs its own signature check and
/// reports `DenyReason::OboTokenSignatureInvalid`.
pub fn validate_with_cert_binding(
    registry: &Registry,
    verifier: &JwtVerifier,
    request: &ValidationRequest<'_>,
    peer_cert_thumbprint: Option<&str>,
    now_unix_secs: i64,
) -> Decision {
    validate_with_cert_binding_and_clock_skew(
        registry,
        verifier,
        request,
        peer_cert_thumbprint,
        now_unix_secs,
        DEFAULT_CLOCK_SKEW_SECS,
    )
}

/// Like [`validate_with_cert_binding`], but with an explicit `nbf`
/// clock-skew allowance (seconds) — the cert-binding counterpart of
/// [`validate_with_clock_skew`], for callers that want
/// [`GatewayConfig::clock_skew_tolerance_secs`][skew] (Task 3) honored on
/// the cert-bound path too.
///
/// [skew]: crate::config::GatewayConfig::clock_skew_tolerance_secs
pub fn validate_with_cert_binding_and_clock_skew(
    registry: &Registry,
    verifier: &JwtVerifier,
    request: &ValidationRequest<'_>,
    peer_cert_thumbprint: Option<&str>,
    now_unix_secs: i64,
    clock_skew_secs: i64,
) -> Decision {
    if let Some(token) = request.obo_token {
        if let Ok(claims) = verifier.verify_signature(token) {
            if let Some(cnf) = &claims.cnf {
                let cert_matches = peer_cert_thumbprint.is_some_and(|thumb| thumb == cnf.x5t_s256);
                if !cert_matches {
                    return Decision::Deny(DenyReason::CertificateBindingMismatch);
                }
            }
        }
    }

    validate_with_clock_skew(registry, verifier, request, now_unix_secs, clock_skew_secs)
}

/// Convenience wrapper for long-lived call sites (a gateway holding one
/// `Registry` + `JwtVerifier` pair across many requests) so they don't have
/// to thread both through every call.
pub struct Validator {
    registry: Registry,
    verifier: JwtVerifier,
}

impl Validator {
    pub fn new(registry: Registry, verifier: JwtVerifier) -> Self {
        Self { registry, verifier }
    }

    pub fn validate(&self, request: &ValidationRequest<'_>, now_unix_secs: i64) -> Decision {
        validate(&self.registry, &self.verifier, request, now_unix_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{ActClaim, JwtSigner, OboClaims};
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};

    const INVENTORY: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
    const ORDERS: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";
    const API_GATEWAY: &str = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway";
    const UNKNOWN: &str = "spiffe://chakra.internal/ns/ghost/sa/ghost";
    const ALICE: &str = "spiffe://chakra.internal/ns/users/sa/alice";
    const GW1: &str = "spiffe://chakra.internal/ns/gw1/sa/gw1";
    const GW2: &str = "spiffe://chakra.internal/ns/gw2/sa/gw2";
    const GW3: &str = "spiffe://chakra.internal/ns/gw3/sa/gw3";

    fn test_registry_with_max_depth(max_obo_chain_depth: u32) -> Registry {
        let yaml = format!(
            r#"
trust_domain: chakra.internal
workloads:
  - name: inventory-svc
    spiffe_id: {INVENTORY}
    max_obo_chain_depth: {max_obo_chain_depth}
    allowed_callers:
      - {ORDERS}
      - {API_GATEWAY}
"#
        );
        Registry::from_yaml_str(&yaml).unwrap()
    }

    fn test_registry() -> Registry {
        test_registry_with_max_depth(3)
    }

    fn id(s: &str) -> SpiffeId {
        s.parse().unwrap()
    }

    /// TEST-ONLY RSA keypair, returned as (signer, verifier).
    fn test_keys() -> (JwtSigner, JwtVerifier) {
        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let private_pem = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();
        let public_pem = public_key.to_pkcs1_pem(LineEnding::LF).unwrap();
        (
            JwtSigner::from_rsa_pem(private_pem.as_bytes()).unwrap(),
            JwtVerifier::from_rsa_pem(public_pem.as_bytes()).unwrap(),
        )
    }

    fn mint_token(signer: &JwtSigner, sub: &str, aud: &[&str], now: i64, ttl: i64) -> String {
        let claims = OboClaims {
            sub: sub.to_string(),
            aud: aud.iter().map(|s| s.to_string()).collect(),
            user: None,
            act: None,
            iat: now,
            exp: now + ttl,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        signer.sign(&claims).unwrap()
    }

    // --- Ported from policy/opa/tests/obo-chain_test.rego ---

    #[test]
    fn direct_call_allowed_when_caller_in_allow_list() {
        let registry = test_registry();
        let (_, verifier) = test_keys();
        let destination = id(INVENTORY);
        let source = id(ORDERS);

        let request = ValidationRequest {
            destination: &destination,
            source_principal: Some(&source),
            obo_token: None,
            caller_chain: None,
        };

        assert_eq!(validate(&registry, &verifier, &request, 0), Decision::Allow);
    }

    #[test]
    fn direct_call_denied_when_caller_not_in_allow_list() {
        let registry = test_registry();
        let (_, verifier) = test_keys();
        let destination = id(INVENTORY);
        let source = id(UNKNOWN);

        let request = ValidationRequest {
            destination: &destination,
            source_principal: Some(&source),
            obo_token: None,
            caller_chain: None,
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 0),
            Decision::Deny(DenyReason::CallerNotInAllowList)
        );
    }

    /// F1 fix — deviation note: this test originally drove the deny from
    /// the unsigned `X-SPIFFE-Caller-Chain` header alone
    /// (`caller_chain: Some("a,b,c,d")`, depth 4 > max 3), with no signed
    /// chain at all. That mechanism is *exactly* the F1 vulnerability this
    /// task fixes — the header is no longer read by `validate` for any
    /// decision — so the old assertion could not survive unchanged. The
    /// test is rewritten here to reach the same depth (4: `sub` + 3 signed
    /// `act` hops) through the fixed mechanism instead, with no
    /// `caller_chain` header at all, preserving the original test's intent
    /// ("depth exceeded denies regardless of an otherwise valid setup").
    #[test]
    fn chain_depth_exceeded_denies_regardless_of_an_otherwise_valid_setup() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        let claims = OboClaims {
            sub: ORDERS.to_string(),
            aud: vec![INVENTORY.to_string()],
            user: None,
            act: Some(Box::new(ActClaim {
                sub: GW1.to_string(),
                act: Some(Box::new(ActClaim {
                    sub: GW2.to_string(),
                    act: Some(Box::new(ActClaim {
                        sub: GW3.to_string(),
                        act: None,
                    })),
                })),
            })),
            iat: 0,
            exp: 300,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let token = signer.sign(&claims).unwrap();

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None, // the header this test used to rely on is gone
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 0),
            Decision::Deny(DenyReason::OboChainDepthExceeded)
        );
    }

    // --- F1, F2 fixed: signed chain depth, chain membership and user
    // principal are enforced from the token, never from headers. These
    // invert gap probes F1 and F2 from
    // docs/reviews/0001-security-gap-review.md into regression tests (see
    // also tests/gap_probes.rs, which exercises the same fix through the
    // crate's public API).

    #[test]
    fn f1_signed_chain_depth_enforced() {
        let registry = test_registry_with_max_depth(3);
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);

        // 4-deep signed chain (sub + 3 act hops) exceeds max depth 3.
        let claims = OboClaims {
            sub: ORDERS.to_string(),
            aud: vec![INVENTORY.to_string()],
            user: Some(ALICE.to_string()),
            act: Some(Box::new(ActClaim {
                sub: GW1.to_string(),
                act: Some(Box::new(ActClaim {
                    sub: GW2.to_string(),
                    act: Some(Box::new(ActClaim {
                        sub: GW3.to_string(),
                        act: None,
                    })),
                })),
            })),
            iat: 0,
            exp: 300,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let token = signer.sign(&claims).unwrap();

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None, // header absent entirely
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 0),
            Decision::Deny(DenyReason::OboChainDepthExceeded)
        );
    }

    #[test]
    fn f1_chain_entries_validated_as_spiffe_ids() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);

        let claims = OboClaims {
            sub: ORDERS.to_string(),
            aud: vec![INVENTORY.to_string()],
            user: Some(ALICE.to_string()),
            act: Some(Box::new(ActClaim {
                sub: "not-a-spiffe-id".to_string(), // invalid chain entry
                act: None,
            })),
            iat: 0,
            exp: 300,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let token = signer.sign(&claims).unwrap();

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 0),
            Decision::Deny(DenyReason::InvalidChainEntry)
        );
    }

    #[test]
    fn f2_user_principal_validated() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);

        let claims = OboClaims {
            sub: ORDERS.to_string(),
            aud: vec![INVENTORY.to_string()],
            user: Some("not-a-user-id".to_string()), // invalid user principal
            act: None,
            iat: 0,
            exp: 300,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let token = signer.sign(&claims).unwrap();

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 0),
            Decision::Deny(DenyReason::InvalidUserPrincipal)
        );
    }

    #[test]
    fn f2_valid_signed_user_principal_is_allowed() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);

        let claims = OboClaims {
            sub: ORDERS.to_string(),
            aud: vec![INVENTORY.to_string()],
            user: Some(ALICE.to_string()), // valid SPIFFE ID
            act: None,
            iat: 0,
            exp: 300,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let token = signer.sign(&claims).unwrap();

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(validate(&registry, &verifier, &request, 0), Decision::Allow);
    }

    #[test]
    fn f1_f2_header_override_impossible() {
        let registry = test_registry_with_max_depth(2);
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);

        // 3-deep signed chain (sub + 2 act hops) exceeds max depth 2.
        let claims = OboClaims {
            sub: ORDERS.to_string(),
            aud: vec![INVENTORY.to_string()],
            user: Some(ALICE.to_string()),
            act: Some(Box::new(ActClaim {
                sub: GW1.to_string(),
                act: Some(Box::new(ActClaim {
                    sub: GW2.to_string(),
                    act: None,
                })),
            })),
            iat: 0,
            exp: 300,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        };
        let token = signer.sign(&claims).unwrap();

        // Attacker-controlled header claims a short, harmless chain.
        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: Some("fake,chain"),
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 0),
            Decision::Deny(DenyReason::OboChainDepthExceeded)
        );

        // Proof the header truly has no effect: omitting it entirely yields
        // the identical decision.
        let request_no_header = ValidationRequest {
            caller_chain: None,
            ..request
        };
        assert_eq!(
            validate(&registry, &verifier, &request_no_header, 0),
            Decision::Deny(DenyReason::OboChainDepthExceeded)
        );
    }

    #[test]
    fn obo_token_not_yet_valid_is_denied() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        let mut claims = OboClaims {
            sub: ORDERS.to_string(),
            aud: vec![INVENTORY.to_string()],
            user: None,
            act: None,
            iat: 0,
            exp: 300,
            nbf: Some(1_000), // far beyond the 30s clock-skew allowance at now=0
            jti: None,
            cnf: None,
            iss: None,
        };
        claims.exp = 2_000;
        let token = signer.sign(&claims).unwrap();

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 0),
            Decision::Deny(DenyReason::OboTokenNotYetValid)
        );
    }

    #[test]
    fn obo_token_nbf_within_clock_skew_is_allowed() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        let claims = OboClaims {
            sub: ORDERS.to_string(),
            aud: vec![INVENTORY.to_string()],
            user: None,
            act: None,
            iat: 0,
            exp: 300,
            nbf: Some(20), // within the 30s clock-skew allowance at now=0
            jti: None,
            cnf: None,
            iss: None,
        };
        let token = signer.sign(&claims).unwrap();

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(validate(&registry, &verifier, &request, 0), Decision::Allow);
    }

    #[test]
    fn new_deny_reasons_have_populated_strings() {
        for reason in [
            DenyReason::InvalidChainEntry,
            DenyReason::InvalidUserPrincipal,
            DenyReason::OboTokenNotYetValid,
        ] {
            assert_ne!(Decision::Deny(reason).deny_reason_str(), "none");
        }
    }

    #[test]
    fn deny_reason_is_always_populated() {
        assert_eq!(Decision::Allow.deny_reason_str(), "none");

        let reasons = [
            DenyReason::UnknownDestination,
            DenyReason::CallerNotInAllowList,
            DenyReason::OboChainDepthExceeded,
            DenyReason::OboTokenExpired,
            DenyReason::OboTokenInvalidAudience,
            DenyReason::OboTokenSignatureInvalid,
            DenyReason::OboTokenSubjectMismatch,
        ];
        for reason in reasons {
            assert_ne!(Decision::Deny(reason).deny_reason_str(), "none");
        }
    }

    // --- Additional edge cases ---

    #[test]
    fn unknown_destination_is_denied() {
        let registry = test_registry();
        let (_, verifier) = test_keys();
        let destination = id(UNKNOWN);

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: None,
            caller_chain: None,
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 0),
            Decision::Deny(DenyReason::UnknownDestination)
        );
    }

    #[test]
    fn obo_path_is_allowed_with_no_source_principal() {
        // The v0.1 zt-gateway proxy path: no mTLS, so source_principal is
        // always None. The OBO token alone must be enough to authorize.
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        let token = mint_token(&signer, ORDERS, &[INVENTORY], 0, 300);

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: Some(API_GATEWAY),
        };

        assert_eq!(validate(&registry, &verifier, &request, 0), Decision::Allow);
    }

    #[test]
    fn obo_token_expired_is_denied() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        // exp = 100, "now" = 100 -> already expired (now >= exp).
        let token = mint_token(&signer, ORDERS, &[INVENTORY], 0, 100);

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 100),
            Decision::Deny(DenyReason::OboTokenExpired)
        );
    }

    #[test]
    fn obo_token_missing_audience_is_denied() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        let token = mint_token(&signer, ORDERS, &[API_GATEWAY], 0, 300); // wrong audience

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 0),
            Decision::Deny(DenyReason::OboTokenInvalidAudience)
        );
    }

    #[test]
    fn obo_token_with_bad_signature_is_denied() {
        let registry = test_registry();
        let (signer, _correct_verifier) = test_keys();
        let (_, wrong_verifier) = test_keys(); // different keypair
        let destination = id(INVENTORY);
        let token = mint_token(&signer, ORDERS, &[INVENTORY], 0, 300);

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(
            validate(&registry, &wrong_verifier, &request, 0),
            Decision::Deny(DenyReason::OboTokenSignatureInvalid)
        );
    }

    #[test]
    fn obo_subject_mismatch_is_denied_when_source_principal_disagrees() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        let claimed_source = id(API_GATEWAY); // mTLS peer says api-gateway...
        let token = mint_token(&signer, ORDERS, &[INVENTORY], 0, 300); // ...but the token says orders-svc

        let request = ValidationRequest {
            destination: &destination,
            source_principal: Some(&claimed_source),
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 0),
            Decision::Deny(DenyReason::OboTokenSubjectMismatch)
        );
    }

    // --- RFC 8705 certificate-bound tokens (Task 8, F5) ---

    use crate::jwt::CertBinding;

    fn mint_token_with_cnf(signer: &JwtSigner, sub: &str, aud: &[&str], cert_thumbprint: &str) -> String {
        let claims = OboClaims {
            sub: sub.to_string(),
            aud: aud.iter().map(|s| s.to_string()).collect(),
            user: None,
            act: None,
            iat: 0,
            exp: 300,
            nbf: None,
            jti: None,
            cnf: Some(CertBinding {
                x5t_s256: cert_thumbprint.to_string(),
            }),
            iss: None,
        };
        signer.sign(&claims).unwrap()
    }

    #[test]
    fn f5_token_with_binding_accepted_with_matching_cert() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        let token = mint_token_with_cnf(&signer, ORDERS, &[INVENTORY], "cert-a-thumbprint");

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(
            validate_with_cert_binding(&registry, &verifier, &request, Some("cert-a-thumbprint"), 0),
            Decision::Allow
        );
    }

    #[test]
    fn f5_token_with_binding_rejected_with_mismatched_cert() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        let token = mint_token_with_cnf(&signer, ORDERS, &[INVENTORY], "cert-a-thumbprint");

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(
            validate_with_cert_binding(&registry, &verifier, &request, Some("cert-b-thumbprint"), 0),
            Decision::Deny(DenyReason::CertificateBindingMismatch)
        );
    }

    #[test]
    fn f5_token_with_binding_rejected_with_no_cert_presented() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        let token = mint_token_with_cnf(&signer, ORDERS, &[INVENTORY], "cert-a-thumbprint");

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(
            validate_with_cert_binding(&registry, &verifier, &request, None, 0),
            Decision::Deny(DenyReason::CertificateBindingMismatch)
        );
    }

    #[test]
    fn f5_tokens_without_binding_still_work_with_or_without_a_cert() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        // Old-style token, no `cnf` claim at all.
        let token = mint_token(&signer, ORDERS, &[INVENTORY], 0, 300);

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        // No cert presented: still allowed, since there's no binding to check.
        assert_eq!(
            validate_with_cert_binding(&registry, &verifier, &request, None, 0),
            Decision::Allow
        );
        // A cert presented anyway: also still allowed -- an unbound token
        // doesn't care who presents it at the transport layer.
        assert_eq!(
            validate_with_cert_binding(&registry, &verifier, &request, Some("whatever-cert"), 0),
            Decision::Allow
        );
    }

    #[test]
    fn f5_cert_binding_mismatch_is_reported_even_when_the_token_is_also_expired() {
        // The cert-binding check runs independently of (and before)
        // `validate`'s own checks, so it's the mismatch that's reported,
        // not `OboTokenExpired` -- proving the two checks don't shadow
        // each other in the wrong order.
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        let claims = OboClaims {
            sub: ORDERS.to_string(),
            aud: vec![INVENTORY.to_string()],
            user: None,
            act: None,
            iat: 0,
            exp: 1, // already expired by now=100 below
            nbf: None,
            jti: None,
            cnf: Some(CertBinding {
                x5t_s256: "cert-a-thumbprint".to_string(),
            }),
            iss: None,
        };
        let token = signer.sign(&claims).unwrap();

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: None,
        };

        assert_eq!(
            validate_with_cert_binding(&registry, &verifier, &request, Some("wrong-cert"), 100),
            Decision::Deny(DenyReason::CertificateBindingMismatch)
        );
    }

    #[test]
    fn f5_cert_binding_mismatch_deny_reason_has_a_populated_string() {
        assert_ne!(
            Decision::Deny(DenyReason::CertificateBindingMismatch).deny_reason_str(),
            "none"
        );
        assert_eq!(
            DenyReason::CertificateBindingMismatch.as_str(),
            "certificate_binding_mismatch"
        );
    }
}
