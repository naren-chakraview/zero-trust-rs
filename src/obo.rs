//! The core decision engine: given a destination, an optional mTLS-verified
//! source principal, and an optional OBO token + caller chain, decide
//! `Allow` or `Deny(reason)`.
//!
//! Ported from two near-identical Rego policies in the blueprint
//! (`policy/opa/policies/validate-obo-chain.rego`, package `chakra.authz`,
//! and `identity/obo-token-policy.rego`, package `chakra.identity.obo`).
//! Where they differ, this module follows `validate-obo-chain.rego` — the
//! one actually wired into the runtime `ext_authz` path — including its
//! "no impersonation" check (the OBO token's `sub` must match an
//! independently-verified `source_principal`, when one is available).
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

use crate::headers::CallerChain;
use crate::jwt::JwtVerifier;
use crate::registry::Registry;
use crate::spiffe_id::SpiffeId;

/// Inputs to a single authorization decision. Mirrors the fields Envoy's
/// `ext_authz` call would carry: who the request claims to be for
/// (`destination`), who the transport layer says the direct peer is
/// (`source_principal`, `None` when there's no independently-verified
/// channel identity — the case for v0.1's plain-HTTP proxy), and the OBO
/// delegation headers, if present.
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
        }
    }
}

/// Decides whether `request` may reach `request.destination`.
///
/// A total function — it never returns `Err`. Every failure mode is a
/// `Decision::Deny(reason)`, mirroring OPA/Rego's "undefined evaluates to
/// deny" philosophy: callers always get an auditable decision + reason,
/// never a try/catch branch to remember.
pub fn validate(
    registry: &Registry,
    verifier: &JwtVerifier,
    request: &ValidationRequest<'_>,
    now_unix_secs: i64,
) -> Decision {
    let Some(destination_entry) = registry.get(request.destination) else {
        return Decision::Deny(DenyReason::UnknownDestination);
    };

    // Depth check applies unconditionally, independent of OBO-token
    // presence — matches ADR-0007's worked example ("a,b,c,d" = depth 4
    // exceeds max 3, denied regardless of anything else about the request).
    let chain = CallerChain::parse(request.caller_chain.unwrap_or(""));
    if chain.depth() > destination_entry.max_obo_chain_depth as usize {
        return Decision::Deny(DenyReason::OboChainDepthExceeded);
    }

    let Some(token) = request.obo_token else {
        // Direct-call path: no OBO token, so the transport-verified peer
        // (if any) must itself be allow-listed for this destination.
        return match request.source_principal {
            Some(source) if destination_entry.allowed_callers.contains(source) => Decision::Allow,
            _ => Decision::Deny(DenyReason::CallerNotInAllowList),
        };
    };

    // OBO path.
    let Ok(claims) = verifier.verify_signature(token) else {
        return Decision::Deny(DenyReason::OboTokenSignatureInvalid);
    };

    if now_unix_secs >= claims.exp {
        return Decision::Deny(DenyReason::OboTokenExpired);
    }

    let destination_str = request.destination.to_string();
    if !claims.aud.iter().any(|aud| aud == &destination_str) {
        return Decision::Deny(DenyReason::OboTokenInvalidAudience);
    }

    // No-impersonation check: when the transport layer independently
    // verified a peer identity, the OBO token's subject must match it.
    if let Some(source) = request.source_principal {
        if claims.sub != source.to_string() {
            return Decision::Deny(DenyReason::OboTokenSubjectMismatch);
        }
    }

    match claims.sub.parse::<SpiffeId>() {
        Ok(sub_id) if destination_entry.allowed_callers.contains(&sub_id) => Decision::Allow,
        _ => Decision::Deny(DenyReason::CallerNotInAllowList),
    }
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
    use crate::jwt::{JwtSigner, OboClaims};
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};

    const INVENTORY: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
    const ORDERS: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";
    const API_GATEWAY: &str = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway";
    const UNKNOWN: &str = "spiffe://chakra.internal/ns/ghost/sa/ghost";

    fn test_registry() -> Registry {
        let yaml = format!(
            r#"
trust_domain: chakra.internal
workloads:
  - name: inventory-svc
    spiffe_id: {INVENTORY}
    max_obo_chain_depth: 3
    allowed_callers:
      - {ORDERS}
      - {API_GATEWAY}
"#
        );
        Registry::from_yaml_str(&yaml).unwrap()
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
            iat: now,
            exp: now + ttl,
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

    #[test]
    fn chain_depth_exceeded_denies_regardless_of_an_otherwise_valid_setup() {
        let registry = test_registry();
        let (signer, verifier) = test_keys();
        let destination = id(INVENTORY);
        let token = mint_token(&signer, ORDERS, &[INVENTORY], 0, 300);

        let request = ValidationRequest {
            destination: &destination,
            source_principal: None,
            obo_token: Some(&token),
            caller_chain: Some("a,b,c,d"), // depth 4, max is 3
        };

        assert_eq!(
            validate(&registry, &verifier, &request, 0),
            Decision::Deny(DenyReason::OboChainDepthExceeded)
        );
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
}
