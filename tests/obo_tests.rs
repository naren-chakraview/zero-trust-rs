//! Task 2 (F15): `iss` (issuer) claim validation.
//!
//! `obo::validate` now checks a token's signed `iss` claim, if present: it
//! must be a well-formed SPIFFE ID (start with `spiffe://`), or the token is
//! denied with `DenyReason::IssuerInvalid`. A *missing* `iss` is explicitly
//! not a deny — old tokens minted before this claim existed must keep
//! working unchanged. These integration tests exercise that behavior
//! through the crate's public API, the same way `tests/gap_probes.rs` does
//! for the F1/F2 fixes.

use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use zero_trust::*;

const INVENTORY: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
const ORDERS: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";

fn registry() -> Registry {
    Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: inventory-svc
    spiffe_id: {INVENTORY}
    max_obo_chain_depth: 3
    allowed_callers:
      - {ORDERS}
"#
    ))
    .unwrap()
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

fn claims_with_iss(iss: Option<String>) -> OboClaims {
    OboClaims {
        sub: ORDERS.to_string(),
        aud: vec![INVENTORY.to_string()],
        user: None,
        act: None,
        iat: 0,
        exp: 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss,
    }
}

/// 1. Token with a valid `iss` (`spiffe://...`) is accepted.
#[test]
fn token_with_valid_spiffe_iss_is_accepted() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let claims = claims_with_iss(Some("spiffe://chakra.internal".to_string()));
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    assert_eq!(validate(&reg, &verifier, &request, 0), Decision::Allow);
}

/// 2. Token with an invalid `iss` format (not `spiffe://...`) is rejected
///    with `DenyReason::IssuerInvalid`.
#[test]
fn token_with_malformed_iss_is_rejected_with_issuer_invalid() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let claims = claims_with_iss(Some("https://not-a-spiffe-issuer.example".to_string()));
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    assert_eq!(
        validate(&reg, &verifier, &request, 0),
        Decision::Deny(DenyReason::IssuerInvalid)
    );
}

/// 2b. Same, but with an empty-string `iss` — also malformed.
#[test]
fn token_with_empty_iss_is_rejected_with_issuer_invalid() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let claims = claims_with_iss(Some(String::new()));
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    assert_eq!(
        validate(&reg, &verifier, &request, 0),
        Decision::Deny(DenyReason::IssuerInvalid)
    );
}

/// 3. Old tokens without an `iss` claim at all still work (backward
///    compat) — a missing `iss` is not treated as invalid.
#[test]
fn token_without_iss_claim_still_works() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let claims = claims_with_iss(None);
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    assert_eq!(validate(&reg, &verifier, &request, 0), Decision::Allow);
}

/// Same backward-compat case, but at the raw-JSON level: a token shaped
/// exactly like one minted before the `iss` claim existed (no `iss` key in
/// the JSON at all, not even `null`) must still deserialize and validate.
#[test]
fn pre_task_2_token_json_shape_still_deserializes_and_validates() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    // Exactly the JSON shape issued before this task: no `iss` field.
    let old_json = format!(r#"{{"sub":"{ORDERS}","aud":["{INVENTORY}"],"exp":300,"iat":0}}"#);
    let claims: OboClaims = serde_json::from_str(&old_json).unwrap();
    assert_eq!(claims.iss, None);

    let token = signer.sign(&claims).unwrap();
    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    assert_eq!(validate(&reg, &verifier, &request, 0), Decision::Allow);
}

/// `IssuerInvalid`'s deny reason string is populated (never the sentinel
/// "none" that `Decision::Allow` reports).
#[test]
fn issuer_invalid_deny_reason_has_a_populated_string() {
    assert_eq!(DenyReason::IssuerInvalid.as_str(), "issuer_invalid");
    assert_ne!(Decision::Deny(DenyReason::IssuerInvalid).deny_reason_str(), "none");
}

/// `IssuerNotTrusted` (reserved for a future trusted-issuer registry) also
/// has a populated string, even though nothing produces it yet.
#[test]
fn issuer_not_trusted_deny_reason_has_a_populated_string() {
    assert_eq!(DenyReason::IssuerNotTrusted.as_str(), "issuer_not_trusted");
    assert_ne!(Decision::Deny(DenyReason::IssuerNotTrusted).deny_reason_str(), "none");
}

/// `LocalIssuer::issue_jwt_svid` (the normal issuance path, Task 2's
/// `src/identity.rs` change) now stamps every token it mints with a
/// `spiffe://`-shaped `iss` claim, so tokens it issues pass the new check
/// above without any extra wiring.
#[test]
fn issued_tokens_carry_a_valid_spiffe_iss_claim() {
    let reg = Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: orders-svc
    spiffe_id: {ORDERS}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: orders-secret
"#
    ))
    .unwrap();
    let issuer = LocalIssuer::generate(reg, 300).unwrap();

    let issued = issuer.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();
    let claims = issuer.verifier().verify_signature(&issued.token).unwrap();

    let iss = claims.iss.expect("issued token must carry an iss claim");
    assert!(iss.starts_with("spiffe://"));
}
