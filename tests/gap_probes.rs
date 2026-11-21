//! Gap probes from `docs/reviews/0001-security-gap-review.md`.
//!
//! F8 and F9 were found against `src/ca.rs` at commit `46cd5f5`: the CA
//! copied every SAN from a CSR straight into the signed leaf (violating the
//! X.509-SVID "exactly one URI SAN" rule), and issued leaves carried no
//! basicConstraints, keyUsage or EKU at all. Both are fixed here; these
//! tests assert the *fixed* (safe) behavior and double as regression tests
//! for the fix. `f8_ca_rejects_ca_true_csr` preserves a probe for existing
//! good behavior that predates this fix.
//!
//! F1 and F2 were found against `src/obo.rs` at the same review: the
//! delegation-chain depth limit was enforced against the unsigned
//! `X-SPIFFE-Caller-Chain` header (bypassable by simply omitting it, and
//! never validated as SPIFFE IDs), and the originating user principal was
//! an unvalidated, unsigned `X-SPIFFE-User-Principal` header recorded as an
//! audit fact. The original review's probes for these
//! (`f1_depth_limit_bypassed_by_omitting_chain_header`,
//! `f1_chain_entries_not_validated`, `f2_token_has_no_user_or_chain_claims`)
//! asserted that vulnerable behavior but were never checked into this file.
//! Both are now fixed (signed `act`/`user` claims, from Task 3's
//! `OboClaims::delegation_chain`/`extract_user_principal`, drive the
//! decision instead); the tests below assert the fixed behavior directly
//! and serve as F1/F2's regression tests.
use rcgen::{CertificateParams, KeyPair, SanType};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use zero_trust::*;

const INV: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
const ORD: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";

fn reg() -> Registry {
    Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: inventory-svc
    spiffe_id: {INV}
    max_obo_chain_depth: 3
    allowed_callers: [{ORD}]
  - name: orders-svc
    spiffe_id: {ORD}
    allowed_callers: []
    bootstrap_token: orders-secret
"#
    ))
    .unwrap()
}

fn csr(params: CertificateParams) -> String {
    let kp = KeyPair::generate().unwrap();
    params.serialize_request(&kp).unwrap().pem().unwrap()
}

fn leaf(pem: &str) -> Vec<u8> {
    rustls_pemfile::certs(&mut pem.as_bytes()).next().unwrap().unwrap().to_vec()
}

/// F8, existing good behavior kept as a regression test: a CSR requesting
/// `basicConstraints CA:TRUE` is rejected outright (rcgen refuses to parse
/// a CSR with extensions it doesn't support).
#[test]
fn f8_ca_rejects_ca_true_csr() {
    let ca = LocalCa::generate(reg(), 3600).unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ca_true.csr");
    let pem = std::fs::read_to_string(path).unwrap();
    assert!(ca.sign_csr("orders-svc", &pem, "orders-secret").is_err());
}

/// F8, fixed: a CSR with more than one URI SAN is rejected instead of
/// having every URI copied into the leaf.
#[test]
fn f8_ca_rejects_multiple_uri_sans() {
    let ca = LocalCa::generate(reg(), 3600).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.subject_alt_names = vec![SanType::URI(ORD.try_into().unwrap()), SanType::URI(INV.try_into().unwrap())];
    let err = ca.sign_csr("orders-svc", &csr(p), "orders-secret").unwrap_err();
    assert!(matches!(err, CaError::MultipleUriSans));
}

/// F8, fixed: a CSR carrying a DNS (or any non-URI) SAN is rejected rather
/// than having that SAN smuggled into the signed leaf.
#[test]
fn f8_ca_rejects_non_uri_sans_in_csr() {
    let ca = LocalCa::generate(reg(), 3600).unwrap();
    let mut p = CertificateParams::new(vec!["evil.example.com".to_string()]).unwrap();
    p.subject_alt_names.insert(0, SanType::URI(ORD.try_into().unwrap()));
    let err = ca.sign_csr("orders-svc", &csr(p), "orders-secret").unwrap_err();
    assert!(matches!(err, CaError::NonUriSanInCsr));
}

/// F8, fixed: the issued leaf has exactly one SAN, a URI matching the
/// authenticated workload's registered SPIFFE ID — no extra SANs, even
/// when the CSR didn't try to smuggle any in.
#[test]
fn f8_ca_issued_leaf_has_exactly_one_uri_san() {
    let ca = LocalCa::generate(reg(), 3600).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.subject_alt_names = vec![SanType::URI(ORD.try_into().unwrap())];
    let signed = ca.sign_csr("orders-svc", &csr(p), "orders-secret").unwrap();
    let der = leaf(&signed.cert_pem);
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let san = cert.subject_alternative_name().unwrap().unwrap();
    assert_eq!(san.value.general_names.len(), 1);
    match &san.value.general_names[0] {
        x509_parser::extensions::GeneralName::URI(uri) => assert_eq!(*uri, ORD),
        other => panic!("expected a single URI SAN, got {other:?}"),
    }
}

/// F9, fixed: the issued leaf carries basicConstraints (cA=false),
/// keyUsage (digitalSignature, keyEncipherment, keyAgreement) and EKU
/// (clientAuth, serverAuth), all absent before this fix.
#[test]
fn f9_leaf_has_svid_constraints() {
    let ca = LocalCa::generate(reg(), 3600).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.subject_alt_names = vec![SanType::URI(ORD.try_into().unwrap())];
    let signed = ca.sign_csr("orders-svc", &csr(p), "orders-secret").unwrap();
    let der = leaf(&signed.cert_pem);
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();

    let bc = cert.basic_constraints().unwrap().unwrap();
    assert!(!bc.value.ca);

    let ku = cert.key_usage().unwrap().unwrap();
    assert!(ku.value.digital_signature());
    assert!(ku.value.key_encipherment());
    assert!(ku.value.key_agreement());

    let eku = cert.extended_key_usage().unwrap().unwrap();
    assert!(eku.value.client_auth);
    assert!(eku.value.server_auth);
}

/// A fresh TEST-ONLY RSA keypair for `obo::validate`'s token signature
/// checks, independent of `LocalIssuer` (which doesn't yet support minting
/// tokens with a delegation chain or user principal — that's Task 5's
/// token-exchange endpoint). Mirrors `src/obo.rs`'s own `test_keys` helper.
fn gap_test_keys() -> (JwtSigner, JwtVerifier) {
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

/// F1, fixed: chain depth is enforced from the signed `act` nesting, not
/// the unsigned `X-SPIFFE-Caller-Chain` header. A forged, short header
/// claiming an innocuous chain has no effect, and omitting the header
/// entirely yields the identical decision — directly inverting
/// `f1_depth_limit_bypassed_by_omitting_chain_header`'s premise.
#[test]
fn f1_signed_chain_depth_enforced_header_has_no_effect() {
    let registry = reg();
    let (signer, verifier) = gap_test_keys();
    let dest: SpiffeId = INV.parse().unwrap();
    let now = now_unix_secs();

    // reg()'s inventory-svc caps max_obo_chain_depth at 3. This chain is
    // 4 deep: sub (orders) + 3 signed act hops.
    let claims = OboClaims { roles: None,
        user_iss: None,
        sub: ORD.to_string(),
        aud: vec![INV.to_string()],
        user: Some("spiffe://chakra.internal/ns/users/sa/alice".to_string()),
        act: Some(Box::new(ActClaim {
            sub: "spiffe://chakra.internal/ns/gw1/sa/gw1".to_string(),
            act: Some(Box::new(ActClaim {
                sub: "spiffe://chakra.internal/ns/gw2/sa/gw2".to_string(),
                act: Some(Box::new(ActClaim {
                    sub: "spiffe://chakra.internal/ns/gw3/sa/gw3".to_string(),
                    act: None,
                })),
            })),
        })),
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &dest,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: Some("x"), // forged/irrelevant; never read for decisions
    };
    assert_eq!(
        validate(&registry, &verifier, &request, now),
        Decision::Deny(DenyReason::OboChainDepthExceeded)
    );

    let request_no_header = ValidationRequest {
        caller_chain: None,
        ..request
    };
    assert_eq!(
        validate(&registry, &verifier, &request_no_header, now),
        Decision::Deny(DenyReason::OboChainDepthExceeded)
    );
}

/// F1, fixed: every entry in the signed delegation chain must itself be a
/// well-formed SPIFFE ID — directly inverting
/// `f1_chain_entries_not_validated`'s premise.
#[test]
fn f1_chain_entries_must_be_valid_spiffe_ids() {
    let registry = reg();
    let (signer, verifier) = gap_test_keys();
    let dest: SpiffeId = INV.parse().unwrap();
    let now = now_unix_secs();

    let claims = OboClaims { roles: None,
        user_iss: None,
        sub: ORD.to_string(),
        aud: vec![INV.to_string()],
        user: None,
        act: Some(Box::new(ActClaim {
            sub: "not-an-id".to_string(),
            act: None,
        })),
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &dest,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };
    assert_eq!(
        validate(&registry, &verifier, &request, now),
        Decision::Deny(DenyReason::InvalidChainEntry)
    );
}

/// F2, fixed: the originating user principal is a signed `user` claim,
/// validated as a SPIFFE ID — directly inverting
/// `f2_token_has_no_user_or_chain_claims`'s premise (that no such signed
/// claim existed at all).
#[test]
fn f2_user_principal_is_signed_and_validated() {
    let registry = reg();
    let (signer, verifier) = gap_test_keys();
    let dest: SpiffeId = INV.parse().unwrap();
    let now = now_unix_secs();

    let good_claims = OboClaims { roles: None,
        user_iss: None,
        sub: ORD.to_string(),
        aud: vec![INV.to_string()],
        user: Some("spiffe://chakra.internal/ns/users/sa/alice".to_string()),
        act: None,
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    let good_token = signer.sign(&good_claims).unwrap();
    let good_request = ValidationRequest {
        destination: &dest,
        source_principal: None,
        obo_token: Some(&good_token),
        caller_chain: None,
    };
    // A well-formed signed user claim round-trips and does not block the
    // decision.
    assert_eq!(validate(&registry, &verifier, &good_request, now), Decision::Allow);

    let mut bad_claims = good_claims;
    bad_claims.user = Some("not-a-user-id".to_string());
    let bad_token = signer.sign(&bad_claims).unwrap();
    let bad_request = ValidationRequest {
        destination: &dest,
        source_principal: None,
        obo_token: Some(&bad_token),
        caller_chain: None,
    };
    // An invalid signed user claim is rejected outright -- it is never
    // taken from (or bypassed via) an unsigned header.
    assert_eq!(
        validate(&registry, &verifier, &bad_request, now),
        Decision::Deny(DenyReason::InvalidUserPrincipal)
    );
}
