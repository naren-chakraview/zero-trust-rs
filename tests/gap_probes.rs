//! Gap probes from `docs/reviews/0001-security-gap-review.md`.
//!
//! F8 and F9 were found against `src/ca.rs` at commit `46cd5f5`: the CA
//! copied every SAN from a CSR straight into the signed leaf (violating the
//! X.509-SVID "exactly one URI SAN" rule), and issued leaves carried no
//! basicConstraints, keyUsage or EKU at all. Both are fixed here; these
//! tests assert the *fixed* (safe) behavior and double as regression tests
//! for the fix. `f8_ca_rejects_ca_true_csr` preserves a probe for existing
//! good behavior that predates this fix.
use rcgen::{CertificateParams, KeyPair, SanType};
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
