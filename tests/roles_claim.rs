//! The human's roles travel from the IdP credential, through the edge mint and the exchange, as a signed claim.
//! A backend that trusts the gateway's token can therefore trust the roles, as it trusts `user`.

use jsonwebtoken::{encode, EncodingKey, Header};
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use serde_json::json;

use zero_trust::{exchange_token_with_cert_binding, IdentityProvider, JsonWebKeySet, LocalIssuer, Registry, SpiffeId, UserIdp};

const EDGE: &str = "spiffe://chakra.internal/ns/edge-gateway/sa/edge-gateway";
const BOUNDARY: &str = "spiffe://chakra.internal/ns/boundary/sa/boundary";
const IDP: &str = "auth.corp.internal";
const ALICE: &str = "alice@corp.internal";

fn registry() -> Registry {
    Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: edge-gateway
    spiffe_id: {EDGE}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: edge-secret
  - name: boundary
    spiffe_id: {BOUNDARY}
    max_obo_chain_depth: 3
    allowed_callers:
      - {EDGE}
"#
    ))
    .unwrap()
}

fn idp_key() -> (String, UserIdp) {
    let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
    let pem = key.to_pkcs1_pem(LineEnding::LF).unwrap().to_string();
    let jwks = JsonWebKeySet::from_rsa_private_pem("idp-1".to_string(), pem.as_bytes()).unwrap();
    let idp = UserIdp::new(IDP.to_string(), jwks, "data-mesh".to_string(), "sub".to_string());
    (pem, idp)
}

fn credential(pem: &str, roles: serde_json::Value) -> String {
    let now = chrono_like_now();
    let mut claims = json!({ "iss": IDP, "aud": "data-mesh", "exp": now + 300, "iat": now, "sub": ALICE });
    if !roles.is_null() {
        claims["roles"] = roles;
    }
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("idp-1".to_string());
    encode(&header, &claims, &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap()).unwrap()
}

fn chrono_like_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[test]
fn the_idp_roles_are_returned_and_malformed_roles_are_refused() {
    let (pem, idp) = idp_key();

    let (principal, roles) = idp.verify_with_roles(&credential(&pem, json!(["risk_analyst"]))).unwrap();
    assert_eq!(principal, ALICE);
    assert_eq!(roles, Some(vec!["risk_analyst".to_string()]));

    let (_, none) = idp.verify_with_roles(&credential(&pem, serde_json::Value::Null)).unwrap();
    assert_eq!(none, None, "no roles claim, no roles");

    assert!(idp.verify_with_roles(&credential(&pem, json!("risk_analyst"))).is_err(), "roles as a string is refused");
    assert!(idp.verify_with_roles(&credential(&pem, json!([1, 2]))).is_err(), "non-string roles are refused");
}

#[test]
fn the_edge_mint_signs_the_roles_and_the_exchange_keeps_them() {
    let issuer = LocalIssuer::generate(registry(), 300).unwrap();
    let edge: SpiffeId = EDGE.parse().unwrap();
    let trusted = vec![IDP.to_string()];

    let user_token = issuer
        .issue_jwt_svid_with_user_and_roles(&edge, ALICE, IDP, &trusted, &["risk_analyst".to_string()], Default::default())
        .unwrap();
    let minted = issuer.verifier().verify_signature(&user_token.token).unwrap();
    assert_eq!(minted.roles, Some(vec!["risk_analyst".to_string()]));

    let plain = issuer.issue_jwt_svid_with_user(&edge, ALICE, IDP, &trusted).unwrap();
    assert_eq!(issuer.verifier().verify_signature(&plain.token).unwrap().roles, None);

    let now = chrono_like_now();
    let (exchanged, _) = exchange_token_with_cert_binding(
        &user_token.token,
        BOUNDARY,
        &edge,
        3,
        &issuer,
        issuer.verifier(),
        &edge,
        300,
        now,
        None,
    )
    .unwrap();
    let after = issuer.verifier().verify_signature(&exchanged).unwrap();
    assert_eq!(after.user.as_deref(), Some(ALICE));
    assert_eq!(after.roles, Some(vec!["risk_analyst".to_string()]), "the exchange carries the roles through");
}

fn credential_with_claims(pem: &str, extra: serde_json::Value) -> String {
    let now = chrono_like_now();
    let mut claims = json!({ "iss": IDP, "aud": "data-mesh", "exp": now + 300, "iat": now, "sub": ALICE });
    for (key, value) in extra.as_object().unwrap() {
        claims[key] = value.clone();
    }
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("idp-1".to_string());
    encode(&header, &claims, &EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap()).unwrap()
}

#[test]
fn only_the_configured_string_claims_become_attributes() {
    let (pem, idp) = idp_key();
    let idp = idp.with_attribute_claims(vec!["kyc_id".to_string(), "department".to_string()]);

    let (_, _, attributes) = idp
        .verify_full(&credential_with_claims(&pem, json!({"kyc_id": "K-1001", "unrelated": "x"})))
        .unwrap();
    let attributes = attributes.expect("the configured claim is carried");
    assert_eq!(attributes.get("kyc_id").map(String::as_str), Some("K-1001"));
    assert!(!attributes.contains_key("unrelated"), "unconfigured claims are never carried");
    assert!(!attributes.contains_key("department"), "a missing configured claim is simply absent");

    let (_, _, none) = idp.verify_full(&credential_with_claims(&pem, json!({"kyc_id": 1001}))).unwrap();
    assert_eq!(none, None, "a non-string attribute is not carried");
}

#[test]
fn the_attributes_are_signed_by_the_edge_mint_and_carried_through_the_exchange() {
    let issuer = LocalIssuer::generate(registry(), 300).unwrap();
    let edge: SpiffeId = EDGE.parse().unwrap();
    let trusted = vec![IDP.to_string()];
    let attributes = std::collections::BTreeMap::from([("kyc_id".to_string(), "K-1001".to_string())]);

    let user_token = issuer
        .issue_jwt_svid_with_user_and_roles(&edge, ALICE, IDP, &trusted, &[], attributes.clone())
        .unwrap();
    let minted = issuer.verifier().verify_signature(&user_token.token).unwrap();
    assert_eq!(minted.user_attributes, Some(attributes.clone()));

    let now = chrono_like_now();
    let (exchanged, _) = exchange_token_with_cert_binding(
        &user_token.token,
        BOUNDARY,
        &edge,
        3,
        &issuer,
        issuer.verifier(),
        &edge,
        300,
        now,
        None,
    )
    .unwrap();
    let after = issuer.verifier().verify_signature(&exchanged).unwrap();
    assert_eq!(after.user_attributes, Some(attributes), "the exchange carries the attributes through");
}
