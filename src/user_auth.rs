//! Verification of human user credentials for the edge-mint path (N5 fix,
//! review 0002).
//!
//! `POST /v1/svid/jwt-with-user` used to trust the credential string it was
//! handed: anyone who named a trusted issuer could mint a token for any user.
//! This module checks the credential itself. It must be an RS256 JWT signed
//! by a configured IdP key, with the expected `iss` and `aud`, unexpired,
//! and carrying the configured principal claim. Only then is that claim's
//! value passed on as the user principal.

use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde_json::{Map, Value};

use crate::identity::JsonWebKeySet;

/// Why a user credential was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UserAuthError {
    /// The claimed issuer has no configured verification keys.
    #[error("untrusted user issuer: {0}")]
    UntrustedIssuer(String),
    /// The credential failed a check (signature, algorithm, issuer,
    /// audience, expiry, or a missing principal claim).
    #[error("invalid user credential: {0}")]
    InvalidCredential(String),
}

/// One trusted identity provider: its public keys plus the checks a
/// credential from it must pass.
#[derive(Debug, Clone)]
pub struct UserIdp {
    issuer: String,
    jwks: JsonWebKeySet,
    audience: String,
    principal_claim: String,
    attribute_claims: Vec<String>,
}

impl UserIdp {
    /// `principal_claim` names the claim whose string value becomes the
    /// human principal (for example `sub` or `email`).
    pub fn new(issuer: String, jwks: JsonWebKeySet, audience: String, principal_claim: String) -> Self {
        Self {
            issuer,
            jwks,
            audience,
            principal_claim,
            attribute_claims: Vec::new(),
        }
    }

    /// The credential claims to carry as attributes of the principal (see `UserIdpConfig::attribute_claims`).
    pub fn with_attribute_claims(mut self, claims: Vec<String>) -> Self {
        self.attribute_claims = claims;
        self
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Verifies `credential` and returns the human principal it names.
    pub fn verify(&self, credential: &str) -> Result<String, UserAuthError> {
        self.verify_with_roles(credential).map(|(principal, _)| principal)
    }

    /// Verifies `credential` and returns the principal and its roles. Roles come from a `roles` claim, which must
    /// be an array of strings when present. `None` when the credential has no `roles` claim.
    pub fn verify_with_roles(&self, credential: &str) -> Result<(String, Option<Vec<String>>), UserAuthError> {
        self.verify_full(credential).map(|(principal, roles, _)| (principal, roles))
    }

    /// Verifies `credential` and returns the principal, its roles, and the configured attribute claims that the
    /// credential carries (a string claim each; absent claims are left out).
    pub fn verify_full(
        &self,
        credential: &str,
    ) -> Result<(String, Option<Vec<String>>, Option<std::collections::BTreeMap<String, String>>), UserAuthError> {
        let invalid = |reason: String| UserAuthError::InvalidCredential(reason);

        let header = decode_header(credential).map_err(|source| invalid(source.to_string()))?;
        // Pin the algorithm. Accepting whatever `alg` the header names
        // allows `none` or HMAC-with-public-key confusion.
        if header.alg != Algorithm::RS256 {
            return Err(invalid(format!("unsupported algorithm {:?}, only RS256 is accepted", header.alg)));
        }
        let kid = header.kid.ok_or_else(|| invalid("missing kid header".to_string()))?;
        let key = self.jwks.decoding_key(&kid).map_err(|source| invalid(source.to_string()))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);

        let data = decode::<Map<String, Value>>(credential, &key, &validation)
            .map_err(|source| invalid(source.to_string()))?;

        let principal = data
            .claims
            .get(&self.principal_claim)
            .and_then(Value::as_str)
            .filter(|principal| !principal.is_empty())
            .map(str::to_string)
            .ok_or_else(|| invalid(format!("missing string claim {:?}", self.principal_claim)))?;

        let roles = match data.claims.get("roles") {
            None => None,
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::to_string)
                            .ok_or_else(|| invalid("roles claim must be an array of strings".to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Some(_) => return Err(invalid("roles claim must be an array of strings".to_string())),
        };
        let mut attributes = std::collections::BTreeMap::new();
        for claim in &self.attribute_claims {
            if let Some(value) = data.claims.get(claim).and_then(Value::as_str).filter(|v| !v.is_empty()) {
                attributes.insert(claim.clone(), value.to_string());
            }
        }
        let attributes = (!attributes.is_empty()).then_some(attributes);
        Ok((principal, roles, attributes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    use rsa::RsaPrivateKey;

    const ISSUER: &str = "auth.corp.internal";
    const AUDIENCE: &str = "zt-gateway";

    fn keypair_pem() -> String {
        let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
        key.to_pkcs1_pem(LineEnding::LF).unwrap().to_string()
    }

    fn idp_for(private_pem: &str, kid: &str) -> UserIdp {
        let jwks = JsonWebKeySet::from_rsa_private_pem(kid.to_string(), private_pem.as_bytes()).unwrap();
        UserIdp::new(ISSUER.to_string(), jwks, AUDIENCE.to_string(), "email".to_string())
    }

    /// Signs a credential with `private_pem` under `kid`, using the given
    /// `iss`/`aud`/`exp`/`email` values.
    fn credential(private_pem: &str, kid: &str, iss: &str, aud: &str, exp: i64, email: &str) -> String {
        let claims = serde_json::json!({
            "iss": iss, "aud": aud, "exp": exp, "sub": "user-123", "email": email,
        });
        sign_raw(private_pem, kid, &claims)
    }

    fn sign_raw(private_pem: &str, kid: &str, claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap()).unwrap()
    }

    fn now() -> i64 {
        crate::now_unix_secs()
    }

    #[test]
    fn accepts_a_correctly_signed_credential_and_returns_the_principal() {
        let pem = keypair_pem();
        let idp = idp_for(&pem, "idp-1");
        let token = credential(&pem, "idp-1", ISSUER, AUDIENCE, now() + 300, "alice@corp.internal");
        assert_eq!(idp.verify(&token).unwrap(), "alice@corp.internal");
    }

    #[test]
    fn rejects_a_credential_signed_by_an_unknown_key() {
        let idp = idp_for(&keypair_pem(), "idp-1");
        let attacker = keypair_pem();
        let token = credential(&attacker, "idp-1", ISSUER, AUDIENCE, now() + 300, "ceo@corp.internal");
        assert!(matches!(idp.verify(&token), Err(UserAuthError::InvalidCredential(_))));
    }

    #[test]
    fn rejects_an_unknown_kid() {
        let pem = keypair_pem();
        let idp = idp_for(&pem, "idp-1");
        let token = credential(&pem, "idp-2", ISSUER, AUDIENCE, now() + 300, "alice@corp.internal");
        assert!(matches!(idp.verify(&token), Err(UserAuthError::InvalidCredential(_))));
    }

    #[test]
    fn rejects_a_wrong_issuer_or_audience() {
        let pem = keypair_pem();
        let idp = idp_for(&pem, "idp-1");
        let wrong_iss = credential(&pem, "idp-1", "evil.example", AUDIENCE, now() + 300, "a@x");
        let wrong_aud = credential(&pem, "idp-1", ISSUER, "other-service", now() + 300, "a@x");
        assert!(idp.verify(&wrong_iss).is_err());
        assert!(idp.verify(&wrong_aud).is_err());
    }

    #[test]
    fn rejects_an_expired_credential() {
        let pem = keypair_pem();
        let idp = idp_for(&pem, "idp-1");
        let token = credential(&pem, "idp-1", ISSUER, AUDIENCE, now() - 3600, "alice@corp.internal");
        assert!(idp.verify(&token).is_err());
    }

    #[test]
    fn rejects_a_credential_without_the_principal_claim() {
        let pem = keypair_pem();
        let idp = idp_for(&pem, "idp-1");
        let token = sign_raw(&pem, "idp-1", &serde_json::json!({"iss": ISSUER, "aud": AUDIENCE, "exp": now() + 300}));
        assert!(idp.verify(&token).is_err());
    }

    #[test]
    fn rejects_an_unsigned_alg_none_credential() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let idp = idp_for(&keypair_pem(), "idp-1");
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","kid":"idp-1"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({"iss": ISSUER, "aud": AUDIENCE, "exp": now() + 300, "email": "ceo@corp.internal"})
                .to_string(),
        );
        assert!(idp.verify(&format!("{header}.{payload}.")).is_err());
    }
}
