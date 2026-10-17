//! Signing and verifying JWT SVIDs (the OBO delegation token).
//!
//! Deliberately split into two narrow types: [`JwtSigner`] only signs,
//! [`JwtVerifier`] only checks the RS256 signature and decodes claims — it
//! does **not** check `exp`/`aud`. Those checks happen centrally in
//! `obo::validate` so each failure can map to a precise, distinct
//! `DenyReason` instead of a single opaque "token invalid" error.

use base64::engine::{general_purpose, Engine as _};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::JwtError;

/// Computes the RFC 8705 `x5t#S256` confirmation value for a client
/// certificate: the SHA-256 digest of its DER encoding, base64url-encoded
/// with no padding. Deterministic (same cert DER always yields the same
/// thumbprint) and collision-resistant enough that two distinct certs are
/// never expected to collide — this is what [`CertBinding::x5t_s256`]
/// carries and what cert-binding validation (`obo::validate_with_cert_binding`)
/// compares the presented TLS client cert's thumbprint against.
pub fn compute_cert_thumbprint_x5t_s256(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let hash = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// The claims carried by a JWT SVID, per ADR-0007: who is delegating
/// (`sub`), who it's delegating to (`aud`), and the token's validity window.
///
/// Extended per RFC 8693 (token exchange) to optionally carry a signed
/// delegation chain: `user` is the originating principal who kicked off the
/// delegation, `act` is a recursively nested chain of intermediate actors
/// (each hop appending itself), `cnf` binds the token to a client
/// certificate (RFC 8705, consumed by cert-binding validation), and `nbf`/
/// `jti` support not-before and replay-cache checks. All five are optional
/// and skip serialization when absent, so tokens minted without delegation
/// are byte-for-byte unchanged from before this extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OboClaims {
    pub sub: String,
    pub aud: Vec<String>,
    /// Signed originating principal (who started the delegation), per RFC
    /// 8693. `None` for a plain, non-delegated OBO token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// RFC 8693 delegation chain: the actor that most recently acted on
    /// behalf of `user`, which may itself nest further actors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActClaim>>,
    /// Unix seconds.
    pub exp: i64,
    /// Unix seconds.
    pub iat: i64,
    /// Not-before (Unix seconds); `None` means no not-before check applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// JWT ID, for replay-cache checks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Certificate binding (RFC 8705), checked by Task 8's cert-binding
    /// validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CertBinding>,
    /// Issuer claim (Task 2/F15): identifies who minted this token, as a
    /// SPIFFE ID (e.g. `spiffe://chakra.internal`). `None` for old tokens
    /// minted before this claim existed — `obo::validate` treats a missing
    /// `iss` as backward-compatible, not as a deny.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
}

impl OboClaims {
    /// Number of delegation hops recorded in the `act` chain — 0 when
    /// there's no `act` claim at all, 1 for a single intermediate actor,
    /// and so on for each further level of nesting.
    pub fn delegation_depth(&self) -> usize {
        let mut depth = 0;
        let mut act = self.act.as_deref();
        while let Some(a) = act {
            depth += 1;
            act = a.act.as_deref();
        }
        depth
    }

    /// The full chain of identities that have held this token, outermost
    /// first: `[sub, act.sub, act.act.sub, ...]`. With no `act` claim this
    /// is just `[sub]`.
    pub fn delegation_chain(&self) -> Vec<String> {
        let mut chain = vec![self.sub.clone()];
        let mut act = self.act.as_deref();
        while let Some(a) = act {
            chain.push(a.sub.clone());
            act = a.act.as_deref();
        }
        chain
    }

    /// The signed originating user principal, if this token carries one.
    pub fn extract_user_principal(&self) -> Option<String> {
        self.user.clone()
    }
}

/// One hop of an RFC 8693 delegation chain: `{"sub": "...", "act": {...}}`.
/// Each `act` claim may itself nest a further `act`, recording every actor
/// that has acted on behalf of the original `user` in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActClaim {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActClaim>>,
}

/// Certificate binding confirmation key (RFC 8705): the base64url-encoded
/// SHA-256 thumbprint of the client certificate this token is bound to.
/// Serializes under the standard `x5t#S256` JSON field name, not the Rust
/// field name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertBinding {
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: String,
}

/// Signs JWT SVIDs with an RS256 private key.
///
/// `kid` is `None` for the original single-key flow ([`Self::from_rsa_pem`])
/// and `Some` when built via [`Self::from_rsa_pem_with_kid`] — the latter
/// stamps every signed token's header with that `kid`, so a verifier
/// holding multiple keys (see [`JwtVerifier::from_jwks_entries`]) knows
/// which one to use without changing anything about how the signature
/// itself is produced.
pub struct JwtSigner {
    encoding_key: EncodingKey,
    kid: Option<String>,
}

impl JwtSigner {
    pub fn from_rsa_pem(private_key_pem: &[u8]) -> Result<Self, JwtError> {
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|source| JwtError::InvalidKey(source.to_string()))?;
        Ok(Self { encoding_key, kid: None })
    }

    /// Like [`Self::from_rsa_pem`], but every token this signer produces
    /// carries `kid` in its JWT header — required for cross-gateway
    /// verification against a JWKS with more than one registered key.
    pub fn from_rsa_pem_with_kid(private_key_pem: &[u8], kid: String) -> Result<Self, JwtError> {
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|source| JwtError::InvalidKey(source.to_string()))?;
        Ok(Self {
            encoding_key,
            kid: Some(kid),
        })
    }

    pub fn sign(&self, claims: &OboClaims) -> Result<String, JwtError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = self.kid.clone();
        let token = jsonwebtoken::encode(&header, claims, &self.encoding_key)?;
        Ok(token)
    }
}

/// Verifies the RS256 signature on JWT SVIDs and decodes their claims.
///
/// Holds one or more keys, each optionally keyed by `kid`. With exactly one
/// key and no `kid` registered (the original [`Self::from_rsa_pem`] flow),
/// verification behaves exactly as before — single key, no `kid` header
/// required. With more than one key (see [`Self::from_jwks_entries`]), the
/// token's `kid` header is mandatory and selects which registered key
/// verifies the signature; never both validated speculatively.
pub struct JwtVerifier {
    keys: Vec<(Option<String>, DecodingKey)>,
}

impl JwtVerifier {
    pub fn from_rsa_pem(public_key_pem: &[u8]) -> Result<Self, JwtError> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem)
            .map_err(|source| JwtError::InvalidKey(source.to_string()))?;
        Ok(Self {
            keys: vec![(None, decoding_key)],
        })
    }

    /// Builds a verifier that trusts every key in a JWKS-style key set,
    /// each identified by `kid` — this is what lets a token signed by one
    /// gateway's active key verify successfully at another gateway that
    /// loaded the same shared JWKS but signs with a different active key.
    pub fn from_jwks_entries(entries: Vec<(String, DecodingKey)>) -> Self {
        Self {
            keys: entries.into_iter().map(|(kid, key)| (Some(kid), key)).collect(),
        }
    }

    /// Verifies the signature and returns the claims. Does not check
    /// expiry or audience — see the module doc comment for why.
    pub fn verify_signature(&self, token: &str) -> Result<OboClaims, JwtError> {
        let decoding_key = self.select_key(token)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        let data = jsonwebtoken::decode::<OboClaims>(token, decoding_key, &validation)?;
        Ok(data.claims)
    }

    /// Resolves which registered key should verify `token`'s signature.
    /// Signed claims are never trusted before this check — the `kid`
    /// comes from the (unverified) header, but it only ever *selects* a
    /// key to verify against; it never substitutes for the signature
    /// check itself.
    fn select_key(&self, token: &str) -> Result<&DecodingKey, JwtError> {
        let header = jsonwebtoken::decode_header(token)?;
        match &header.kid {
            Some(kid) => self
                .keys
                .iter()
                .find(|(registered_kid, _)| registered_kid.as_deref() == Some(kid.as_str()))
                .map(|(_, key)| key)
                .ok_or_else(|| JwtError::UnknownKeyId(kid.clone())),
            None if self.keys.len() == 1 => Ok(&self.keys[0].1),
            None => Err(JwtError::MissingKeyId),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
    use rsa::{RsaPrivateKey, RsaPublicKey};

    /// Generates a fresh 2048-bit TEST-ONLY RSA keypair as PKCS#1 PEM bytes.
    /// Never do this in production code — real key material comes from
    /// config/SPIRE, not `RsaPrivateKey::new` at request time.
    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::rngs::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation");
        let public_key = RsaPublicKey::from(&private_key);

        let private_pem = private_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("encode private key");
        let public_pem = public_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("encode public key");

        (private_pem.as_bytes().to_vec(), public_pem.into_bytes())
    }

    fn sample_claims(exp: i64) -> OboClaims {
        OboClaims {
            sub: "spiffe://chakra.internal/ns/orders/sa/orders-svc".to_string(),
            aud: vec!["spiffe://chakra.internal/ns/inventory/sa/inventory-svc".to_string()],
            user: None,
            act: None,
            exp,
            iat: 0,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        }
    }

    #[test]
    fn signs_and_verifies_round_trip() {
        let (private_pem, public_pem) = generate_keypair();
        let signer = JwtSigner::from_rsa_pem(&private_pem).unwrap();
        let verifier = JwtVerifier::from_rsa_pem(&public_pem).unwrap();

        let claims = sample_claims(9_999_999_999);
        let token = signer.sign(&claims).unwrap();
        let decoded = verifier.verify_signature(&token).unwrap();

        assert_eq!(decoded, claims);
    }

    #[test]
    fn rejects_a_token_signed_by_a_different_key() {
        let (private_pem_a, _) = generate_keypair();
        let (_, public_pem_b) = generate_keypair();

        let signer = JwtSigner::from_rsa_pem(&private_pem_a).unwrap();
        let verifier = JwtVerifier::from_rsa_pem(&public_pem_b).unwrap();

        let token = signer.sign(&sample_claims(9_999_999_999)).unwrap();
        assert!(verifier.verify_signature(&token).is_err());
    }

    #[test]
    fn verify_signature_ignores_expiry_by_design() {
        let (private_pem, public_pem) = generate_keypair();
        let signer = JwtSigner::from_rsa_pem(&private_pem).unwrap();
        let verifier = JwtVerifier::from_rsa_pem(&public_pem).unwrap();

        // exp = 1 (long expired). verify_signature should still succeed —
        // expiry is obo::validate's job, not JwtVerifier's.
        let token = signer.sign(&sample_claims(1)).unwrap();
        assert!(verifier.verify_signature(&token).is_ok());
    }

    #[test]
    fn from_rsa_pem_signs_without_a_kid_header_by_default() {
        let (private_pem, _) = generate_keypair();
        let signer = JwtSigner::from_rsa_pem(&private_pem).unwrap();
        let token = signer.sign(&sample_claims(9_999_999_999)).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert!(header.kid.is_none());
    }

    #[test]
    fn from_rsa_pem_with_kid_stamps_the_header() {
        let (private_pem, _) = generate_keypair();
        let signer = JwtSigner::from_rsa_pem_with_kid(&private_pem, "key-1".to_string()).unwrap();
        let token = signer.sign(&sample_claims(9_999_999_999)).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.kid, Some("key-1".to_string()));
    }

    #[test]
    fn from_jwks_entries_verifies_the_matching_kid() {
        let (private_pem_1, public_pem_1) = generate_keypair();
        let (private_pem_2, public_pem_2) = generate_keypair();

        let decoding_key_1 = DecodingKey::from_rsa_pem(&public_pem_1).unwrap();
        let decoding_key_2 = DecodingKey::from_rsa_pem(&public_pem_2).unwrap();
        let verifier = JwtVerifier::from_jwks_entries(vec![
            ("key-1".to_string(), decoding_key_1),
            ("key-2".to_string(), decoding_key_2),
        ]);

        let signer_1 = JwtSigner::from_rsa_pem_with_kid(&private_pem_1, "key-1".to_string()).unwrap();
        let signer_2 = JwtSigner::from_rsa_pem_with_kid(&private_pem_2, "key-2".to_string()).unwrap();

        let token_1 = signer_1.sign(&sample_claims(9_999_999_999)).unwrap();
        let token_2 = signer_2.sign(&sample_claims(9_999_999_999)).unwrap();

        assert!(verifier.verify_signature(&token_1).is_ok());
        assert!(verifier.verify_signature(&token_2).is_ok());
    }

    #[test]
    fn from_jwks_entries_rejects_an_unknown_kid() {
        let (_private_pem_1, public_pem_1) = generate_keypair();
        let (private_pem_unregistered, _) = generate_keypair();

        let decoding_key_1 = DecodingKey::from_rsa_pem(&public_pem_1).unwrap();
        let verifier = JwtVerifier::from_jwks_entries(vec![("key-1".to_string(), decoding_key_1)]);

        let rogue_signer =
            JwtSigner::from_rsa_pem_with_kid(&private_pem_unregistered, "unknown-kid".to_string()).unwrap();
        let token = rogue_signer.sign(&sample_claims(9_999_999_999)).unwrap();

        let err = verifier.verify_signature(&token).unwrap_err();
        assert!(matches!(err, JwtError::UnknownKeyId(kid) if kid == "unknown-kid"));
    }

    #[test]
    fn from_jwks_entries_rejects_a_token_with_no_kid_when_multiple_keys_are_registered() {
        let (private_pem_1, public_pem_1) = generate_keypair();
        let (_private_pem_2, public_pem_2) = generate_keypair();

        let decoding_key_1 = DecodingKey::from_rsa_pem(&public_pem_1).unwrap();
        let decoding_key_2 = DecodingKey::from_rsa_pem(&public_pem_2).unwrap();
        let verifier = JwtVerifier::from_jwks_entries(vec![
            ("key-1".to_string(), decoding_key_1),
            ("key-2".to_string(), decoding_key_2),
        ]);

        // Signed the old way — no `kid` header at all. With more than one
        // registered key the verifier has no way to know which to try, so
        // this must be a hard error, never a silent fallback to "guess".
        let signer = JwtSigner::from_rsa_pem(&private_pem_1).unwrap();
        let token = signer.sign(&sample_claims(9_999_999_999)).unwrap();

        let err = verifier.verify_signature(&token).unwrap_err();
        assert!(matches!(err, JwtError::MissingKeyId));
    }

    // --- RFC 8693 delegation chain (Task 3) ---

    #[test]
    fn delegation_depth_is_zero_with_no_act_claim() {
        let claims = sample_claims(2000);
        assert_eq!(claims.delegation_depth(), 0);
        assert_eq!(
            claims.delegation_chain(),
            vec!["spiffe://chakra.internal/ns/orders/sa/orders-svc".to_string()]
        );
    }

    #[test]
    fn delegation_depth_counts_nested_act_hops() {
        let mut claims = sample_claims(2000);
        claims.sub = "spiffe://backend".to_string();
        claims.user = Some("spiffe://alice".to_string());
        claims.act = Some(Box::new(ActClaim {
            sub: "spiffe://gateway-a".to_string(),
            act: Some(Box::new(ActClaim {
                sub: "spiffe://gateway-b".to_string(),
                act: None,
            })),
        }));

        assert_eq!(claims.delegation_depth(), 2);
    }

    #[test]
    fn delegation_chain_extracts_all_subs_in_order() {
        let mut claims = sample_claims(2000);
        claims.sub = "spiffe://backend".to_string();
        claims.user = Some("spiffe://alice".to_string());
        claims.act = Some(Box::new(ActClaim {
            sub: "spiffe://gw-a".to_string(),
            act: Some(Box::new(ActClaim {
                sub: "spiffe://gw-b".to_string(),
                act: None,
            })),
        }));

        assert_eq!(
            claims.delegation_chain(),
            vec![
                "spiffe://backend".to_string(),
                "spiffe://gw-a".to_string(),
                "spiffe://gw-b".to_string(),
            ]
        );
    }

    #[test]
    fn extract_user_principal_returns_the_user_claim() {
        let mut claims = sample_claims(2000);
        claims.user = Some("spiffe://alice".to_string());
        assert_eq!(claims.extract_user_principal(), Some("spiffe://alice".to_string()));

        let no_user_claims = sample_claims(2000);
        assert_eq!(no_user_claims.extract_user_principal(), None);
    }

    #[test]
    fn claims_serialization_skips_none_optional_fields() {
        let claims = sample_claims(2000);
        let json = serde_json::to_string(&claims).unwrap();

        assert!(!json.contains("\"user\""));
        assert!(!json.contains("\"act\""));
        assert!(!json.contains("\"cnf\""));
        assert!(!json.contains("\"nbf\""));
        assert!(!json.contains("\"jti\""));
    }

    #[test]
    fn claims_serialization_includes_set_optional_fields() {
        let mut claims = sample_claims(2000);
        claims.user = Some("spiffe://alice".to_string());
        claims.act = Some(Box::new(ActClaim {
            sub: "spiffe://gw-a".to_string(),
            act: None,
        }));
        claims.nbf = Some(900);
        claims.jti = Some("token-id-1".to_string());
        claims.cnf = Some(CertBinding {
            x5t_s256: "base64url_thumbprint".to_string(),
        });

        let json = serde_json::to_string(&claims).unwrap();
        let round_tripped: OboClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped, claims);
    }

    #[test]
    fn cert_binding_serializes_with_the_rfc_8705_field_name() {
        let binding = CertBinding {
            x5t_s256: "base64url_thumbprint".to_string(),
        };
        let json = serde_json::to_string(&binding).unwrap();
        assert!(json.contains("\"x5t#S256\""));
        assert!(!json.contains("x5t_s256"));

        let round_tripped: CertBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped, binding);
    }

    // --- RFC 8705 certificate-binding thumbprint (Task 8) ---

    /// A fresh self-signed cert's DER bytes, generated the same way
    /// `ServerCertificate::generate_ephemeral` does in `tls.rs` — this
    /// module has no fixture files of its own, so a freshly generated
    /// cert stands in for "a real client cert" here.
    fn generate_cert_der(subject_alt_name: &str) -> Vec<u8> {
        let certified_key = rcgen::generate_simple_self_signed(vec![subject_alt_name.to_string()]).unwrap();
        certified_key.cert.der().to_vec()
    }

    #[test]
    fn test_compute_cert_thumbprint_x5t_s256() {
        let cert_der = generate_cert_der("client-a");
        let thumbprint = compute_cert_thumbprint_x5t_s256(&cert_der);

        // base64url (no padding): only alphanumerics, '-', and '_'.
        assert!(!thumbprint.is_empty());
        assert!(thumbprint.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(!thumbprint.contains('='));

        // Deterministic: hashing the same DER bytes again gives the same
        // thumbprint.
        let thumbprint2 = compute_cert_thumbprint_x5t_s256(&cert_der);
        assert_eq!(thumbprint, thumbprint2);
    }

    #[test]
    fn test_different_certs_different_thumbprints() {
        let cert_a = generate_cert_der("client-a");
        let cert_b = generate_cert_der("client-b");

        let thumb_a = compute_cert_thumbprint_x5t_s256(&cert_a);
        let thumb_b = compute_cert_thumbprint_x5t_s256(&cert_b);

        assert_ne!(thumb_a, thumb_b);
    }

    #[test]
    fn old_tokens_without_delegation_fields_still_deserialize() {
        // Shape produced by the pre-Task-3 `OboClaims` — no user/act/cnf/
        // nbf/jti at all. Backward compatibility requires this to still
        // deserialize cleanly, with the new fields defaulting to `None`.
        let old_json = r#"{"sub":"spiffe://test","aud":["spiffe://test-aud"],"exp":2000,"iat":1000}"#;
        let claims: OboClaims = serde_json::from_str(old_json).unwrap();

        assert_eq!(claims.sub, "spiffe://test");
        assert_eq!(claims.aud, vec!["spiffe://test-aud".to_string()]);
        assert_eq!(claims.exp, 2000);
        assert_eq!(claims.iat, 1000);
        assert_eq!(claims.user, None);
        assert_eq!(claims.act, None);
        assert_eq!(claims.nbf, None);
        assert_eq!(claims.jti, None);
        assert_eq!(claims.cnf, None);
        assert_eq!(claims.delegation_depth(), 0);
    }
}
