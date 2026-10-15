//! Signing and verifying JWT SVIDs (the OBO delegation token).
//!
//! Deliberately split into two narrow types: [`JwtSigner`] only signs,
//! [`JwtVerifier`] only checks the RS256 signature and decodes claims — it
//! does **not** check `exp`/`aud`. Those checks happen centrally in
//! `obo::validate` so each failure can map to a precise, distinct
//! `DenyReason` instead of a single opaque "token invalid" error.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::JwtError;

/// The claims carried by a JWT SVID, per ADR-0007: who is delegating
/// (`sub`), who it's delegating to (`aud`), and the token's validity window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OboClaims {
    pub sub: String,
    pub aud: Vec<String>,
    /// Unix seconds.
    pub exp: i64,
    /// Unix seconds.
    pub iat: i64,
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
            exp,
            iat: 0,
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
}
