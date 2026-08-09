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
pub struct JwtSigner {
    encoding_key: EncodingKey,
}

impl JwtSigner {
    pub fn from_rsa_pem(private_key_pem: &[u8]) -> Result<Self, JwtError> {
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem)
            .map_err(|source| JwtError::InvalidKey(source.to_string()))?;
        Ok(Self { encoding_key })
    }

    pub fn sign(&self, claims: &OboClaims) -> Result<String, JwtError> {
        let header = Header::new(Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, claims, &self.encoding_key)?;
        Ok(token)
    }
}

/// Verifies the RS256 signature on JWT SVIDs and decodes their claims.
pub struct JwtVerifier {
    decoding_key: DecodingKey,
}

impl JwtVerifier {
    pub fn from_rsa_pem(public_key_pem: &[u8]) -> Result<Self, JwtError> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem)
            .map_err(|source| JwtError::InvalidKey(source.to_string()))?;
        Ok(Self { decoding_key })
    }

    /// Verifies the signature and returns the claims. Does not check
    /// expiry or audience — see the module doc comment for why.
    pub fn verify_signature(&self, token: &str) -> Result<OboClaims, JwtError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        let data = jsonwebtoken::decode::<OboClaims>(token, &self.decoding_key, &validation)?;
        Ok(data.claims)
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
}
