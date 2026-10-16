//! X.509 SVID issuance: a small in-process CA that signs CSRs into
//! short-lived client certificates carrying a SPIFFE ID SAN URI.
//!
//! Deliberately CSR-based: the workload generates its own keypair and only
//! ever sends a signing *request* — the private key never transits the
//! network or touches this process, mirroring how real CAs (and SPIRE)
//! work. See `docs/design/0001-tls-mtls-termination.md` for the full
//! trust-root-vs-issuance-capability design this trait boundary supports.

use std::path::Path;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequestParams,
    DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use time::{Duration, OffsetDateTime};

use crate::error::CaError;
use crate::registry::{CredentialCheck, Registry};

/// A freshly signed X.509 SVID (leaf certificate), PEM-encoded. No private
/// key here — the CA never had one to include.
#[derive(Debug, Clone)]
pub struct SignedCert {
    pub cert_pem: String,
    pub expires_at: i64,
}

/// How `zt-gateway` obtains its X.509 signing capability. A trait boundary
/// for the same reason [`crate::IdentityProvider`] is one: [`LocalCa`] is
/// the only v0.1 implementation, but a real CA/SPIRE-backed one can replace
/// it later without touching `obo.rs` or the HTTP layer.
pub trait CertificateAuthority {
    /// This CA's own certificate (DER) — the trust root for verifying
    /// client certs it issued.
    fn root_cert_der(&self) -> &[u8];

    /// Validates `credential` against `requester_workload_name`'s
    /// registered bootstrap token, checks the CSR's SAN URI matches that
    /// workload's registered SPIFFE ID exactly, then signs it.
    fn sign_csr(
        &self,
        requester_workload_name: &str,
        csr_pem: &str,
        credential: &str,
    ) -> Result<SignedCert, CaError>;
}

/// v0.1's only [`CertificateAuthority`]: an in-process, self-signed root.
/// Holds its own keypair, deliberately separate from [`crate::LocalIssuer`]'s
/// JWT-signing key — compromising one shouldn't compromise the other.
pub struct LocalCa {
    registry: Registry,
    ca_cert: Certificate,
    ca_key: KeyPair,
    ttl_seconds: i64,
}

impl LocalCa {
    /// Generates a fresh, self-signed CA root. Not persisted anywhere —
    /// restarting the gateway invalidates every certificate it issued.
    /// Fine for local dev; a real deployment should use [`Self::load`].
    pub fn generate(registry: Registry, ttl_seconds: i64) -> Result<Self, CaError> {
        let ca_key = KeyPair::generate().map_err(|source| CaError::Signing(source.to_string()))?;

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "zt-gateway local CA");

        let mut params =
            CertificateParams::new(Vec::<String>::new()).map_err(|source| CaError::Signing(source.to_string()))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name = distinguished_name;

        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|source| CaError::Signing(source.to_string()))?;

        Ok(Self { registry, ca_cert, ca_key, ttl_seconds })
    }

    /// Loads an existing CA certificate + private key from disk — the
    /// persistent-CA path for a real deployment (or for a fleet of
    /// `zt-gateway` instances that should all issue from the same root).
    pub fn load(registry: Registry, cert_path: &Path, key_path: &Path, ttl_seconds: i64) -> Result<Self, CaError> {
        let cert_pem = std::fs::read_to_string(cert_path).map_err(|source| CaError::Signing(source.to_string()))?;
        let key_pem = std::fs::read_to_string(key_path).map_err(|source| CaError::Signing(source.to_string()))?;

        let ca_key = KeyPair::from_pem(&key_pem).map_err(|source| CaError::Signing(source.to_string()))?;
        let ca_params =
            CertificateParams::from_ca_cert_pem(&cert_pem).map_err(|source| CaError::Signing(source.to_string()))?;
        // Re-signing with the loaded key reconstructs a `Certificate` object
        // usable as `signed_by`'s issuer (rcgen has no other way to turn a
        // loaded CA cert + key back into that type) — preserves the
        // original subject/validity/serial that `from_ca_cert_pem` parsed
        // out of the file, so this is cryptographically equivalent to the
        // certificate on disk even though the DER bytes are re-serialized.
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(|source| CaError::Signing(source.to_string()))?;

        Ok(Self { registry, ca_cert, ca_key, ttl_seconds })
    }
}

impl CertificateAuthority for LocalCa {
    fn root_cert_der(&self) -> &[u8] {
        self.ca_cert.der()
    }

    fn sign_csr(&self, requester_workload_name: &str, csr_pem: &str, credential: &str) -> Result<SignedCert, CaError> {
        let requester = match self.registry.check_bootstrap_token(requester_workload_name, credential) {
            CredentialCheck::Ok(entry) => entry,
            CredentialCheck::UnknownWorkload => {
                return Err(CaError::UnknownWorkload(requester_workload_name.to_string()))
            }
            CredentialCheck::InvalidCredential => return Err(CaError::InvalidBootstrapToken),
        };

        // The CSR is used only for its public key (proof of possession) and
        // to carry the requested SAN for the mismatch check below — the
        // leaf is built from scratch below, so nothing else in the CSR
        // (its own distinguished_name, validity, etc.) ever reaches the
        // signed certificate.
        let csr_params = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|source| CaError::MalformedCsr(source.to_string()))?;

        validate_csr_sans(&csr_params.params.subject_alt_names)?;

        let expected = requester.spiffe_id.to_string();
        let requested_uri = csr_params.params.subject_alt_names.iter().find_map(|san| match san {
            SanType::URI(uri) => Some(uri.clone()),
            _ => None,
        });
        let san_uri = match requested_uri {
            Some(uri) if uri.to_string() == expected => uri,
            Some(uri) => {
                return Err(CaError::SanMismatch {
                    requested: uri.to_string(),
                    expected,
                })
            }
            None => {
                return Err(CaError::SanMismatch {
                    requested: String::new(),
                    expected,
                })
            }
        };

        let not_before = OffsetDateTime::now_utc();
        let not_after = not_before + Duration::seconds(self.ttl_seconds);

        // Built from scratch (not derived from `csr_params.params`): the
        // leaf's identity, validity and constraints all come from this
        // CA's policy, not from whatever a workload put in its CSR. Only
        // the SAN URI that was just checked against the registry above
        // survives into it, plus the CSR's public key below.
        let mut leaf_params = CertificateParams::new(Vec::<String>::new())
            .map_err(|source| CaError::Signing(source.to_string()))?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, requester_workload_name);
        leaf_params.distinguished_name = distinguished_name;
        leaf_params.subject_alt_names = vec![SanType::URI(san_uri)];
        leaf_params.not_before = not_before;
        leaf_params.not_after = not_after;
        // X.509-SVID leaf constraints: not a CA, and scoped to exactly the
        // key usages/EKUs a workload identity needs for mTLS.
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params.key_usages =
            vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment, KeyUsagePurpose::KeyAgreement];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth, ExtendedKeyUsagePurpose::ServerAuth];

        let signed = leaf_params
            .signed_by(&csr_params.public_key, &self.ca_cert, &self.ca_key)
            .map_err(|source| CaError::Signing(source.to_string()))?;

        Ok(SignedCert {
            cert_pem: signed.pem(),
            expires_at: not_after.unix_timestamp(),
        })
    }
}

/// Rejects a CSR whose SAN list isn't exactly what the X.509-SVID spec
/// allows a workload to request: a single URI SAN, nothing else. A CSR
/// with a DNS/IP/email SAN, an `OtherName`, or more than one URI SAN is
/// rejected outright rather than having the extras silently dropped — the
/// workload asked for an identity this CA won't issue, and papering over
/// that is a worse failure mode than an explicit error.
fn validate_csr_sans(sans: &[SanType]) -> Result<(), CaError> {
    let uri_count = sans.iter().filter(|san| matches!(san, SanType::URI(_))).count();
    if uri_count != sans.len() {
        return Err(CaError::NonUriSanInCsr);
    }
    if uri_count > 1 {
        return Err(CaError::MultipleUriSans);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spiffe_id::SpiffeId;

    const INVENTORY: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";

    fn test_registry() -> Registry {
        Registry::from_yaml_str(&format!(
            r#"
trust_domain: chakra.internal
workloads:
  - name: inventory-svc
    spiffe_id: {INVENTORY}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: inventory-secret
"#
        ))
        .unwrap()
    }

    /// Builds a CSR the way a workload would: its own fresh keypair, a SAN
    /// URI carrying the SPIFFE ID it's requesting a cert for.
    fn build_csr(spiffe_id: &str) -> String {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![SanType::URI(spiffe_id.try_into().unwrap())];
        params.serialize_request(&key_pair).unwrap().pem().unwrap()
    }

    #[test]
    fn signs_a_csr_whose_san_matches_the_authenticated_workload() {
        let ca = LocalCa::generate(test_registry(), 3600).unwrap();
        let csr = build_csr(INVENTORY);

        let signed = ca.sign_csr("inventory-svc", &csr, "inventory-secret").unwrap();
        assert!(signed.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(signed.expires_at > crate::now_unix_secs());
    }

    #[test]
    fn rejects_a_csr_requesting_a_different_identity() {
        let ca = LocalCa::generate(test_registry(), 3600).unwrap();
        let csr = build_csr("spiffe://chakra.internal/ns/orders/sa/orders-svc");

        let err = ca.sign_csr("inventory-svc", &csr, "inventory-secret").unwrap_err();
        assert!(matches!(err, CaError::SanMismatch { .. }));
    }

    #[test]
    fn rejects_a_wrong_bootstrap_token() {
        let ca = LocalCa::generate(test_registry(), 3600).unwrap();
        let csr = build_csr(INVENTORY);

        let err = ca.sign_csr("inventory-svc", &csr, "wrong").unwrap_err();
        assert!(matches!(err, CaError::InvalidBootstrapToken));
    }

    #[test]
    fn rejects_an_unknown_workload() {
        let ca = LocalCa::generate(test_registry(), 3600).unwrap();
        let csr = build_csr(INVENTORY);

        let err = ca.sign_csr("ghost-svc", &csr, "anything").unwrap_err();
        assert!(matches!(err, CaError::UnknownWorkload(name) if name == "ghost-svc"));
    }

    #[test]
    fn rejects_a_malformed_csr() {
        let ca = LocalCa::generate(test_registry(), 3600).unwrap();
        let err = ca.sign_csr("inventory-svc", "not a csr", "inventory-secret").unwrap_err();
        assert!(matches!(err, CaError::MalformedCsr(_)));
    }

    #[test]
    fn root_cert_der_is_non_empty_and_stable_across_calls() {
        let ca = LocalCa::generate(test_registry(), 3600).unwrap();
        let a = ca.root_cert_der().to_vec();
        let b = ca.root_cert_der().to_vec();
        assert!(!a.is_empty());
        assert_eq!(a, b);
    }

    #[test]
    fn load_round_trips_a_generated_ca_through_pem_files() {
        let dir = std::env::temp_dir().join(format!("zt-gateway-ca-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("ca-cert.pem");
        let key_path = dir.join("ca-key.pem");

        let original = LocalCa::generate(test_registry(), 3600).unwrap();
        std::fs::write(&cert_path, original.ca_cert.pem()).unwrap();
        std::fs::write(&key_path, original.ca_key.serialize_pem()).unwrap();

        let loaded = LocalCa::load(test_registry(), &cert_path, &key_path, 3600).unwrap();
        let csr = build_csr(INVENTORY);
        loaded.sign_csr("inventory-svc", &csr, "inventory-secret").unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn spiffe_id_parses_from_the_san_used_in_tests() {
        // Sanity check that the SAN URIs used above are themselves valid
        // SpiffeIds, so a SAN-mismatch test failure can't be masked by a
        // typo in the test fixture's SPIFFE ID string.
        let _: SpiffeId = INVENTORY.parse().unwrap();
    }
}
