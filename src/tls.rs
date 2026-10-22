//! Server-side TLS certificate material: load it from disk, or generate an
//! ephemeral self-signed one for local development, and build a
//! `rustls::ServerConfig` from it — optionally with client-certificate
//! verification (mTLS) layered in, for the trust root resolved in
//! `main.rs` (self-issued, externally trusted, or ephemeral-dev; see
//! `docs/design/0001-tls-mtls-termination.md`).

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;

use crate::error::TlsError;

/// A server certificate chain + the private key that signs for it.
#[derive(Debug)]
pub struct ServerCertificate {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl Clone for ServerCertificate {
    // `PrivateKeyDer` isn't `Clone`, so copy the key via `clone_key`. The F10
    // fix needs one certificate for both the proxy and admin acceptors.
    fn clone(&self) -> Self {
        Self {
            cert_chain: self.cert_chain.clone(),
            private_key: self.private_key.clone_key(),
        }
    }
}

impl ServerCertificate {
    /// Loads a PEM certificate chain and private key from disk.
    pub fn load(cert_path: &Path, key_path: &Path) -> Result<Self, TlsError> {
        let cert_chain = load_certs(cert_path)?;
        let private_key = load_private_key(key_path)?;
        Ok(Self { cert_chain, private_key })
    }

    /// Generates a fresh, self-signed certificate for local development.
    /// Not something a real client should be asked to trust long-term —
    /// same spirit as `LocalIssuer::generate`'s ephemeral JWT signing key.
    pub fn generate_ephemeral(subject_alt_names: Vec<String>) -> Result<Self, TlsError> {
        let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
            .map_err(|source| TlsError::Generation(source.to_string()))?;

        let cert_der = certified_key.cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified_key.key_pair.serialize_der(),
        ));

        Ok(Self {
            cert_chain: vec![cert_der],
            private_key: key_der,
        })
    }
}

/// Loads every certificate found in a PEM file. Used both for a server's
/// own cert chain and — from `main.rs` — for reading a trust-root CA cert
/// off disk when this gateway only *verifies* against a CA it doesn't
/// control (see the "verify-only mode" case in the design doc).
pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err(TlsError::NoCertsFound(path.display().to_string()));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| TlsError::NoKeyFound(path.display().to_string()))
}

/// Builds a client-certificate verifier trusting exactly `trust_root_der`.
/// `allow_unauthenticated` is what distinguishes `ClientAuth::Optional`
/// (connections without a client cert are still accepted — they just won't
/// get a verified `source_principal`) from `ClientAuth::Required` (the TLS
/// handshake itself fails without one).
pub fn build_client_cert_verifier(
    trust_root_der: &[u8],
    allow_unauthenticated: bool,
) -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(trust_root_der.to_vec()))
        .map_err(TlsError::RustlsConfig)?;

    let mut builder = WebPkiClientVerifier::builder(Arc::new(roots));
    if allow_unauthenticated {
        builder = builder.allow_unauthenticated();
    }
    builder
        .build()
        .map_err(|source| TlsError::Generation(source.to_string()))
}

/// Builds a `rustls::ServerConfig` for `server_cert`. `client_cert_verifier`
/// being `None` means `ClientAuth::None` — no client certificate requested,
/// the plain-TLS Phase 1 behavior. The `ring` crypto provider is selected
/// explicitly rather than relying on a process-wide default having been
/// installed — keeps this function callable from anywhere (including
/// tests) without ordering requirements on startup code.
pub fn build_server_config(
    server_cert: ServerCertificate,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
) -> Result<rustls::ServerConfig, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(TlsError::RustlsConfig)?;

    let builder = match client_cert_verifier {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    };

    builder
        .with_single_cert(server_cert.cert_chain, server_cert.private_key)
        .map_err(TlsError::RustlsConfig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_cert_has_a_non_empty_chain_and_key() {
        let cert = ServerCertificate::generate_ephemeral(vec!["localhost".to_string()]).unwrap();
        assert_eq!(cert.cert_chain.len(), 1);
    }

    #[test]
    fn ephemeral_cert_builds_a_server_config() {
        let cert = ServerCertificate::generate_ephemeral(vec!["localhost".to_string()]).unwrap();
        build_server_config(cert, None).unwrap();
    }

    #[test]
    fn ephemeral_cert_builds_a_server_config_with_a_client_verifier() {
        let server_cert = ServerCertificate::generate_ephemeral(vec!["localhost".to_string()]).unwrap();
        let ca = ServerCertificate::generate_ephemeral(vec!["test-ca".to_string()]).unwrap();
        let verifier = build_client_cert_verifier(&ca.cert_chain[0], true).unwrap();
        build_server_config(server_cert, Some(verifier)).unwrap();
    }

    #[test]
    fn loading_a_missing_cert_file_is_an_io_error() {
        let err = ServerCertificate::load(Path::new("does-not-exist-cert.pem"), Path::new("does-not-exist-key.pem"))
            .unwrap_err();
        assert!(matches!(err, TlsError::Io(_)));
    }

    #[test]
    fn round_trips_a_generated_cert_through_pem_files() {
        // Write an ephemeral cert+key to temp files, then load them back
        // through the same path `load()` uses, proving the two halves of
        // this module (generation, loading) agree on format.
        let dir = std::env::temp_dir().join(format!("zt-gateway-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");

        let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, certified_key.cert.pem()).unwrap();
        std::fs::write(&key_path, certified_key.key_pair.serialize_pem()).unwrap();

        let loaded = ServerCertificate::load(&cert_path, &key_path).unwrap();
        assert_eq!(loaded.cert_chain.len(), 1);
        build_server_config(loaded, None).unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }
}
