//! Gateway configuration: where to listen, where to forward, which registry
//! and signing key to use, and which registered workload this particular
//! `zt-gateway` instance is protecting.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::ConfigError;
use crate::spiffe_id::SpiffeId;

fn default_listen_addr() -> String {
    "127.0.0.1:8443".to_string()
}

fn default_token_ttl_seconds() -> i64 {
    300
}

fn default_ca_ttl_seconds() -> i64 {
    3600 // 1h, matching ADR-0002's X.509 SVID TTL
}

/// How strictly `zt-gateway` requires a TLS client certificate.
/// See `docs/design/0001-tls-mtls-termination.md` for the full rollout story.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuth {
    /// No client cert requested. `source_principal` stays `None` — same as
    /// v0.1's plain-HTTP behavior, just with the connection now encrypted.
    #[default]
    None,
    /// Client cert requested but not required; present callers get a
    /// verified `source_principal`, absent ones fall back to
    /// bearer-token-only. The migration mode.
    Optional,
    /// The TLS handshake itself fails without a valid client cert. Parity
    /// with the blueprint's `PeerAuthentication: STRICT`.
    Required,
}

/// TLS termination settings. `GatewayConfig::tls` being `None` entirely
/// preserves exact v0.1 plain-HTTP behavior.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Server certificate PEM. Omit (along with `key_path`) to generate an
    /// ephemeral, self-signed one at startup — fine for local dev, not for
    /// anything a real client needs to trust without `-k`/`--insecure`.
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default)]
    pub client_auth: ClientAuth,
}

/// CA settings, governing both the client-cert trust root (`cert_path`,
/// used whenever `client_auth != None`) and, optionally, this gateway's
/// own certificate-issuance capability (`key_path`).
///
/// `cert_path` set with `key_path` absent means "trust certs from this CA,
/// but don't attempt to issue any" — `POST /v1/svid/x509` returns `501` in
/// that mode rather than failing at startup. See "Trust root vs. issuance
/// capability" in the design doc.
#[derive(Debug, Clone, Deserialize)]
pub struct CaConfig {
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default = "default_ca_ttl_seconds")]
    pub ttl_seconds: i64,
}

/// Loaded from a YAML file, with a handful of fields overridable by
/// environment variables — the usual "file for structure, env for
/// per-deployment values" split, handy when the same config file is reused
/// across dev/staging/prod containers.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Base URL of the backend application this gateway fronts, e.g.
    /// `http://127.0.0.1:8080`.
    pub upstream_addr: String,

    /// Path to the `spiffe-ids.yaml`-shaped workload registry.
    pub registry_path: PathBuf,

    /// The SPIFFE ID (as it appears in `registry_path`) of the workload
    /// this gateway instance protects — i.e. the `destination` used in
    /// every `obo::validate` call on the proxy path.
    pub protected_workload: String,

    /// PKCS#1 PEM private key for signing JWT SVIDs. When absent, the
    /// gateway generates an ephemeral keypair at startup (see
    /// [`crate::LocalIssuer::generate`]) — fine for development, but every
    /// issued token becomes unverifiable across a restart.
    #[serde(default)]
    pub signing_key_path: Option<PathBuf>,

    /// Path to a JWKS document (see [`crate::LocalIssuer::with_jwks`]) shared
    /// across every gateway in the trust domain. When set (together with
    /// `active_kid`), this takes priority over `signing_key_path` — it lets
    /// this gateway verify tokens signed by any other gateway's active key,
    /// not just its own.
    #[serde(default)]
    pub jwks_path: Option<PathBuf>,

    /// Which `kid` in `jwks_path` this gateway instance signs new tokens
    /// with. Required when `jwks_path` is set; ignored otherwise.
    #[serde(default)]
    pub active_kid: Option<String>,

    #[serde(default = "default_token_ttl_seconds")]
    pub token_ttl_seconds: i64,

    /// TLS termination settings. `None` = plain HTTP (v0.1 behavior).
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// CA settings for client-cert verification and/or X.509 SVID
    /// issuance. Only meaningful when `tls.client_auth != ClientAuth::None`.
    #[serde(default)]
    pub ca: Option<CaConfig>,
}

impl GatewayConfig {
    /// Parses the YAML only — does not touch the process environment. Pure
    /// and side-effect-free, which is what makes it safe to call from
    /// multiple tests running concurrently (see [`Self::with_env_overrides`]).
    pub fn from_yaml_str(s: &str) -> Result<Self, ConfigError> {
        let config: GatewayConfig = serde_yaml_ng::from_str(s)?;
        Ok(config)
    }

    /// The real production load path: read the file, parse it, then apply
    /// any `ZT_GATEWAY_*` environment overrides on top.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)?;
        Ok(Self::from_yaml_str(&contents)?.with_env_overrides())
    }

    /// `ZT_GATEWAY_LISTEN_ADDR`, `ZT_GATEWAY_UPSTREAM_ADDR`,
    /// `ZT_GATEWAY_REGISTRY_PATH`, `ZT_GATEWAY_SIGNING_KEY_PATH`,
    /// `ZT_GATEWAY_JWKS_PATH`, `ZT_GATEWAY_ACTIVE_KID` — each, if set,
    /// overrides the corresponding value from the config file.
    ///
    /// Reading the process environment is a side effect, so it's a
    /// separate, explicit step rather than something `from_yaml_str` does
    /// automatically — that keeps parsing pure and testable in isolation.
    pub fn with_env_overrides(mut self) -> Self {
        if let Ok(v) = std::env::var("ZT_GATEWAY_LISTEN_ADDR") {
            self.listen_addr = v;
        }
        if let Ok(v) = std::env::var("ZT_GATEWAY_UPSTREAM_ADDR") {
            self.upstream_addr = v;
        }
        if let Ok(v) = std::env::var("ZT_GATEWAY_REGISTRY_PATH") {
            self.registry_path = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("ZT_GATEWAY_SIGNING_KEY_PATH") {
            self.signing_key_path = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("ZT_GATEWAY_JWKS_PATH") {
            self.jwks_path = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("ZT_GATEWAY_ACTIVE_KID") {
            self.active_kid = Some(v);
        }
        self
    }

    pub fn protected_workload_id(&self) -> Result<SpiffeId, ConfigError> {
        self.protected_workload
            .parse()
            .map_err(ConfigError::InvalidProtectedWorkload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
upstream_addr: http://127.0.0.1:8080
registry_path: registry.yaml
protected_workload: spiffe://chakra.internal/ns/inventory/sa/inventory-svc
"#;

    #[test]
    fn applies_defaults_for_omitted_fields() {
        let config = GatewayConfig::from_yaml_str(MINIMAL).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:8443");
        assert_eq!(config.token_ttl_seconds, 300);
        assert!(config.signing_key_path.is_none());
    }

    #[test]
    fn explicit_values_override_defaults() {
        let yaml = format!("{MINIMAL}\nlisten_addr: 0.0.0.0:9000\ntoken_ttl_seconds: 60\n");
        let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
        assert_eq!(config.listen_addr, "0.0.0.0:9000");
        assert_eq!(config.token_ttl_seconds, 60);
    }

    #[test]
    fn protected_workload_id_parses_a_valid_spiffe_id() {
        let config = GatewayConfig::from_yaml_str(MINIMAL).unwrap();
        let id = config.protected_workload_id().unwrap();
        assert_eq!(id.service_account(), "inventory-svc");
    }

    #[test]
    fn protected_workload_id_rejects_a_malformed_spiffe_id() {
        let yaml = MINIMAL.replace(
            "protected_workload: spiffe://chakra.internal/ns/inventory/sa/inventory-svc",
            "protected_workload: not-a-spiffe-id",
        );
        let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
        assert!(config.protected_workload_id().is_err());
    }

    /// `with_env_overrides` mutates/reads process-global state, which
    /// Rust's default (multi-threaded) test runner does not isolate between
    /// tests. Keeping `from_yaml_str` itself pure (see its doc comment)
    /// means every *other* test in this module is immune to this test's
    /// env var writes, regardless of execution order.
    #[test]
    fn env_vars_override_file_values() {
        std::env::set_var("ZT_GATEWAY_LISTEN_ADDR", "0.0.0.0:1234");
        std::env::set_var("ZT_GATEWAY_UPSTREAM_ADDR", "http://127.0.0.1:9999");

        let config = GatewayConfig::from_yaml_str(MINIMAL).unwrap().with_env_overrides();
        assert_eq!(config.listen_addr, "0.0.0.0:1234");
        assert_eq!(config.upstream_addr, "http://127.0.0.1:9999");

        std::env::remove_var("ZT_GATEWAY_LISTEN_ADDR");
        std::env::remove_var("ZT_GATEWAY_UPSTREAM_ADDR");
    }

    #[test]
    fn tls_and_ca_are_absent_by_default() {
        let config = GatewayConfig::from_yaml_str(MINIMAL).unwrap();
        assert!(config.tls.is_none());
        assert!(config.ca.is_none());
    }

    #[test]
    fn tls_block_defaults_client_auth_to_none() {
        let yaml = format!(
            "{MINIMAL}\ntls:\n  cert_path: server-cert.pem\n  key_path: server-key.pem\n"
        );
        let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
        let tls = config.tls.unwrap();
        assert_eq!(tls.client_auth, ClientAuth::None);
        assert_eq!(tls.cert_path, Some(PathBuf::from("server-cert.pem")));
    }

    #[test]
    fn tls_block_with_no_cert_paths_is_valid_ephemeral_mode() {
        let yaml = format!("{MINIMAL}\ntls:\n  client_auth: required\n");
        let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
        let tls = config.tls.unwrap();
        assert!(tls.cert_path.is_none());
        assert!(tls.key_path.is_none());
        assert_eq!(tls.client_auth, ClientAuth::Required);
    }

    #[test]
    fn client_auth_parses_all_three_values() {
        for (yaml_value, expected) in [
            ("none", ClientAuth::None),
            ("optional", ClientAuth::Optional),
            ("required", ClientAuth::Required),
        ] {
            let yaml = format!("{MINIMAL}\ntls:\n  client_auth: {yaml_value}\n");
            let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
            assert_eq!(config.tls.unwrap().client_auth, expected, "value: {yaml_value}");
        }
    }

    #[test]
    fn ca_cert_path_without_key_path_is_valid_verify_only_mode() {
        let yaml = format!("{MINIMAL}\nca:\n  cert_path: org-ca.pem\n");
        let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
        let ca = config.ca.unwrap();
        assert_eq!(ca.cert_path, Some(PathBuf::from("org-ca.pem")));
        assert!(ca.key_path.is_none());
        assert_eq!(ca.ttl_seconds, 3600);
    }

    #[test]
    fn ca_ttl_seconds_is_configurable() {
        let yaml = format!("{MINIMAL}\nca:\n  cert_path: ca.pem\n  key_path: ca-key.pem\n  ttl_seconds: 900\n");
        let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
        assert_eq!(config.ca.unwrap().ttl_seconds, 900);
    }

    #[test]
    fn jwks_path_and_active_kid_are_absent_by_default() {
        let config = GatewayConfig::from_yaml_str(MINIMAL).unwrap();
        assert!(config.jwks_path.is_none());
        assert!(config.active_kid.is_none());
    }

    #[test]
    fn jwks_path_and_active_kid_parse_when_present() {
        let yaml = format!("{MINIMAL}\njwks_path: jwks.json\nactive_kid: key-1\n");
        let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
        assert_eq!(config.jwks_path, Some(PathBuf::from("jwks.json")));
        assert_eq!(config.active_kid, Some("key-1".to_string()));
    }

    #[test]
    fn env_vars_override_jwks_path_and_active_kid() {
        std::env::set_var("ZT_GATEWAY_JWKS_PATH", "/etc/zt/jwks.json");
        std::env::set_var("ZT_GATEWAY_ACTIVE_KID", "key-2");

        let config = GatewayConfig::from_yaml_str(MINIMAL).unwrap().with_env_overrides();
        assert_eq!(config.jwks_path, Some(PathBuf::from("/etc/zt/jwks.json")));
        assert_eq!(config.active_kid, Some("key-2".to_string()));

        std::env::remove_var("ZT_GATEWAY_JWKS_PATH");
        std::env::remove_var("ZT_GATEWAY_ACTIVE_KID");
    }
}
