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

    #[serde(default = "default_token_ttl_seconds")]
    pub token_ttl_seconds: i64,
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
    /// `ZT_GATEWAY_REGISTRY_PATH`, `ZT_GATEWAY_SIGNING_KEY_PATH` — each, if
    /// set, overrides the corresponding value from the config file.
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
}
