//! Gateway configuration: where to listen, where to forward, which registry
//! and signing key to use, and which registered workload this particular
//! `zt-gateway` instance is protecting.

use std::net::SocketAddr;
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

/// Admin listener (issuance + authorize + token-exchange) default: loopback
/// only (F10 fix) — issuance is control-plane traffic, never meant to be
/// reachable from outside the host/pod, so the default is restrictive by
/// design rather than something an operator has to remember to lock down.
fn default_admin_addr() -> SocketAddr {
    "127.0.0.1:6443".parse().unwrap()
}

/// Proxy listener (protected-traffic forwarding) default: all interfaces,
/// the standard HTTPS port — this is the listener meant to receive real
/// user/caller traffic.
fn default_proxy_addr() -> SocketAddr {
    "0.0.0.0:443".parse().unwrap()
}

/// Requests per second the admin listener accepts before further requests
/// are queued/delayed by the rate limiter (F7 fix).
fn default_admin_rate_limit() -> u32 {
    10
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

    /// This gateway's own SPIFFE ID, appended to the signed `act`
    /// delegation chain by `POST /v1/token-exchange`
    /// ([`crate::token_exchange::exchange_token`]) when this gateway hands
    /// a request on to a further hop. Defaults to `protected_workload`
    /// when unset — correct for the common single-protected-workload
    /// deployment, but should be set explicitly for a gateway that fans
    /// requests out to multiple downstream audiences under its own
    /// distinct identity.
    #[serde(default)]
    pub gateway_id: Option<String>,

    #[serde(default = "default_token_ttl_seconds")]
    pub token_ttl_seconds: i64,

    /// TLS termination settings. `None` = plain HTTP (v0.1 behavior).
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// CA settings for client-cert verification and/or X.509 SVID
    /// issuance. Only meaningful when `tls.client_auth != ClientAuth::None`.
    #[serde(default)]
    pub ca: Option<CaConfig>,

    /// Admin listener address (default: `127.0.0.1:6443`, loopback-only).
    /// Serves `/v1/svid/x509`, `/v1/authorize`, and `/v1/token-exchange` —
    /// see `zt-gateway`'s `build_admin_router` (F10 fix: splitting this out
    /// of the proxy listener is what makes `client_auth: required` on the
    /// proxy listener possible without also locking issuance behind an
    /// mTLS cert a workload doesn't have yet).
    #[serde(default = "default_admin_addr")]
    pub admin_addr: SocketAddr,

    /// Proxy listener address (default: `0.0.0.0:443`). Serves only the
    /// reverse-proxy catch-all (protected traffic forwarding) — issuance
    /// and control-plane routes are never reachable here.
    #[serde(default = "default_proxy_addr")]
    pub proxy_addr: SocketAddr,

    /// Requests per second the admin listener accepts (F7 fix: issuance
    /// previously had no rate limiting at all). Default: 10.
    #[serde(default = "default_admin_rate_limit")]
    pub admin_rate_limit: u32,
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
        if let Ok(v) = std::env::var("ZT_GATEWAY_ADMIN_ADDR") {
            self.admin_addr = v
                .parse()
                .unwrap_or_else(|e| panic!("ZT_GATEWAY_ADMIN_ADDR={v:?} is not a valid socket address: {e}"));
        }
        if let Ok(v) = std::env::var("ZT_GATEWAY_PROXY_ADDR") {
            self.proxy_addr = v
                .parse()
                .unwrap_or_else(|e| panic!("ZT_GATEWAY_PROXY_ADDR={v:?} is not a valid socket address: {e}"));
        }
        if let Ok(v) = std::env::var("ZT_GATEWAY_ADMIN_RATE_LIMIT") {
            self.admin_rate_limit = v
                .parse()
                .unwrap_or_else(|e| panic!("ZT_GATEWAY_ADMIN_RATE_LIMIT={v:?} is not a valid u32: {e}"));
        }
        self
    }

    /// Test-only constructor for a minimal, otherwise-valid config whose
    /// listener addresses are the given `proxy`/`admin` sockets — used by
    /// `zt-gateway`'s listener-isolation tests, which need real,
    /// test-chosen ports rather than the production defaults (loopback
    /// `6443`/`0.0.0.0:443`, the latter of which requires a privileged
    /// port and would collide across concurrently-run tests anyway). Not
    /// `#[cfg(test)]`-gated because it's consumed from `zt-gateway.rs`'s
    /// own `#[cfg(test)]` module, a separate compilation unit from this
    /// library crate's test build.
    pub fn test_with_listeners(proxy: SocketAddr, admin: SocketAddr) -> Self {
        Self {
            listen_addr: default_listen_addr(),
            upstream_addr: "http://127.0.0.1:0".to_string(),
            registry_path: PathBuf::from("unused-in-tests.yaml"),
            protected_workload: "spiffe://chakra.internal/ns/inventory/sa/inventory-svc".to_string(),
            signing_key_path: None,
            jwks_path: None,
            active_kid: None,
            gateway_id: None,
            token_ttl_seconds: default_token_ttl_seconds(),
            tls: None,
            ca: None,
            admin_addr: admin,
            proxy_addr: proxy,
            admin_rate_limit: default_admin_rate_limit(),
        }
    }

    pub fn protected_workload_id(&self) -> Result<SpiffeId, ConfigError> {
        self.protected_workload
            .parse()
            .map_err(ConfigError::InvalidProtectedWorkload)
    }

    /// This gateway's own identity for RFC 8693 token exchange, falling
    /// back to [`Self::protected_workload_id`] when `gateway_id` is unset
    /// (see that field's doc comment for when an explicit value matters).
    pub fn gateway_id_spiffe_id(&self) -> Result<SpiffeId, ConfigError> {
        match &self.gateway_id {
            Some(value) => value.parse().map_err(|source| ConfigError::InvalidGatewayId {
                value: value.clone(),
                source,
            }),
            None => self.protected_workload_id(),
        }
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
    fn gateway_id_defaults_to_protected_workload_when_unset() {
        let config = GatewayConfig::from_yaml_str(MINIMAL).unwrap();
        assert!(config.gateway_id.is_none());
        assert_eq!(
            config.gateway_id_spiffe_id().unwrap(),
            config.protected_workload_id().unwrap()
        );
    }

    #[test]
    fn gateway_id_overrides_protected_workload_when_set() {
        let yaml = format!("{MINIMAL}\ngateway_id: spiffe://chakra.internal/ns/gateway-a/sa/gateway-a\n");
        let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
        let id = config.gateway_id_spiffe_id().unwrap();
        assert_eq!(id.service_account(), "gateway-a");
        assert_ne!(id, config.protected_workload_id().unwrap());
    }

    #[test]
    fn gateway_id_rejects_a_malformed_spiffe_id() {
        let yaml = format!("{MINIMAL}\ngateway_id: not-a-spiffe-id\n");
        let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
        assert!(matches!(
            config.gateway_id_spiffe_id(),
            Err(ConfigError::InvalidGatewayId { .. })
        ));
    }

    #[test]
    fn admin_and_proxy_listener_defaults_are_loopback_admin_and_wildcard_proxy() {
        let config = GatewayConfig::from_yaml_str(MINIMAL).unwrap();
        assert_eq!(config.admin_addr, "127.0.0.1:6443".parse().unwrap());
        assert_eq!(config.proxy_addr, "0.0.0.0:443".parse().unwrap());
        assert_eq!(config.admin_rate_limit, 10);
    }

    #[test]
    fn admin_and_proxy_listener_addresses_are_configurable() {
        let yaml = format!(
            "{MINIMAL}\nadmin_addr: 127.0.0.1:7000\nproxy_addr: 0.0.0.0:7443\nadmin_rate_limit: 25\n"
        );
        let config = GatewayConfig::from_yaml_str(&yaml).unwrap();
        assert_eq!(config.admin_addr, "127.0.0.1:7000".parse().unwrap());
        assert_eq!(config.proxy_addr, "0.0.0.0:7443".parse().unwrap());
        assert_eq!(config.admin_rate_limit, 25);
    }

    #[test]
    fn env_vars_override_admin_and_proxy_listener_settings() {
        std::env::set_var("ZT_GATEWAY_ADMIN_ADDR", "127.0.0.1:7001");
        std::env::set_var("ZT_GATEWAY_PROXY_ADDR", "0.0.0.0:7444");
        std::env::set_var("ZT_GATEWAY_ADMIN_RATE_LIMIT", "42");

        let config = GatewayConfig::from_yaml_str(MINIMAL).unwrap().with_env_overrides();
        assert_eq!(config.admin_addr, "127.0.0.1:7001".parse().unwrap());
        assert_eq!(config.proxy_addr, "0.0.0.0:7444".parse().unwrap());
        assert_eq!(config.admin_rate_limit, 42);

        std::env::remove_var("ZT_GATEWAY_ADMIN_ADDR");
        std::env::remove_var("ZT_GATEWAY_PROXY_ADDR");
        std::env::remove_var("ZT_GATEWAY_ADMIN_RATE_LIMIT");
    }

    #[test]
    fn test_with_listeners_builds_a_minimal_valid_config() {
        let proxy: SocketAddr = "127.0.0.1:19443".parse().unwrap();
        let admin: SocketAddr = "127.0.0.1:19444".parse().unwrap();
        let config = GatewayConfig::test_with_listeners(proxy, admin);
        assert_eq!(config.proxy_addr, proxy);
        assert_eq!(config.admin_addr, admin);
        assert!(config.protected_workload_id().is_ok());
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
