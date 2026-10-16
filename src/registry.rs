//! The SPIFFE ID registry: which workloads exist, who may call them, and how
//! deep an OBO delegation chain may go before being rejected.
//!
//! Mirrors the shape of the blueprint's `identity/spiffe-ids.yaml`.

use std::collections::HashMap;
use std::io::Read;

use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::error::RegistryError;
use crate::spiffe_id::SpiffeId;

/// Used when a workload entry omits `max_obo_chain_depth`. Deliberately
/// conservative (only direct calls, no delegation) — the real registry file
/// always sets this explicitly per-workload.
pub const DEFAULT_MAX_OBO_CHAIN_DEPTH: u32 = 1;

/// A single registered workload: its identity, who may call it, and how deep
/// an OBO chain may be before this workload rejects the request.
#[derive(Debug, Clone)]
pub struct WorkloadEntry {
    pub name: String,
    pub spiffe_id: SpiffeId,
    pub max_obo_chain_depth: u32,
    pub allowed_callers: Vec<SpiffeId>,
    /// Shared secret this workload presents to `zt-gateway`'s issuance
    /// endpoint to prove it is who it claims when requesting a JWT SVID.
    /// A v0.1 stand-in for real SPIRE node attestation.
    pub bootstrap_token: Option<String>,
}

/// The result of [`Registry::check_bootstrap_token`]. A plain enum, not a
/// `Result`, because "unknown workload" and "wrong token" are deliberately
/// not conflated — callers map each to their own distinct error variant
/// (e.g. `IdentityError::UnknownWorkload` vs. `InvalidBootstrapToken`).
pub enum CredentialCheck<'a> {
    Ok(&'a WorkloadEntry),
    UnknownWorkload,
    InvalidCredential,
}

/// The parsed registry: every known workload, keyed by its `SpiffeId`.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    trust_domain: String,
    entries: HashMap<SpiffeId, WorkloadEntry>,
}

impl Registry {
    /// Parses a registry from a YAML string (e.g. `include_str!(...)` in tests).
    pub fn from_yaml_str(s: &str) -> Result<Self, RegistryError> {
        let raw: RawRegistry = serde_yaml_ng::from_str(s)?;
        Self::from_raw(raw)
    }

    /// Parses a registry from any `Read` source (a file, a socket, ...).
    pub fn from_reader<R: Read>(mut r: R) -> Result<Self, RegistryError> {
        let mut buf = String::new();
        r.read_to_string(&mut buf)?;
        Self::from_yaml_str(&buf)
    }

    fn from_raw(raw: RawRegistry) -> Result<Self, RegistryError> {
        let mut entries = HashMap::with_capacity(raw.workloads.len());

        for workload in raw.workloads {
            // `spiffe_id: null` marks a legacy workload onboarded via the ZT
            // gateway — it has no SVID of its own, so there's nothing to
            // register. This is a normal, expected row, not an error.
            let Some(spiffe_id_str) = workload.spiffe_id else {
                continue;
            };

            let spiffe_id =
                spiffe_id_str
                    .parse::<SpiffeId>()
                    .map_err(|source| RegistryError::InvalidSpiffeId {
                        name: workload.name.clone(),
                        source,
                    })?;

            let mut allowed_callers = Vec::with_capacity(workload.allowed_callers.len());
            for caller in workload.allowed_callers {
                let parsed = caller.parse::<SpiffeId>().map_err(|source| {
                    RegistryError::InvalidAllowedCaller {
                        name: workload.name.clone(),
                        caller: caller.clone(),
                        source,
                    }
                })?;
                allowed_callers.push(parsed);
            }

            let entry = WorkloadEntry {
                name: workload.name,
                max_obo_chain_depth: workload.max_obo_chain_depth.unwrap_or(DEFAULT_MAX_OBO_CHAIN_DEPTH),
                allowed_callers,
                bootstrap_token: workload.bootstrap_token,
                spiffe_id: spiffe_id.clone(),
            };

            if entries.insert(spiffe_id.clone(), entry).is_some() {
                return Err(RegistryError::DuplicateSpiffeId(spiffe_id.to_string()));
            }
        }

        Ok(Self {
            trust_domain: raw.trust_domain,
            entries,
        })
    }

    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    pub fn get(&self, id: &SpiffeId) -> Option<&WorkloadEntry> {
        self.entries.get(id)
    }

    /// Linear scan by human-readable name (used by the issuance endpoint,
    /// where a caller identifies itself by name rather than by SPIFFE ID —
    /// it doesn't have one yet, that's what it's asking for). Fine at the
    /// registry sizes this crate targets; a name index would only be worth
    /// adding if this were called in a hot path over many thousands of
    /// entries.
    pub fn get_by_name(&self, name: &str) -> Option<&WorkloadEntry> {
        self.entries.values().find(|entry| entry.name == name)
    }

    /// Checks a presented `bootstrap_token` against `workload_name`'s
    /// registered one. Every issuance endpoint (JWT SVID, X.509 SVID, ...)
    /// needs this exact "look up by name, compare the token" check — it
    /// lives here once so `identity.rs` and `ca.rs` can't drift apart on
    /// what counts as a valid credential.
    ///
    /// The actual byte comparison uses [`subtle::ConstantTimeEq`] rather
    /// than `==` (F7 fix) — a naive `str` comparison short-circuits on the
    /// first mismatched byte, so its running time leaks how many leading
    /// bytes of a guessed token were correct, which turns bootstrap-token
    /// brute-forcing into a timing side-channel. Even the "workload doesn't
    /// exist" branch still performs a dummy constant-time comparison before
    /// returning, so a caller can't distinguish "unknown workload" from
    /// "known workload, wrong token" by response latency either.
    pub fn check_bootstrap_token(&self, workload_name: &str, credential: &str) -> CredentialCheck<'_> {
        let Some(entry) = self.get_by_name(workload_name) else {
            let dummy = "x";
            let _ = dummy.as_bytes().ct_eq(credential.as_bytes());
            return CredentialCheck::UnknownWorkload;
        };
        match &entry.bootstrap_token {
            Some(expected) if bool::from(expected.as_bytes().ct_eq(credential.as_bytes())) => {
                CredentialCheck::Ok(entry)
            }
            None => {
                let dummy = "x";
                let _ = dummy.as_bytes().ct_eq(credential.as_bytes());
                CredentialCheck::InvalidCredential
            }
            Some(_) => CredentialCheck::InvalidCredential,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Deserialization target matching the YAML file shape exactly. Kept
/// private and separate from `Registry`/`WorkloadEntry` (the "raw" vs.
/// "validated" split) so the public types only ever hold data that has
/// already passed SPIFFE ID parsing.
#[derive(Debug, Deserialize)]
struct RawRegistry {
    trust_domain: String,
    workloads: Vec<RawWorkloadEntry>,
}

#[derive(Debug, Deserialize)]
struct RawWorkloadEntry {
    name: String,
    spiffe_id: Option<String>,
    #[serde(default)]
    max_obo_chain_depth: Option<u32>,
    #[serde(default)]
    allowed_callers: Vec<String>,
    #[serde(default)]
    bootstrap_token: Option<String>,
    // Gateway-topology-only fields on legacy entries — accepted and
    // currently unused; kept so the real spiffe-ids.yaml deserializes
    // without error instead of failing on unknown fields.
    #[serde(default)]
    #[allow(dead_code)]
    onboarding_topology: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    gateway_spiffe_id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"
trust_domain: chakra.internal
workloads:
  - name: api-gateway
    spiffe_id: spiffe://chakra.internal/ns/api-gateway/sa/api-gateway
    max_obo_chain_depth: 1
    allowed_callers: []

  - name: inventory-svc
    spiffe_id: spiffe://chakra.internal/ns/inventory/sa/inventory-svc
    max_obo_chain_depth: 3
    allowed_callers:
      - spiffe://chakra.internal/ns/orders/sa/orders-svc
      - spiffe://chakra.internal/ns/api-gateway/sa/api-gateway
    bootstrap_token: inventory-secret

  - name: legacy-billing-svc
    spiffe_id: null
    onboarding_topology: topology-b-dedicated-pod
    gateway_spiffe_id: spiffe://chakra.internal/ns/zt-gateway/sa/zt-gateway
    note: "legacy, no SVID of its own"
"#;

    #[test]
    fn loads_workloads_and_skips_null_spiffe_id_entries() {
        let registry = Registry::from_yaml_str(FIXTURE).unwrap();

        assert_eq!(registry.trust_domain(), "chakra.internal");
        // 3 rows in YAML, but the null-spiffe_id legacy row is skipped.
        assert_eq!(registry.len(), 2);

        let inventory: SpiffeId = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc"
            .parse()
            .unwrap();
        let entry = registry.get(&inventory).unwrap();
        assert_eq!(entry.name, "inventory-svc");
        assert_eq!(entry.max_obo_chain_depth, 3);
        assert_eq!(entry.allowed_callers.len(), 2);
        assert_eq!(entry.bootstrap_token.as_deref(), Some("inventory-secret"));
    }

    #[test]
    fn missing_max_obo_chain_depth_uses_conservative_default() {
        let registry = Registry::from_yaml_str(FIXTURE).unwrap();
        let gw: SpiffeId = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway"
            .parse()
            .unwrap();
        assert_eq!(registry.get(&gw).unwrap().max_obo_chain_depth, 1);
    }

    #[test]
    fn unknown_workload_lookup_returns_none() {
        let registry = Registry::from_yaml_str(FIXTURE).unwrap();
        let unknown: SpiffeId = "spiffe://chakra.internal/ns/ghost/sa/ghost".parse().unwrap();
        assert!(registry.get(&unknown).is_none());
    }

    /// Qualitative timing test (F7): comparing against the correct token,
    /// a wrong token of the same length, and a wrong token of a different
    /// length should all take roughly the same time — proving the compare
    /// doesn't short-circuit on the first mismatched byte the way `==`
    /// does. Exact timing is hardware/load-dependent, so this only asserts
    /// the deltas stay small, not that the absolute numbers match.
    #[test]
    fn bootstrap_token_comparison_is_constant_time() {
        let registry = Registry::from_yaml_str(FIXTURE).unwrap();
        let workload = "inventory-svc";
        let correct_token = "inventory-secret";
        let wrong_same_len = "xxxxxxxxxxxxxxxx"; // same length as correct_token
        let wrong_diff_len = "x";

        // Warm up (JIT/cache effects, first-call overhead) before timing.
        for _ in 0..1000 {
            let _ = registry.check_bootstrap_token(workload, correct_token);
            let _ = registry.check_bootstrap_token(workload, wrong_same_len);
            let _ = registry.check_bootstrap_token(workload, wrong_diff_len);
        }

        let time_many = |token: &str| -> u128 {
            let start = std::time::Instant::now();
            for _ in 0..5000 {
                let _ = registry.check_bootstrap_token(workload, token);
            }
            start.elapsed().as_micros()
        };

        let correct_time = time_many(correct_token);
        let wrong_same_len_time = time_many(wrong_same_len);
        let wrong_diff_len_time = time_many(wrong_diff_len);

        // All three should match in outcome (allow/deny) as a sanity check...
        assert!(matches!(
            registry.check_bootstrap_token(workload, correct_token),
            CredentialCheck::Ok(_)
        ));
        assert!(matches!(
            registry.check_bootstrap_token(workload, wrong_same_len),
            CredentialCheck::InvalidCredential
        ));

        // ...and the batched timings should be in the same ballpark —
        // comfortably loose bounds since this runs on shared CI hardware.
        let max_time = correct_time.max(wrong_same_len_time).max(wrong_diff_len_time);
        let min_time = correct_time.min(wrong_same_len_time).min(wrong_diff_len_time);
        assert!(
            max_time < min_time.max(1) * 20,
            "timings diverged too much: correct={correct_time}us same_len={wrong_same_len_time}us diff_len={wrong_diff_len_time}us"
        );
    }

    #[test]
    fn invalid_spiffe_id_is_a_hard_error() {
        let bad = r#"
trust_domain: chakra.internal
workloads:
  - name: broken
    spiffe_id: not-a-spiffe-id
    allowed_callers: []
"#;
        let err = Registry::from_yaml_str(bad).unwrap_err();
        assert!(matches!(err, RegistryError::InvalidSpiffeId { .. }));
    }
}
