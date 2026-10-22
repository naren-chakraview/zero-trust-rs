//! Capability policy for proxied requests (F11, review 0002).
//!
//! After a request passes the OBO decision, this policy asks whether the
//! verified caller may use this method and path. Grants come from two
//! sources, both taken from verified identity and never from client headers:
//!
//! - `users`: the verified user principal, which is the signed `user` claim
//!   of the OBO token.
//! - `workloads`: the verified machine caller, from the mTLS peer or the
//!   signed OBO chain. This is the machine-identity gate: a workload grant
//!   can only match an identity the gateway has already authenticated.
//!
//! A request with no matching rule falls through to the policy's default.
//! `default: allow` is only valid until `default_allow_until`, after which it
//! denies. Startup refuses an expired allow default, so operators must
//! eventually move to `default: deny`.

use std::path::Path;

use serde::Deserialize;

use crate::config::wildcard_matches;
use crate::spiffe_id::SpiffeId;

/// Why loading a capability policy failed.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityPolicyError {
    #[error("reading capability policy: {0}")]
    Io(#[from] std::io::Error),
    #[error("parsing capability policy: {0}")]
    Parse(String),
    #[error("invalid capability policy: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultMode {
    Allow,
    Deny,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    method: Option<String>,
    path: String,
    #[serde(default)]
    users: Vec<String>,
    #[serde(default)]
    workloads: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    default: DefaultMode,
    #[serde(default)]
    default_allow_until: Option<i64>,
    #[serde(default)]
    rules: Vec<RuleFile>,
}

/// One grant. A request matches when its method and path match and it is
/// either a listed user or a listed workload.
#[derive(Debug, Clone)]
pub struct CapabilityRule {
    method: Option<String>,
    path: String,
    users: Vec<String>,
    workloads: Vec<SpiffeId>,
}

/// The verified facts a capability decision is made from.
#[derive(Debug, Clone, Copy)]
pub struct CapabilityRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    /// Verified user principal, if the OBO token carried one.
    pub user: Option<&'a str>,
    /// Verified machine caller, from the mTLS peer or the OBO chain.
    pub caller: Option<&'a SpiffeId>,
}

/// Outcome of a capability check, with the reason for logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityDecision {
    Allow(&'static str),
    Deny(&'static str),
}

impl CapabilityDecision {
    pub fn is_allow(self) -> bool {
        matches!(self, Self::Allow(_))
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::Allow(reason) | Self::Deny(reason) => reason,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CapabilityPolicy {
    default: DefaultMode,
    default_allow_until: Option<i64>,
    rules: Vec<CapabilityRule>,
}

impl CapabilityPolicy {
    /// Parses a policy and checks it. `now` is only used to refuse an allow
    /// default whose deadline has already passed.
    pub fn from_yaml_str(yaml: &str, now: i64) -> Result<Self, CapabilityPolicyError> {
        let file: PolicyFile =
            serde_yaml_ng::from_str(yaml).map_err(|source| CapabilityPolicyError::Parse(source.to_string()))?;

        if file.default == DefaultMode::Allow {
            match file.default_allow_until {
                None => {
                    return Err(CapabilityPolicyError::Invalid(
                        "default: allow requires default_allow_until (unix seconds); move to default: deny when ready"
                            .to_string(),
                    ))
                }
                Some(until) if now >= until => {
                    return Err(CapabilityPolicyError::Invalid(format!(
                        "default_allow_until ({until}) has passed; set default: deny or extend the deadline"
                    )))
                }
                Some(_) => {}
            }
        }

        let rules = file
            .rules
            .into_iter()
            .map(|rule| {
                let workloads = rule
                    .workloads
                    .iter()
                    .map(|raw| {
                        raw.parse::<SpiffeId>().map_err(|source| {
                            CapabilityPolicyError::Invalid(format!("workload {raw:?} is not a SPIFFE ID: {source}"))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(CapabilityRule {
                    method: rule.method.map(|m| m.to_ascii_uppercase()),
                    path: rule.path,
                    users: rule.users,
                    workloads,
                })
            })
            .collect::<Result<Vec<_>, CapabilityPolicyError>>()?;

        Ok(Self {
            default: file.default,
            default_allow_until: file.default_allow_until,
            rules,
        })
    }

    /// Reads and parses the policy file at `path`.
    pub fn from_file(path: &Path, now: i64) -> Result<Self, CapabilityPolicyError> {
        Self::from_yaml_str(&std::fs::read_to_string(path)?, now)
    }

    /// Decides one request. Rules are checked first, in order. Any match
    /// allows. If none match, the default applies, and an allow default
    /// stops applying at `default_allow_until`.
    pub fn check(&self, request: &CapabilityRequest<'_>, now: i64) -> CapabilityDecision {
        for rule in &self.rules {
            if let Some(method) = &rule.method {
                if !method.eq_ignore_ascii_case(request.method) {
                    continue;
                }
            }
            if !wildcard_matches(&rule.path, request.path) {
                continue;
            }
            let user_granted = request.user.is_some_and(|user| rule.users.iter().any(|u| u == user));
            let workload_granted = request.caller.is_some_and(|caller| rule.workloads.contains(caller));
            if user_granted || workload_granted {
                return CapabilityDecision::Allow("rule_matched");
            }
        }

        match self.default {
            DefaultMode::Deny => CapabilityDecision::Deny("default_deny"),
            DefaultMode::Allow => match self.default_allow_until {
                Some(until) if now < until => CapabilityDecision::Allow("default_allow"),
                _ => CapabilityDecision::Deny("default_allow_expired"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORDERS: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";
    const OTHER: &str = "spiffe://chakra.internal/ns/billing/sa/billing-svc";
    const ALICE: &str = "alice@corp.internal";
    const NOW: i64 = 1_000_000;
    const FUTURE: i64 = NOW + 86_400;

    fn policy(yaml: &str) -> CapabilityPolicy {
        CapabilityPolicy::from_yaml_str(yaml, NOW).unwrap()
    }

    fn request<'a>(method: &'a str, path: &'a str, user: Option<&'a str>, caller: Option<&'a SpiffeId>) -> CapabilityRequest<'a> {
        CapabilityRequest { method, path, user, caller }
    }

    fn deny_policy() -> CapabilityPolicy {
        policy(&format!(
            r#"
default: deny
rules:
  - method: POST
    path: /tools/search
    users: [{ALICE}]
  - path: /inventory/*
    workloads: [{ORDERS}]
"#
        ))
    }

    #[test]
    fn user_grant_allows_the_listed_user_on_the_listed_tool() {
        let p = deny_policy();
        let decision = p.check(&request("POST", "/tools/search", Some(ALICE), None), NOW);
        assert_eq!(decision, CapabilityDecision::Allow("rule_matched"));
    }

    #[test]
    fn same_user_is_denied_on_a_different_tool() {
        let p = deny_policy();
        let decision = p.check(&request("POST", "/tools/delete", Some(ALICE), None), NOW);
        assert_eq!(decision, CapabilityDecision::Deny("default_deny"));
    }

    #[test]
    fn a_different_user_is_denied_on_the_granted_tool() {
        let p = deny_policy();
        let decision = p.check(&request("POST", "/tools/search", Some("bob@corp.internal"), None), NOW);
        assert!(!decision.is_allow());
    }

    #[test]
    fn workload_grant_allows_the_listed_machine_caller_with_no_user() {
        let p = deny_policy();
        let orders: SpiffeId = ORDERS.parse().unwrap();
        let decision = p.check(&request("GET", "/inventory/42", None, Some(&orders)), NOW);
        assert_eq!(decision, CapabilityDecision::Allow("rule_matched"));
    }

    #[test]
    fn workload_grant_does_not_match_an_unlisted_caller() {
        let p = deny_policy();
        let billing: SpiffeId = OTHER.parse().unwrap();
        let decision = p.check(&request("GET", "/inventory/42", None, Some(&billing)), NOW);
        assert!(!decision.is_allow());
    }

    #[test]
    fn a_method_mismatch_does_not_match_a_rule() {
        let p = deny_policy();
        let decision = p.check(&request("DELETE", "/tools/search", Some(ALICE), None), NOW);
        assert!(!decision.is_allow());
    }

    #[test]
    fn default_deny_refuses_a_request_no_rule_covers() {
        let p = deny_policy();
        let decision = p.check(&request("GET", "/anything", Some(ALICE), None), NOW);
        assert_eq!(decision, CapabilityDecision::Deny("default_deny"));
    }

    #[test]
    fn default_allow_permits_uncovered_requests_before_the_deadline() {
        let p = policy(&format!("default: allow\ndefault_allow_until: {FUTURE}\n"));
        let decision = p.check(&request("GET", "/anything", None, None), NOW);
        assert_eq!(decision, CapabilityDecision::Allow("default_allow"));
    }

    #[test]
    fn default_allow_stops_allowing_at_the_deadline() {
        let until = NOW + 100;
        let p = policy(&format!("default: allow\ndefault_allow_until: {until}\n"));
        let decision = p.check(&request("GET", "/anything", None, None), until);
        assert_eq!(decision, CapabilityDecision::Deny("default_allow_expired"));
    }

    #[test]
    fn default_allow_is_refused_at_load_when_the_deadline_has_passed() {
        let err = CapabilityPolicy::from_yaml_str(&format!("default: allow\ndefault_allow_until: {NOW}\n"), NOW)
            .unwrap_err();
        assert!(matches!(err, CapabilityPolicyError::Invalid(_)));
    }

    #[test]
    fn default_allow_without_a_deadline_is_refused_at_load() {
        let err = CapabilityPolicy::from_yaml_str("default: allow\n", NOW).unwrap_err();
        assert!(matches!(err, CapabilityPolicyError::Invalid(_)));
    }

    #[test]
    fn a_workload_that_is_not_a_spiffe_id_is_refused_at_load() {
        let err = CapabilityPolicy::from_yaml_str(
            "default: deny\nrules:\n  - path: /x\n    workloads: [not-a-spiffe-id]\n",
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityPolicyError::Invalid(_)));
    }

    #[test]
    fn unknown_fields_are_refused_so_typos_do_not_silently_open_access() {
        let err = CapabilityPolicy::from_yaml_str("default: deny\nrules:\n  - path: /x\n    user: [alice]\n", NOW)
            .unwrap_err();
        assert!(matches!(err, CapabilityPolicyError::Parse(_)));
    }
}
