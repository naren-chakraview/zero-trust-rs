//! Capability policy for proxied requests (F11, review 0002).
//!
//! After a request passes the OBO decision, this policy asks whether the
//! verified caller may use this method and path. Both sides are taken from
//! verified identity and never from client headers:
//!
//! - `workloads`: the verified machine caller (the current actor, from the
//!   mTLS peer or the signed OBO chain). Every rule names at least one. This
//!   is the machine-identity gate.
//! - `users`: the verified user principal (the signed `user` claim). A rule
//!   with users matches only a request that carries one of them, from a
//!   caller the same rule lists. A rule with no users matches only a request
//!   with no user.
//!
//! A request acting for a user is therefore allowed only when the user and
//! the acting workload both hold a grant in the same rule (review 0003 R1). An
//! agent's rights never exceed its own grant, and a user's rights never reach
//! data through an agent that wasn't granted them.
//!
//! A request with no matching rule falls through to the policy's default.
//! `default: allow` is only valid until `default_allow_until`, after which it
//! denies. Startup refuses an expired allow default, so operators must
//! eventually move to `default: deny`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Deserialize;

use crate::config::path_matches;
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

        for rule in &file.rules {
            if rule.workloads.is_empty() {
                return Err(CapabilityPolicyError::Invalid(format!(
                    "rule for {:?} must name at least one workload: a request is always made by a workload, \
                     and a user grant only counts together with the workload acting for that user",
                    rule.path
                )));
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
            if !path_matches(&rule.path, request.path) {
                continue;
            }
            let caller_granted = request.caller.is_some_and(|caller| rule.workloads.contains(caller));
            let user_granted = match (rule.users.is_empty(), request.user) {
                // Workload-only rule: applies only when there is no user, so an
                // agent acting for someone can't use a grant meant for machines.
                (true, None) => true,
                // User rule: the user must be listed in this same rule.
                (false, Some(user)) => rule.users.iter().any(|u| u == user),
                _ => false,
            };
            if caller_granted && user_granted {
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

/// The live policy, shared between request handlers and the reload task.
///
/// Requests take a snapshot with [`Self::current`], so a reload never changes a
/// decision that is already being made. A reload swaps the whole policy at
/// once.
#[derive(Debug)]
pub struct CapabilityPolicyHandle {
    current: RwLock<Arc<CapabilityPolicy>>,
}

impl CapabilityPolicyHandle {
    pub fn new(policy: CapabilityPolicy) -> Self {
        Self {
            current: RwLock::new(Arc::new(policy)),
        }
    }

    pub fn current(&self) -> Arc<CapabilityPolicy> {
        self.current.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    fn replace(&self, policy: CapabilityPolicy) {
        *self.current.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(policy);
    }
}

/// Reloads the policy at `path` if its contents differ from `last_seen`.
///
/// Returns `Ok(true)` after swapping in a new policy and `Ok(false)` when the
/// file is unchanged. A file that fails to read, parse, or validate returns an
/// error and leaves the live policy unchanged. Comparing contents rather than
/// mtime also catches Kubernetes ConfigMap updates, which replace the file.
pub fn reload_if_changed(
    handle: &CapabilityPolicyHandle,
    path: &Path,
    last_seen: &mut Option<String>,
    now: i64,
) -> Result<bool, CapabilityPolicyError> {
    let contents = std::fs::read_to_string(path)?;
    if last_seen.as_deref() == Some(contents.as_str()) {
        return Ok(false);
    }
    let policy = CapabilityPolicy::from_yaml_str(&contents, now)?;
    handle.replace(policy);
    *last_seen = Some(contents);
    Ok(true)
}

/// Polls `path` every `interval` and reloads it on change, for the life of the
/// process. A rejected reload is logged and the previous policy keeps running.
pub async fn watch_capability_policy(handle: Arc<CapabilityPolicyHandle>, path: PathBuf, interval: Duration) {
    let mut last_seen = std::fs::read_to_string(&path).ok();
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match reload_if_changed(&handle, &path, &mut last_seen, crate::now_unix_secs()) {
            Ok(true) => tracing::info!(path = %path.display(), "capability policy reloaded"),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                path = %path.display(),
                %error,
                "capability policy reload rejected; keeping the previous policy"
            ),
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
    workloads: [{ORDERS}]
  - path: /inventory/*
    workloads: [{ORDERS}]
"#
        ))
    }

    #[test]
    fn user_grant_allows_the_listed_user_on_the_listed_tool() {
        let p = deny_policy();
        let orders: SpiffeId = ORDERS.parse().unwrap();
        let decision = p.check(&request("POST", "/tools/search", Some(ALICE), Some(&orders)), NOW);
        assert_eq!(decision, CapabilityDecision::Allow("rule_matched"));
    }

    #[test]
    fn same_user_is_denied_on_a_different_tool() {
        let p = deny_policy();
        let orders: SpiffeId = ORDERS.parse().unwrap();
        let decision = p.check(&request("POST", "/tools/delete", Some(ALICE), Some(&orders)), NOW);
        assert_eq!(decision, CapabilityDecision::Deny("default_deny"));
    }

    #[test]
    fn a_different_user_is_denied_on_the_granted_tool() {
        let p = deny_policy();
        let orders: SpiffeId = ORDERS.parse().unwrap();
        let decision = p.check(&request("POST", "/tools/search", Some("bob@corp.internal"), Some(&orders)), NOW);
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

    #[test]
    fn reload_swaps_in_an_edited_policy_and_ignores_an_unchanged_file() {
        let dir = std::env::temp_dir().join(format!("zt-f11-reload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("capability-policy.yaml");
        std::fs::write(&path, "default: deny\n").unwrap();

        let handle = CapabilityPolicyHandle::new(CapabilityPolicy::from_file(&path, NOW).unwrap());
        let mut last_seen = Some(std::fs::read_to_string(&path).unwrap());
        let caller: SpiffeId = ORDERS.parse().unwrap();
        let probe = request("GET", "/x", Some(ALICE), Some(&caller));
        assert!(!handle.current().check(&probe, NOW).is_allow());

        std::fs::write(&path, format!("default: deny\nrules:\n  - path: /x\n    users: [alice@corp.internal]\n    workloads: [{ORDERS}]\n")).unwrap();
        assert_eq!(reload_if_changed(&handle, &path, &mut last_seen, NOW).unwrap(), true);
        assert!(handle.current().check(&probe, NOW).is_allow());

        assert_eq!(reload_if_changed(&handle, &path, &mut last_seen, NOW).unwrap(), false);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rejected_reload_keeps_the_previous_policy_live() {
        let dir = std::env::temp_dir().join(format!("zt-f11-bad-reload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("capability-policy.yaml");
        std::fs::write(&path, format!("default: deny\nrules:\n  - path: /x\n    users: [alice@corp.internal]\n    workloads: [{ORDERS}]\n")).unwrap();

        let handle = CapabilityPolicyHandle::new(CapabilityPolicy::from_file(&path, NOW).unwrap());
        let mut last_seen = Some(std::fs::read_to_string(&path).unwrap());
        let caller: SpiffeId = ORDERS.parse().unwrap();

        // A typo'd field must be rejected, and the allow rule must keep working.
        std::fs::write(&path, format!("default: deny\nrules:\n  - path: /x\n    user: [alice@corp.internal]\n    workloads: [{ORDERS}]\n")).unwrap();
        assert!(reload_if_changed(&handle, &path, &mut last_seen, NOW).is_err());
        assert!(handle.current().check(&request("GET", "/x", Some(ALICE), Some(&caller)), NOW).is_allow());

        // An allow default whose deadline has passed is refused the same way.
        std::fs::write(&path, format!("default: allow\ndefault_allow_until: {NOW}\n")).unwrap();
        assert!(reload_if_changed(&handle, &path, &mut last_seen, NOW).is_err());
        assert!(handle.current().check(&request("GET", "/x", Some(ALICE), Some(&caller)), NOW).is_allow());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- R1 (review 0003): a user and the agent acting for them both need the grant ---

    const AGENT: &str = "spiffe://chakra.internal/ns/agents/sa/research-agent";
    const ADMIN: &str = "admin@corp.internal";
    const INTERN: &str = "intern@corp.internal";

    fn agent_policy() -> CapabilityPolicy {
        policy(&format!(
            r#"
default: deny
rules:
  - method: GET
    path: /orders/*
    workloads: [{AGENT}]
  - method: DELETE
    path: /orders/*
    users: [{ADMIN}]
    workloads: [{ORDERS}]
  - method: DELETE
    path: /orders/*
    users: [{ADMIN}]
    workloads: [{AGENT}]
"#
        ))
    }

    #[test]
    fn r1_agent_with_only_a_get_grant_cannot_delete_for_an_admin() {
        let agent: SpiffeId = AGENT.parse().unwrap();
        let decision = agent_policy().check(&request("DELETE", "/orders/42", Some(INTERN), Some(&agent)), NOW);
        assert!(!decision.is_allow(), "the agent may only read; it can't delete even when acting for a user");
        let admin_via_agent = agent_policy().check(&request("DELETE", "/orders/42", Some(ADMIN), Some(&agent)), NOW);
        assert_eq!(admin_via_agent, CapabilityDecision::Allow("rule_matched"),
            "admin acting through an agent that holds DELETE can delete");
    }

    #[test]
    fn r1_intern_with_no_grants_cannot_get_through_the_agent() {
        let agent: SpiffeId = AGENT.parse().unwrap();
        let decision = agent_policy().check(&request("GET", "/orders/42", Some(INTERN), Some(&agent)), NOW);
        assert!(!decision.is_allow(), "the agent's own GET grant doesn't extend to a user who has none");
    }

    #[test]
    fn r1_admin_delete_is_refused_when_the_acting_workload_has_no_grant() {
        let stranger: SpiffeId = OTHER.parse().unwrap();
        let decision = agent_policy().check(&request("DELETE", "/orders/42", Some(ADMIN), Some(&stranger)), NOW);
        assert!(!decision.is_allow(), "a user's grant alone is not enough");
    }

    #[test]
    fn r1_user_rule_without_a_workload_is_refused_at_load() {
        let err = CapabilityPolicy::from_yaml_str(
            &format!("default: deny\nrules:\n  - method: DELETE\n    path: /orders/*\n    users: [{ADMIN}]\n"),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityPolicyError::Invalid(_)));
    }

    #[test]
    fn r4_a_single_star_grant_cannot_be_reached_through_dot_segments() {
        let agent: SpiffeId = AGENT.parse().unwrap();
        let decision = agent_policy().check(&request("GET", "/orders/../admin/keys", None, Some(&agent)), NOW);
        assert!(!decision.is_allow(), "'*' must not match across '/' or through '..'");
    }

}
