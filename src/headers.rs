//! The three headers that carry OBO delegation state between hops, and the
//! `X-SPIFFE-Caller-Chain` parsing/formatting logic (ADR-0007,
//! `identity/index.md`'s "OBO Token Construction").

use crate::spiffe_id::SpiffeId;

pub const HEADER_OBO_TOKEN: &str = "X-SPIFFE-OBO-Token";
pub const HEADER_CALLER_CHAIN: &str = "X-SPIFFE-Caller-Chain";
pub const HEADER_USER_PRINCIPAL: &str = "X-SPIFFE-User-Principal";

/// The append-only, comma-separated list of SPIFFE IDs a request has passed
/// through so far, ordered from originator to most recent hop.
///
/// `depth()` matches the Rego policies' `count(chain_entries)` exactly: an
/// absent or empty header is depth 0, and blank entries from stray commas
/// are dropped rather than counted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallerChain(Vec<String>);

impl CallerChain {
    pub fn parse(header_value: &str) -> Self {
        let entries = header_value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        Self(entries)
    }

    pub fn depth(&self) -> usize {
        self.0.len()
    }

    pub fn entries(&self) -> &[String] {
        &self.0
    }

    pub fn to_header_value(&self) -> String {
        self.0.join(",")
    }

    /// Returns a new chain with `id` appended. The chain itself never
    /// mutates in place — each hop derives a new one, matching the
    /// "append-only" semantics from ADR-0007.
    pub fn appended(&self, id: &SpiffeId) -> Self {
        let mut entries = self.0.clone();
        entries.push(id.to_string());
        Self(entries)
    }
}

/// The three headers to attach to an outbound, delegated request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundHeaders {
    pub obo_token: String,
    pub caller_chain: String,
    pub user_principal: String,
}

/// Builds the outbound OBO headers for a service about to call a downstream
/// on behalf of `user_principal`, having already obtained `jwt_svid` (e.g.
/// from [`crate::IdentityProvider::issue_jwt_svid`]) scoped to that
/// downstream.
pub fn build_outbound_headers(
    jwt_svid: &str,
    own_id: &SpiffeId,
    existing_chain: &CallerChain,
    user_principal: &str,
) -> OutboundHeaders {
    OutboundHeaders {
        obo_token: jwt_svid.to_string(),
        caller_chain: existing_chain.appended(own_id).to_header_value(),
        user_principal: user_principal.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_empty_header_is_depth_zero() {
        assert_eq!(CallerChain::parse("").depth(), 0);
        assert_eq!(CallerChain::default().depth(), 0);
    }

    #[test]
    fn parses_and_trims_comma_separated_entries() {
        let chain = CallerChain::parse(" a , b ,c");
        assert_eq!(chain.entries(), ["a", "b", "c"]);
        assert_eq!(chain.depth(), 3);
    }

    #[test]
    fn drops_blank_entries_from_stray_commas() {
        let chain = CallerChain::parse("a,,b,");
        assert_eq!(chain.entries(), ["a", "b"]);
    }

    #[test]
    fn to_header_value_round_trips() {
        let original = "a,b,c";
        let chain = CallerChain::parse(original);
        assert_eq!(chain.to_header_value(), original);
    }

    #[test]
    fn appended_preserves_order_and_is_non_mutating() {
        let base = CallerChain::parse("a,b");
        let gateway: SpiffeId = "spiffe://chakra.internal/ns/zt-gateway/sa/zt-gateway"
            .parse()
            .unwrap();

        let extended = base.appended(&gateway);

        assert_eq!(base.depth(), 2, "appended() must not mutate the receiver");
        assert_eq!(extended.depth(), 3);
        assert_eq!(
            extended.entries(),
            ["a", "b", "spiffe://chakra.internal/ns/zt-gateway/sa/zt-gateway"]
        );
    }

    #[test]
    fn build_outbound_headers_appends_own_id_to_existing_chain() {
        let own_id: SpiffeId = "spiffe://chakra.internal/ns/orders/sa/orders-svc"
            .parse()
            .unwrap();
        let existing = CallerChain::parse("spiffe://chakra.internal/ns/api-gateway/sa/api-gateway");

        let headers = build_outbound_headers("dummy-jwt", &own_id, &existing, "user@chakra.internal");

        assert_eq!(headers.obo_token, "dummy-jwt");
        assert_eq!(
            headers.caller_chain,
            "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway,spiffe://chakra.internal/ns/orders/sa/orders-svc"
        );
        assert_eq!(headers.user_principal, "user@chakra.internal");
    }
}
