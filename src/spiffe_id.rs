//! SPIFFE ID parsing and formatting.
//!
//! This crate only needs the narrow shape used by the blueprint:
//! `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`.
//! A hand-rolled parser is used instead of the general-purpose `url` crate:
//! the shape is fixed and narrow, and `url`'s normalization (percent-decoding,
//! host casing, etc.) could silently accept forms the SPIFFE spec forbids.

use std::fmt;
use std::str::FromStr;

use crate::error::SpiffeIdError;

/// A parsed SPIFFE ID: `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`.
///
/// `PartialEq + Eq + Hash` make this usable as a `HashMap` key (the registry
/// looks workloads up by `SpiffeId`); `PartialOrd + Ord` give it a stable
/// sort order, handy for deterministic test output and logging.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpiffeId {
    trust_domain: String,
    namespace: String,
    service_account: String,
}

impl SpiffeId {
    /// Builds a `SpiffeId` from its parts, rejecting empty components.
    pub fn new(
        trust_domain: impl Into<String>,
        namespace: impl Into<String>,
        service_account: impl Into<String>,
    ) -> Result<Self, SpiffeIdError> {
        let trust_domain = trust_domain.into();
        let namespace = namespace.into();
        let service_account = service_account.into();

        if trust_domain.is_empty() {
            return Err(SpiffeIdError::EmptyTrustDomain);
        }
        if namespace.is_empty() {
            return Err(SpiffeIdError::EmptyNamespace);
        }
        if service_account.is_empty() {
            return Err(SpiffeIdError::EmptyServiceAccount);
        }

        Ok(Self {
            trust_domain,
            namespace,
            service_account,
        })
    }

    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn service_account(&self) -> &str {
        &self.service_account
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "spiffe://{}/ns/{}/sa/{}",
            self.trust_domain, self.namespace, self.service_account
        )
    }
}

impl FromStr for SpiffeId {
    type Err = SpiffeIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s.strip_prefix("spiffe://").ok_or(SpiffeIdError::InvalidScheme)?;

        // "<trust-domain>/ns/<namespace>/sa/<service-account>"
        let mut parts = rest.splitn(2, '/');
        let trust_domain = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");

        if trust_domain.is_empty() {
            return Err(SpiffeIdError::EmptyTrustDomain);
        }

        let segments: Vec<&str> = path.split('/').collect();
        let ["ns", namespace, "sa", service_account] = segments[..] else {
            return Err(SpiffeIdError::InvalidPathShape);
        };

        Self::new(trust_domain, namespace, service_account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_id() {
        let id: SpiffeId = "spiffe://chakra.internal/ns/orders/sa/orders-svc"
            .parse()
            .unwrap();
        assert_eq!(id.trust_domain(), "chakra.internal");
        assert_eq!(id.namespace(), "orders");
        assert_eq!(id.service_account(), "orders-svc");
    }

    #[test]
    fn display_round_trips_through_from_str() {
        let original = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
        let id: SpiffeId = original.parse().unwrap();
        assert_eq!(id.to_string(), original);
        let reparsed: SpiffeId = id.to_string().parse().unwrap();
        assert_eq!(id, reparsed);
    }

    #[test]
    fn rejects_malformed_ids() {
        let cases: &[(&str, SpiffeIdError)] = &[
            ("http://chakra.internal/ns/orders/sa/orders-svc", SpiffeIdError::InvalidScheme),
            ("spiffe:///ns/orders/sa/orders-svc", SpiffeIdError::EmptyTrustDomain),
            ("spiffe://chakra.internal/wrong/orders/sa/orders-svc", SpiffeIdError::InvalidPathShape),
            ("spiffe://chakra.internal/ns/orders/sa", SpiffeIdError::InvalidPathShape),
            ("spiffe://chakra.internal/ns//sa/orders-svc", SpiffeIdError::EmptyNamespace),
            (
                "spiffe://chakra.internal/ns/orders/sa/orders-svc/extra",
                SpiffeIdError::InvalidPathShape,
            ),
        ];

        for (input, expected) in cases {
            let err = input.parse::<SpiffeId>().unwrap_err();
            assert_eq!(&err, expected, "input: {input}");
        }
    }
}
