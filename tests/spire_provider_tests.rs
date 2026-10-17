//! Tests for Task 5 / F13: `zero_trust::SpireProvider`, an `IdentityProvider`
//! backed by a SPIRE agent's Workload API. No SPIRE agent is assumed to be
//! running wherever this test suite executes (CI, a laptop, this sandbox),
//! so these tests only exercise:
//!
//! 1. A compile-time proof that `SpireProvider` actually implements
//!    `IdentityProvider` -- the same trait `LocalIssuer` implements, and
//!    the thing that lets `zt-gateway` swap one for the other behind a
//!    single `Arc<dyn IdentityProvider + Send + Sync>` field (see
//!    `src/bin/zt-gateway.rs`'s `main`).
//! 2. That `SpireProvider::new` fails *gracefully* -- a plain `Err`, never
//!    a panic or a hang -- when there is no SPIRE agent listening on the
//!    configured socket path, which is the expected state in this
//!    environment and in most CI runs.
//!
//! Actually exercising `fetch_x509_svid`/`fetch_jwt_bundles`/
//! `issue_jwt_svid` end-to-end against a live SPIRE deployment is out of
//! scope here (no SPIRE/k8s wiring exists yet in this repo) -- see the
//! Task 5 report's "Concerns" section.

use zero_trust::{IdentityProvider, SpireProvider};

/// Purely a compile-time check: if `SpireProvider` ever stopped
/// implementing `IdentityProvider`, this function's body would fail to
/// type-check and the whole test binary would fail to compile -- no
/// SPIRE connection, and no `SpireProvider` instance, is needed to prove
/// this.
#[allow(dead_code)]
fn assert_identity_provider<T: IdentityProvider>() {}

#[test]
fn spire_provider_implements_identity_provider() {
    assert_identity_provider::<SpireProvider>();
}

/// `zt-gateway`'s `main` stores the configured provider as
/// `Arc<dyn IdentityProvider + Send + Sync>` (see `AppState::identity`) --
/// this is the same bound `SpireProvider` has to satisfy for that wiring
/// to compile.
#[allow(dead_code)]
fn assert_identity_provider_object_safe(_provider: std::sync::Arc<dyn IdentityProvider + Send + Sync>) {}

/// With no SPIRE agent listening on this (deliberately unused) socket
/// path, `SpireProvider::new` must return `Err`, not panic and not hang --
/// this is the "fails gracefully if SPIRE isn't running" requirement from
/// the Task 5 brief, and the actual behavior anyone running this suite
/// without a SPIRE agent (which is the common case) will see.
#[tokio::test]
async fn new_fails_gracefully_when_no_spire_agent_is_listening() {
    let result = SpireProvider::new("unix:/tmp/zt-gateway-test-no-such-spire-agent.sock").await;
    assert!(
        result.is_err(),
        "expected SpireProvider::new to fail when no SPIRE agent is listening on the socket"
    );
}

/// Same expectation against a syntactically invalid endpoint -- still a
/// graceful `Err`, not a panic, regardless of *why* the connection can't
/// be established.
#[tokio::test]
async fn new_fails_gracefully_on_a_malformed_socket_path() {
    let result = SpireProvider::new("not a valid workload api endpoint").await;
    assert!(result.is_err());
}
