//! Tests for F14 / Task 1 (multi-backend routing): `Route` and
//! `RouteTable` in `zero_trust::config`. These are pure, in-memory tests —
//! no registry, no network, no gateway process — exercising only the
//! route-matching logic itself. `zt-gateway`'s own test suite
//! (`src/bin/zt-gateway.rs`'s `#[cfg(test)] mod tests`) covers how
//! `resolve_route` wires this into `proxy_handler`.

use zero_trust::{Route, RouteTable};

fn route(host_pattern: &str, path_pattern: &str, workload_id: &str, upstream_addr: &str) -> Route {
    Route {
        host_pattern: host_pattern.to_string(),
        path_pattern: path_pattern.to_string(),
        workload_id: workload_id.to_string(),
        upstream_addr: upstream_addr.to_string(),
        delegate: false,
        delegated_ttl_seconds: 60,
    }
}

const INVENTORY: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
const ORDERS: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";

/// Requirement 1: a single configured route matches a request whose path
/// (and host) satisfy its wildcard patterns.
#[test]
fn single_route_matches_correctly() {
    let table = RouteTable::new(vec![route(
        "*",
        "/api/inventory/**",
        INVENTORY,
        "http://127.0.0.1:9001",
    )]);

    let resolved = table.resolve("GET", "/api/inventory/items/42", Some("gateway.example.com"));
    assert_eq!(
        resolved,
        Some((INVENTORY.to_string(), "http://127.0.0.1:9001".to_string()))
    );
}

/// R4 (review 0003): `*` matches one path segment. It no longer crosses `/`, so
/// `/api/inventory/*` does not match a deeper path.
#[test]
fn single_star_does_not_match_across_segments() {
    let table = RouteTable::new(vec![route(
        "*",
        "/api/inventory/*",
        INVENTORY,
        "http://127.0.0.1:9001",
    )]);

    assert!(table.resolve("GET", "/api/inventory/42", Some("gateway.example.com")).is_some());
    assert_eq!(table.resolve("GET", "/api/inventory/items/42", Some("gateway.example.com")), None);
}

/// Requirement 2: a request that matches no configured route resolves to
/// `None` -- the caller (`resolve_route` in `zt-gateway`) is responsible
/// for falling back to the single `upstream_addr`, not `RouteTable` itself.
#[test]
fn no_match_returns_none() {
    let table = RouteTable::new(vec![route(
        "*",
        "/api/inventory/*",
        INVENTORY,
        "http://127.0.0.1:9001",
    )]);

    assert_eq!(table.resolve("GET", "/api/orders/42", Some("gateway.example.com")), None);
    assert_eq!(table.resolve("GET", "/health", None), None);
}

/// Requirement 3: when more than one route's patterns would match, the
/// first configured route wins -- the same "first matching rule" ordering
/// most reverse proxies use, so operators can order specific routes ahead
/// of catch-alls.
#[test]
fn multiple_routes_first_match_wins() {
    let table = RouteTable::new(vec![
        route("*", "/api/inventory/*", INVENTORY, "http://127.0.0.1:9001"),
        route("*", "/api/orders/*", ORDERS, "http://127.0.0.1:9002"),
        // A catch-all appended last; even though it would also match the
        // inventory request below, the earlier, more specific route must
        // win because it comes first.
        route("*", "/api/*", "spiffe://chakra.internal/ns/catchall/sa/catchall", "http://127.0.0.1:9000"),
    ]);

    assert_eq!(
        table.resolve("GET", "/api/inventory/items", None),
        Some((INVENTORY.to_string(), "http://127.0.0.1:9001".to_string()))
    );
    assert_eq!(
        table.resolve("POST", "/api/orders/99", None),
        Some((ORDERS.to_string(), "http://127.0.0.1:9002".to_string()))
    );
    // Falls through to the catch-all for anything else under /api/*.
    assert_eq!(
        table.resolve("GET", "/api/misc", None).unwrap().1,
        "http://127.0.0.1:9000"
    );
}

/// An empty route table (the default, backward-compatible config) never
/// matches anything -- `resolve_route` in `zt-gateway` is what falls back
/// to `upstream_addr` in this case, not `RouteTable`.
#[test]
fn empty_route_table_matches_nothing() {
    let table = RouteTable::default();
    assert!(table.is_empty());
    assert_eq!(table.resolve("GET", "/anything", Some("host")), None);
}

/// Host patterns support the same `*`/`*.example.com` wildcard matching as
/// path patterns, and a route only matches when both host and path match.
#[test]
fn host_pattern_wildcard_matching() {
    let table = RouteTable::new(vec![route(
        "*.example.com",
        "/api/*",
        INVENTORY,
        "http://127.0.0.1:9001",
    )]);

    assert!(table
        .resolve("GET", "/api/items", Some("inventory.example.com"))
        .is_some());
    // Host doesn't match the pattern -> no match even though the path does.
    assert_eq!(table.resolve("GET", "/api/items", Some("inventory.other.com")), None);
    // Path doesn't match the pattern -> no match even though the host does.
    assert_eq!(
        table.resolve("GET", "/health", Some("inventory.example.com")),
        None
    );
}

/// `host_pattern` defaults to `*` (match-any-host) when omitted from YAML,
/// so a purely path-based route table (the common case) doesn't need to
/// repeat `host_pattern: "*"` everywhere.
#[test]
fn route_deserializes_from_yaml_with_default_host_pattern() {
    let yaml = format!(
        "path_pattern: /api/inventory/*\nworkload_id: {INVENTORY}\nupstream_addr: http://127.0.0.1:9001\n"
    );
    let route: Route = serde_yaml_ng::from_str(&yaml).unwrap();
    assert_eq!(route.host_pattern, "*");
    assert_eq!(route.path_pattern, "/api/inventory/*");
}
