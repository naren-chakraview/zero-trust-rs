//! Integration test: loads the checked-in fixture (adapted from the
//! blueprint's real `identity/spiffe-ids.yaml`) from disk, the same way
//! `zt-gateway` loads its registry at startup, and confirms it resolves the
//! way the blueprint document says it should.

use zero_trust::Registry;

#[test]
fn loads_the_fixture_registry_from_disk() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/registry.yaml");
    let registry = Registry::from_reader(std::fs::File::open(path).unwrap()).unwrap();

    assert_eq!(registry.trust_domain(), "chakra.internal");
    // 4 rows in the file; legacy-billing-svc (spiffe_id: null) is skipped.
    assert_eq!(registry.len(), 3);

    let inventory = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc"
        .parse()
        .unwrap();
    let entry = registry.get(&inventory).expect("inventory-svc should be registered");

    assert_eq!(entry.max_obo_chain_depth, 3);
    let allowed: Vec<String> = entry.allowed_callers.iter().map(|id| id.to_string()).collect();
    assert!(allowed.contains(&"spiffe://chakra.internal/ns/orders/sa/orders-svc".to_string()));
    assert!(allowed.contains(&"spiffe://chakra.internal/ns/api-gateway/sa/api-gateway".to_string()));
}
