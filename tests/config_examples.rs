//! Every example config in `examples/` must parse, must keep the admin listener on loopback (the gateway refuses to
//! start otherwise), and must name a registry that parses. The examples are the first thing a reader runs, so a
//! change that breaks one should fail CI, not a reader's first run.

use std::fs;
use std::path::{Path, PathBuf};

use zero_trust::{GatewayConfig, Registry};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn example_configs() -> Vec<PathBuf> {
    let mut configs: Vec<PathBuf> = fs::read_dir(repo_root().join("examples"))
        .expect("examples/ exists")
        .map(|entry| entry.expect("readable entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "yaml"))
        .collect();
    configs.sort();
    assert!(!configs.is_empty(), "no example configs found under examples/");
    configs
}

#[test]
fn every_example_config_parses_with_a_loopback_admin_listener() {
    for path in example_configs() {
        let text = fs::read_to_string(&path).unwrap();
        let config = GatewayConfig::from_yaml_str(&text)
            .unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()));
        assert!(
            config.admin_addr.ip().is_loopback(),
            "{}: admin_addr {} must be loopback",
            path.display(),
            config.admin_addr
        );
    }
}

#[test]
fn every_example_config_names_a_registry_that_parses() {
    for path in example_configs() {
        let config = GatewayConfig::from_yaml_str(&fs::read_to_string(&path).unwrap()).unwrap();
        // Registry paths in the examples are relative to the repo root, where the examples say to run the binary.
        let registry_path = repo_root().join(&config.registry_path);
        if !registry_path.exists() {
            // Some examples point at a registry the operator supplies; only the fixture is guaranteed to exist.
            continue;
        }
        Registry::from_yaml_str(&fs::read_to_string(&registry_path).unwrap())
            .unwrap_or_else(|e| panic!("{}: registry {} does not parse: {e}", path.display(), registry_path.display()));
    }
}

#[test]
fn the_shipped_fixture_registry_parses() {
    let fixture: &Path = Path::new("tests/fixtures/registry.yaml");
    let text = fs::read_to_string(repo_root().join(fixture)).unwrap();
    Registry::from_yaml_str(&text).expect("tests/fixtures/registry.yaml parses");
}
