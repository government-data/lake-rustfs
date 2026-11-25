//! The module's `module.yaml`, parsed by quality-sdk's `module-manifest`:
//! the manifest an installation's agent reads from the package.

use module_manifest::Manifest;

fn manifest() -> Manifest {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../module.yaml");
    let text = std::fs::read_to_string(path).unwrap();
    Manifest::parse(&text).unwrap()
}

#[test]
fn module_yaml_is_a_valid_manifest() {
    let m = manifest();
    assert_eq!(m.name, "lake-rustfs");
    assert!(m.requires.capabilities.is_empty());
}

#[test]
fn it_provides_the_lake_with_lake_admin_1() {
    let m = manifest();
    let lake = &m.provides.capabilities;
    assert_eq!(lake.len(), 1);
    assert_eq!((lake[0].name.as_str(), lake[0].version), ("lake", 1));
    for protocol in ["s3", "iceberg-rest", "sts", "mtls-gate", "lake-admin/1"] {
        assert!(
            lake[0].protocols.iter().any(|p| p == protocol),
            "{protocol}"
        );
    }
}

#[test]
fn rustfs_data_is_critical() {
    let m = manifest();
    let critical = m.data.critical();
    assert_eq!(critical.volumes.len(), 1);
    assert_eq!(critical.volumes[0].service, "rustfs");
    assert_eq!(m.health.services, ["rustfs", "gate", "admin"]);
}

#[test]
fn rustfs_data_is_backed_up_by_the_replica_not_copied() {
    let m = manifest();
    let replicated: Vec<_> = m.data.replicated().map(|v| v.name.as_str()).collect();
    assert_eq!(replicated, ["rustfs-data"]);
    assert!(m.data.dumped().volumes.is_empty());
}
