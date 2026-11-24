//! The adapter's RustFS operations against real RustFS behind the
//! repository's gate (moved from `infrastructure`'s `rustfs_*_live`): run
//! by `tools/verify/rustfs_replication_gate.sh` (the health) and
//! `tools/verify/rustfs_replication_app.sh` (the replication), which start
//! them and give the addresses, the CA and a machine's `machine.pem`
//! (`LAKE_CA_FILE`, `LAKE_CLIENT_CERT_FILE`) and the admin keys' files;
//! ignored otherwise.

use std::sync::Arc;

use contracts::lake_admin::{Credentials, Health, ReplicaTarget};
use lake_rustfs_admin::replication::{self, Outcome};
use lake_rustfs_admin::{health, Certs, Rustfs};

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name}: run its tools/verify script"))
}

/// The keys a lake's script would have shown, from its file.
fn keys(file: &str) -> Credentials {
    let file = std::fs::read_to_string(var(file)).unwrap();
    let get = |name: &str| {
        let line = file.lines().find(|l| l.starts_with(name)).unwrap();
        line[name.len() + 1..].trim().to_string()
    };
    Credentials {
        access_key: get("ADMIN_ACCESS_KEY"),
        secret_key: get("ADMIN_SECRET_KEY"),
    }
}

/// The CA and the machine's certificate the scripts give.
fn certs() -> Arc<Certs> {
    let read = |name: &str| std::fs::read_to_string(var(name)).unwrap();
    Arc::new(Certs::from_pem(
        &read("LAKE_CA_FILE"),
        &read("LAKE_CLIENT_CERT_FILE"),
    ))
}

#[tokio::test]
#[ignore = "needs tools/verify/rustfs_replication_gate.sh"]
async fn a_lake_behind_its_gate_answers_its_drives_to_the_keys_sent() {
    let port = var("QD_VERIFY_GATE_PORT");
    let node = var("QD_VERIFY_NODE");
    let lake = Rustfs::new(&format!("https://{node}:{port}"), &node, certs());
    let kept = keys("QD_VERIFY_ADMIN_KEYS");
    let answered = health::health(&lake, Some(&kept)).await.unwrap();
    let drives = Health::Answered {
        drives_online: 1,
        drives_offline: 0,
    };
    assert_eq!(answered, drives);
    let wrong = Credentials {
        secret_key: "0".repeat(64),
        ..kept.clone()
    };
    let refused = health::health(&lake, Some(&wrong)).await.unwrap();
    let code = "SignatureDoesNotMatch".to_string();
    assert_eq!(refused, Health::KeysRefused { code });
    // Trusting the CA but presenting no certificate: the gate refuses it.
    let ca = std::fs::read(var("LAKE_CA_FILE")).unwrap();
    let bare = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&ca).unwrap())
        .build()
        .unwrap();
    let port: u16 = port.parse().unwrap();
    let lake = lake.with_client(bare, "https", port);
    let refused = health::health(&lake, Some(&kept)).await;
    assert!(refused.is_err(), "{refused:?}");
    println!("without a certificate: {refused:?}");
}

#[tokio::test]
#[ignore = "needs tools/verify/rustfs_replication_app.sh"]
async fn the_adapter_configures_a_warehouses_replication() {
    let port: u16 = var("QD_VERIFY_REPLICA_PORT").parse().unwrap();
    // The source node's name, as its proxy is named by it.
    let proxy = var("QD_VERIFY_PROXY");
    let node = proxy.split(':').next().unwrap().to_string();
    let lake = Rustfs::new(&var("QD_VERIFY_SOURCE"), &node, certs()).at("https", port);
    let target = ReplicaTarget {
        endpoint: var("QD_VERIFY_NODE"),
        source_pool: false,
    };
    let (main, replica) = (keys("QD_VERIFY_MAIN_KEYS"), keys("QD_VERIFY_REPLICA_KEYS"));
    let warehouse = var("QD_VERIFY_WAREHOUSE");
    let outcome = replication::configure(&lake, &warehouse, &target, &main, &replica).await;
    println!("configured: {outcome:?}");
    assert_eq!(outcome, Outcome::Configured);
    let missing = "qd-tenant-0000000000000000000000000000ffff";
    let outcome = replication::configure(&lake, missing, &target, &main, &replica).await;
    println!("a warehouse the main lake does not have: {outcome:?}");
    assert_eq!(outcome, Outcome::NoWarehouse);
}
