//! The adapter's RustFS operations (decision 0078, step 11) against a
//! stand-in of a lake's gate over plain HTTP on the loopback: the requests
//! each signs with the keys the core sent, and what it makes of each
//! answer. RustFS itself is in `tools/verify/rustfs_replication_gate.sh`
//! and `rustfs_warehouse.sh`. Moved from `infrastructure`'s `rustfs_*`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use contracts::lake_admin::{Credentials, Health, ReplicaTarget, WarehouseOutcome};
use lake_rustfs_admin::replication::{self, Outcome};
use lake_rustfs_admin::{health, warehouse, Certs, Rustfs};
use testkit::tls::TestCa;

const SOURCE_SECRET: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const REPLICA_SECRET: &str = "7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b";
const ARN: &str = "arn:minio:replication:us-east-1:d1:qd-tenant-a";
const W: &str = "qd-tenant-a";
const OK: (&str, &str) = ("200 OK", "");
const MISSING: (&str, &str) = ("404 Not Found", "");

fn keys(secret: &str) -> Credentials {
    Credentials {
        access_key: "qd-platform-admin".into(),
        secret_key: secret.into(),
    }
}

/// A request as the stand-in saw it: its first line, its headers, its body.
#[derive(Debug, Clone)]
pub struct Seen {
    pub line: String,
    pub head: String,
    pub body: String,
}

/// A stand-in that answers each request with the next of `answers`.
pub fn gate(answers: Vec<(&'static str, &'static str)>) -> (u16, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kept = seen.clone();
    std::thread::spawn(move || {
        for (status, body) in answers {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            let (mut raw, mut buf) = (Vec::new(), [0u8; 4096]);
            let end = loop {
                let n = conn.read(&mut buf).unwrap();
                raw.extend_from_slice(&buf[..n]);
                if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .map_or(0, |v| v.trim().parse().unwrap());
            while raw.len() < end + length {
                let n = conn.read(&mut buf).unwrap();
                raw.extend_from_slice(&buf[..n]);
            }
            let line = head.lines().next().unwrap_or_default().to_string();
            let got = String::from_utf8_lossy(&raw[end..end + length]).into_owned();
            kept.lock().unwrap().push(Seen {
                line,
                head,
                body: got,
            });
            let reply = format!(
                "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            conn.write_all(reply.as_bytes()).unwrap();
        }
    });
    (port, seen)
}

/// The adapter's lake at the stand-in on `port`, its node `lake-1`; the
/// replica is `127.0.0.1` on the same port.
pub fn lake(port: u16) -> Rustfs {
    let ca = TestCa::new();
    let certs = Certs::from_pem(&ca.pem, &ca.machine("lake", "lake-1").bundle());
    Rustfs::new(
        &format!("http://127.0.0.1:{port}"),
        "lake-1",
        Arc::new(certs),
    )
    .with_client(reqwest::Client::new(), "http", port)
}

fn lines(seen: &Mutex<Vec<Seen>>) -> Vec<String> {
    seen.lock()
        .unwrap()
        .iter()
        .map(|s| s.line.clone())
        .collect()
}

#[tokio::test]
async fn info_is_asked_signed_with_the_keys_sent_and_its_drives_read() {
    let info = r#"{"info":{"backend":{"backendType":"Erasure","onlineDisks":4,"offlineDisks":0}}}"#;
    let (port, seen) = gate(vec![("200 OK", info)]);
    let health = health::health(&lake(port), Some(&keys(SOURCE_SECRET))).await;
    let drives = Health::Answered {
        drives_online: 4,
        drives_offline: 0,
    };
    assert_eq!(health.unwrap(), drives);
    let seen = seen.lock().unwrap()[0].clone();
    assert_eq!(seen.line, "get /rustfs/admin/v3/info http/1.1");
    let head = seen.head;
    assert!(
        head.contains(&format!("host: 127.0.0.1:{port}\r\n")),
        "{head}"
    );
    assert!(head.contains("content-length: 0\r\n"), "{head}");
    assert!(head.contains("authorization: aws4-hmac-sha256 credential=qd-platform-admin/"));
    assert!(head.contains("signedheaders=content-length;host;x-amz-content-sha256;x-amz-date"));
    assert!(!head.contains(SOURCE_SECRET), "the secret travelled");
}

#[tokio::test]
async fn refused_keys_no_keys_and_a_lake_not_reached_are_told_apart() {
    let refusal = "<Error><Code>SignatureDoesNotMatch</Code><Message>m</Message></Error>";
    let (port, _) = gate(vec![("403 Forbidden", refusal)]);
    let health = health::health(&lake(port), Some(&keys(SOURCE_SECRET))).await;
    let refused = Health::KeysRefused {
        code: "SignatureDoesNotMatch".into(),
    };
    assert_eq!(health.unwrap(), refused);
    assert_eq!(
        health::health(&lake(9), None).await.unwrap(),
        Health::NoKeys
    );
    // A port nothing listens on: bound, then let go.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let down = health::health(&lake(port), Some(&keys(SOURCE_SECRET))).await;
    let down = format!("{:?}", down.unwrap_err());
    assert!(
        down.contains("Lake") && down.contains("127.0.0.1"),
        "{down}"
    );
    assert!(!down.contains(SOURCE_SECRET));
}

#[tokio::test]
async fn a_missing_warehouse_is_made_then_its_table_bucket() {
    let (port, seen) = gate(vec![MISSING, OK, OK]);
    let made = warehouse::ensure(&lake(port), W, &keys(SOURCE_SECRET)).await;
    assert_eq!(made, WarehouseOutcome::Made);
    assert_eq!(
        lines(&seen),
        [
            format!("head /{W} http/1.1"),
            format!("put /{W} http/1.1"),
            format!("put /iceberg/v1/buckets/{W} http/1.1"),
        ]
    );
    for s in seen.lock().unwrap().iter() {
        assert!(s
            .head
            .contains("authorization: aws4-hmac-sha256 credential=qd-platform-admin/"));
        assert!(!s.head.contains(SOURCE_SECRET));
    }
    let (port, seen) = gate(vec![OK, OK]);
    let there = warehouse::ensure(&lake(port), W, &keys(SOURCE_SECRET)).await;
    assert_eq!(there, WarehouseOutcome::Present);
    assert_eq!(
        lines(&seen).len(),
        2,
        "not made again; its table bucket asked"
    );
}

#[tokio::test]
async fn a_refused_warehouse_step_says_which() {
    let refusal = "<Error><Code>AccessDenied</Code><Message>m</Message></Error>";
    let (port, seen) = gate(vec![MISSING, ("403 Forbidden", refusal)]);
    let failed = warehouse::ensure(&lake(port), W, &keys(SOURCE_SECRET)).await;
    let bucket = WarehouseOutcome::Failed {
        step: "warehouse_bucket".into(),
        detail: "HTTP 403 AccessDenied".into(),
    };
    assert_eq!(failed, bucket);
    assert_eq!(lines(&seen).len(), 2, "the table bucket is not asked");
    let bad = r#"{"error":{"message":"Bucket not found","code":400}}"#;
    let (port, _) = gate(vec![OK, ("400 Bad Request", bad)]);
    let failed = warehouse::ensure(&lake(port), W, &keys(SOURCE_SECRET)).await;
    let tables = WarehouseOutcome::Failed {
        step: "warehouse_tables".into(),
        detail: "HTTP 400".into(),
    };
    assert_eq!(failed, tables);
}

fn target(pool: bool) -> ReplicaTarget {
    ReplicaTarget {
        endpoint: "127.0.0.1".into(),
        source_pool: pool,
    }
}

async fn configure(port: u16, pool: bool) -> Outcome {
    let (source, replica) = (keys(SOURCE_SECRET), keys(REPLICA_SECRET));
    replication::configure(&lake(port), W, &target(pool), &source, &replica).await
}

#[tokio::test]
async fn every_replication_step_is_signed_by_its_lake_in_order() {
    let arn: &'static str = Box::leak(format!("\"{ARN}\"").into_boxed_str());
    let (port, seen) = gate(vec![OK, OK, OK, OK, OK, ("200 OK", arn), OK]);
    assert_eq!(configure(port, false).await, Outcome::Configured);
    let seen = seen.lock().unwrap().clone();
    let lines: Vec<&str> = seen.iter().map(|s| s.line.as_str()).collect();
    assert_eq!(
        lines,
        [
            "head /qd-tenant-a http/1.1",
            "put /qd-tenant-a http/1.1",
            "put /qd-tenant-a?object-lock= http/1.1",
            "put /qd-tenant-a?versioning= http/1.1",
            "put /qd-tenant-a?lifecycle= http/1.1",
            "put /rustfs/admin/v3/set-remote-target?bucket=qd-tenant-a http/1.1",
            "put /qd-tenant-a?replication= http/1.1",
        ]
    );
    assert!(seen[1]
        .head
        .contains("x-amz-bucket-object-lock-enabled: true"));
    assert!(seen[2]
        .body
        .contains("<Mode>COMPLIANCE</Mode><Days>30</Days>"));
    assert!(seen[4].body.contains("<NoncurrentDays>7</NoncurrentDays>"));
    let remote: serde_json::Value = serde_json::from_str(&seen[5].body).unwrap();
    assert_eq!(remote["endpoint"], "lake-1:9100", "the source node's proxy");
    assert_eq!(remote["secure"], true);
    assert_eq!(remote["credentials"]["secretKey"], REPLICA_SECRET);
    assert!(seen[6].body.contains(&format!("<Role>{ARN}</Role>")));
    for s in &seen {
        assert!(s
            .head
            .contains("authorization: aws4-hmac-sha256 credential=qd-platform-admin/"));
        assert!(!s.head.contains(SOURCE_SECRET) && !s.head.contains(REPLICA_SECRET));
        assert!(!s.body.contains(SOURCE_SECRET), "{}", s.line);
    }
    // The replica's secret goes to the source in the target's body alone.
    let carrying: Vec<usize> = (0..seen.len())
        .filter(|i| seen[*i].body.contains(REPLICA_SECRET))
        .collect();
    assert_eq!(carrying, [5]);
}

#[tokio::test]
async fn a_pools_replication_goes_through_the_alias_each_node_maps_to_itself() {
    let arn: &'static str = Box::leak(format!("\"{ARN}\"").into_boxed_str());
    let (port, seen) = gate(vec![OK, OK, OK, OK, OK, ("200 OK", arn), OK]);
    assert_eq!(configure(port, true).await, Outcome::Configured);
    let remote = seen.lock().unwrap()[5].body.clone();
    let remote: serde_json::Value = serde_json::from_str(&remote).unwrap();
    assert_eq!(
        (remote["endpoint"].clone(), remote["secure"].clone()),
        ("qd-lake-replication:9100".into(), false.into())
    );
}

#[tokio::test]
async fn a_missing_warehouse_asks_nothing_more_and_a_refused_step_says_which() {
    let (port, seen) = gate(vec![MISSING]);
    assert_eq!(configure(port, false).await, Outcome::NoWarehouse);
    assert_eq!(seen.lock().unwrap().len(), 1);
    let refusal = "<Error><Code>AccessDenied</Code><Message>m</Message></Error>";
    let (port, seen) = gate(vec![OK, OK, OK, OK, ("403 Forbidden", refusal)]);
    let failed = Outcome::Failed {
        step: "source_lifecycle".into(),
        detail: "HTTP 403 AccessDenied".into(),
    };
    assert_eq!(configure(port, false).await, failed);
    assert_eq!(seen.lock().unwrap().len(), 5);
    let (port, _) = gate(vec![OK, OK, OK, OK, OK, ("200 OK", "not an arn")]);
    let no_arn = Outcome::Failed {
        step: "remote_target".into(),
        detail: "no ARN in the answer".into(),
    };
    assert_eq!(configure(port, false).await, no_arn);
}

/// The adapter for the stand-in's lake, served on a free port of localhost,
/// and the core server's client of it.
async fn served(port: u16) -> lake_contract::admin_wire::AdminClient {
    let ca = TestCa::new();
    let certs = Arc::new(Certs::from_pem(
        &ca.pem,
        &ca.machine("lake", "localhost").bundle(),
    ));
    let lake = Rustfs::new(&format!("http://127.0.0.1:{port}"), "lake-1", certs.clone())
        .with_client(reqwest::Client::new(), "http", port);
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://localhost:{}", tcp.local_addr().unwrap().port());
    let serving = lake_rustfs_admin::serve(tcp, certs, Arc::new(lake), std::future::pending());
    tokio::spawn(serving);
    let core = ca.machine(lake_rustfs_admin::routes::CALLER_ROLE, "app-1");
    lake_contract::admin_wire::AdminClient::new(&url, &ca.pem, &core.bundle())
}

#[tokio::test]
async fn the_keys_come_in_headers_and_an_operation_without_them_is_invalid() {
    use contracts::lake_admin::{headers, paths};
    let (port, seen) = gate(vec![MISSING, OK, OK, OK, OK]);
    let core = served(port).await;
    let (status, body) = core.call("GET", &paths::health(), None).await;
    assert_eq!((status, body["state"].clone()), (200, "no_keys".into()));
    let bad = [(headers::ADMIN_KEYS, "no-colon".to_string())];
    let (status, body) = core.call_with("GET", &paths::health(), None, &bad).await;
    assert_eq!((status, body["code"].clone()), (400, "invalid".into()));
    let rules = serde_json::json!({});
    let path = paths::warehouse(W);
    let (status, body) = core.call("PUT", &path, Some(&rules)).await;
    assert_eq!((status, body["code"].clone()), (400, "invalid".into()));
    assert!(
        seen.lock().unwrap().is_empty(),
        "nothing asked without keys"
    );
    let with = [(headers::ADMIN_KEYS, headers::encode(&keys(SOURCE_SECRET)))];
    let made = core.call_with("PUT", &path, Some(&rules), &with).await;
    assert_eq!(made, (201, serde_json::json!({"state": "made"})));
    let there = core.call_with("PUT", &path, Some(&rules), &with).await;
    assert_eq!(there, (200, serde_json::json!({"state": "present"})));
    let name = paths::warehouse("Not_A_Bucket");
    let (status, _) = core.call_with("PUT", &name, Some(&rules), &with).await;
    assert_eq!(status, 400);
    let replica = paths::replication(W);
    let target = serde_json::json!({"endpoint": "127.0.0.1"});
    let (status, body) = core.call_with("PUT", &replica, Some(&target), &with).await;
    assert_eq!(
        (status, body["code"].clone()),
        (400, "invalid".into()),
        "no replica keys"
    );
    assert_eq!(lines(&seen).len(), 5);
}
