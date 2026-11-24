//! The adapter at the wire, against a test CA: who it answers, `GET
//! /about`, the error shape, and its certificate read again when renewed.

use std::sync::Arc;

use contracts::lake_admin::{self as wire, ErrorCode};
use lake_contract::admin_wire::{self, AdminClient};
use lake_rustfs_admin::routes::CALLER_ROLE;
use lake_rustfs_admin::{serve, Certs, Rustfs};
use testkit::tls::TestCa;

/// The adapter on a free port of localhost: its `https://localhost:<port>`.
async fn adapter(certs: Certs) -> String {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let certs = Arc::new(certs);
    // A lake nothing answers at: these cases ask it nothing.
    let lake = Arc::new(Rustfs::new("https://127.0.0.1:9", "lake-1", certs.clone()));
    tokio::spawn(serve(tcp, certs, lake, std::future::pending()));
    format!("https://localhost:{port}")
}

fn as_role(url: &str, ca: &TestCa, role: &str) -> AdminClient {
    AdminClient::new(
        url,
        &ca.pem,
        &ca.machine(role, &format!("{role}-1")).bundle(),
    )
}

#[tokio::test]
async fn the_core_server_reads_about() {
    let ca = TestCa::new();
    let url = adapter(Certs::from_pem(
        &ca.pem,
        &ca.machine("lake", "localhost").bundle(),
    ))
    .await;
    let (status, body) = as_role(&url, &ca, CALLER_ROLE)
        .call("GET", &wire::paths::about(), None)
        .await;
    assert_eq!(status, 200, "{body}");
    let about: wire::About = serde_json::from_value(body).unwrap();
    assert_eq!(about.protocols, [wire::PROTOCOL]);
    assert_eq!(about.implementation, "lake-rustfs");
}

#[tokio::test]
async fn another_role_of_the_ca_is_refused() {
    let ca = TestCa::new();
    let url = adapter(Certs::from_pem(
        &ca.pem,
        &ca.machine("lake", "localhost").bundle(),
    ))
    .await;
    for role in ["worker", "lake", "updater"] {
        let stranger = as_role(&url, &ca, role);
        admin_wire::refused_by_its_certificate(&stranger, "qd-tenant-a1").await;
        let (status, _) = stranger.call("GET", &wire::paths::about(), None).await;
        assert_eq!(status, 403, "{role} reads nothing");
    }
}

#[tokio::test]
async fn a_certificate_of_another_ca_does_not_connect() {
    let ca = TestCa::new();
    let url = adapter(Certs::from_pem(
        &ca.pem,
        &ca.machine("lake", "localhost").bundle(),
    ))
    .await;
    let other = TestCa::new();
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(ca.pem.as_bytes()).unwrap())
        .identity(
            reqwest::Identity::from_pem(other.machine("app", "app-1").bundle().as_bytes()).unwrap(),
        )
        .build()
        .unwrap();
    let answer = client
        .get(format!("{url}{}", wire::paths::about()))
        .send()
        .await;
    assert!(answer.is_err(), "the handshake is refused: {answer:?}");
}

#[tokio::test]
async fn an_operation_not_served_answers_the_error_shape() {
    let ca = TestCa::new();
    let url = adapter(Certs::from_pem(
        &ca.pem,
        &ca.machine("lake", "localhost").bundle(),
    ))
    .await;
    let core = as_role(&url, &ca, CALLER_ROLE);
    let (status, body) = core.call("GET", "/lake-admin/v1/nothing", None).await;
    assert_eq!(status, 404, "{body}");
    let error: wire::ErrorBody = serde_json::from_value(body).unwrap();
    assert_eq!((error.code, error.retryable), (ErrorCode::Unknown, false));
    assert!(
        error.error.contains("GET /lake-admin/v1/nothing"),
        "{}",
        error.error
    );
}

#[tokio::test]
async fn a_renewed_certificate_is_read_again() {
    let ca = TestCa::new();
    let dir = std::env::temp_dir().join(format!("qs-lake-admin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ca.crt"), &ca.pem).unwrap();
    let first = ca.machine("lake", "localhost");
    std::fs::write(dir.join("machine.pem"), first.bundle()).unwrap();
    let certs = Arc::new(Certs::from_dir(&dir));
    let before = certs.config().unwrap();
    assert!(
        Arc::ptr_eq(&before, &certs.config().unwrap()),
        "unchanged, kept"
    );

    std::thread::sleep(std::time::Duration::from_millis(20));
    let next = dir.join("next.pem");
    std::fs::write(&next, ca.machine("lake", "localhost").bundle()).unwrap();
    std::fs::rename(&next, dir.join("machine.pem")).unwrap();
    let after = certs.config().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(!Arc::ptr_eq(&before, &after), "renewed, read again");
}

#[tokio::test]
async fn a_grant_is_translated_twice_alike_and_a_bad_one_refused() {
    let ca = TestCa::new();
    let url = adapter(Certs::from_pem(
        &ca.pem,
        &ca.machine("lake", "localhost").bundle(),
    ))
    .await;
    let core = as_role(&url, &ca, CALLER_ROLE);
    let grant = serde_json::to_value(contracts::LakeGrant::read_only("qd-tenant-a1")).unwrap();
    let path = wire::paths::session_policy();
    let first = core.call("POST", &path, Some(&grant)).await;
    assert_eq!(first, core.call("POST", &path, Some(&grant)).await);
    assert_eq!(first.0, 200, "{}", first.1);
    let answer: wire::SessionPolicy = serde_json::from_value(first.1).unwrap();
    assert!(answer.policy.contains("arn:aws:s3:::qd-tenant-a1/*"));

    // The contract suite's error cases: a body that is no grant is `400
    // invalid`; an unknown warehouse's replication, `404 unknown` (its
    // `GET` is not served yet).
    admin_wire::errors(&core, "qd-tenant-unknown").await;
    let unsafe_grant = serde_json::json!({"warehouse": "qd-w", "write_objects_under": "../x"});
    let (status, body) = core.call("POST", &path, Some(&unsafe_grant)).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["code"], "invalid");
}
