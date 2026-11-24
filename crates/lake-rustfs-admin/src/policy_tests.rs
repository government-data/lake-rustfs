//! The dialect's tests, moved with it from the core's policies per kind of
//! job: each kind, said as a grant, allows what it allowed.

use std::collections::BTreeSet;

use contracts::{LakeGrant, LakeRead, LakeTable};
use serde_json::{json, Value};

use super::session_policy;

const W: &str = "qd-w";

fn policy(grant: &LakeGrant) -> Value {
    serde_json::from_str(&session_policy(grant).unwrap()).unwrap()
}

fn statements(grant: &LakeGrant) -> Vec<Value> {
    policy(grant)["Statement"].as_array().unwrap().clone()
}

/// Every (action, resource) the policy allows.
fn pairs(grant: &LakeGrant) -> BTreeSet<(String, String)> {
    let mut all = BTreeSet::new();
    for s in statements(grant) {
        for a in s["Action"].as_array().unwrap() {
            for r in s["Resource"].as_array().unwrap() {
                all.insert((a.as_str().unwrap().into(), r.as_str().unwrap().into()));
            }
        }
    }
    all
}

fn expect(rows: &[(&[&str], &[&str])]) -> BTreeSet<(String, String)> {
    let mut all = BTreeSet::new();
    for (actions, resources) in rows {
        for a in *actions {
            for r in *resources {
                all.insert(((*a).into(), format!("arn:aws:s3:::{W}{r}")));
            }
        }
    }
    all
}

fn table(namespace: &str, name: &str, location: &str) -> LakeTable {
    LakeTable {
        namespace: namespace.into(),
        name: name.into(),
        location: location.into(),
    }
}

const BUCKET: &[&str] = &["", "/*"];
const GETS: &[&str] = &[
    "admin:GetTableCatalog",
    "admin:GetTableBucket",
    "admin:GetTableNamespace",
    "admin:GetTable",
    "admin:GetTableMetadata",
    "admin:GetTableMetadataLocation",
];
const COMMIT: &[&str] = &[
    "admin:CommitTable",
    "admin:SetTableMetadata",
    "admin:SetTableMetadataLocation",
];
const WRITE: &[&str] = &[
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:AbortMultipartUpload",
    "s3:ListMultipartUploadParts",
];

#[test]
fn reading_the_warehouse_gets_and_lists_only() {
    let grant = LakeGrant::read_only(W);
    let read = &["s3:GetBucketLocation", "s3:ListBucket", "s3:GetObject"];
    assert_eq!(pairs(&grant), expect(&[(read, BUCKET), (GETS, BUCKET)]));
}

#[test]
fn a_listing_reads_the_tables_metadata_and_no_data_file() {
    let grant = LakeGrant::metadata(W);
    let list = &["s3:GetBucketLocation", "s3:ListBucket"];
    let rows = [
        (&list[..], &[""][..]),
        (&["s3:GetObject"][..], &["/*/metadata/*"][..]),
        (GETS, BUCKET),
    ];
    assert_eq!(pairs(&grant), expect(&rows));
}

#[test]
fn manifests_are_written_and_not_even_read_back() {
    let grant = LakeGrant {
        write_objects_under: Some("manifests/".into()),
        ..LakeGrant::on(W)
    };
    assert_eq!(
        pairs(&grant),
        expect(&[(&["s3:PutObject"], &["/manifests/*"])])
    );
}

#[test]
fn making_namespaces_allows_nothing_else() {
    let grant = LakeGrant {
        make_namespaces: true,
        ..LakeGrant::on(W)
    };
    let actions = &[
        "admin:GetTableCatalog",
        "admin:GetTableBucket",
        "admin:GetTableNamespace",
        "admin:SetTableNamespace",
    ];
    assert_eq!(pairs(&grant), expect(&[(actions, BUCKET)]));
}

#[test]
fn an_extraction_writes_its_namespaces_and_its_tables_files() {
    let grant = LakeGrant {
        create_tables_in: vec!["loans_bronze".into(), "loans_silver".into()],
        write_tables: vec![table("loans_bronze", "t1", "tables/u-1")],
        ..LakeGrant::read_only(W)
    };
    let read = &[
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetObject",
        "s3:ListBucketMultipartUploads",
    ];
    let writes = &[
        "/.*/namespaces/loans_bronze/*",
        "/.*/namespaces/loans_silver/*",
        "/tables/u-1/*",
        "/.*/namespaces/loans_bronze/tables/t1/*",
    ];
    let catalog: Vec<&str> = [GETS, &["admin:CreateTable"], COMMIT].concat();
    let rows = [(&read[..], BUCKET), (WRITE, writes), (&catalog[..], BUCKET)];
    assert_eq!(pairs(&grant), expect(&rows));
}

#[test]
fn a_maintain_job_writes_its_tables_files_and_creates_nothing() {
    let grant = LakeGrant {
        write_tables: vec![
            table("loans_bronze", "t1", "tables/u-1"),
            table("loans_silver", "t1", "tables/u-2"),
        ],
        ..LakeGrant::read_only(W)
    };
    let read = &["s3:GetBucketLocation", "s3:ListBucket", "s3:GetObject"];
    let writes = &[
        "/tables/u-1/*",
        "/.*/namespaces/loans_bronze/tables/t1/*",
        "/tables/u-2/*",
        "/.*/namespaces/loans_silver/tables/t1/*",
    ];
    let catalog: Vec<&str> = [GETS, COMMIT].concat();
    let rows = [(&read[..], BUCKET), (WRITE, writes), (&catalog[..], BUCKET)];
    assert_eq!(pairs(&grant), expect(&rows));
    assert!(!policy(&grant).to_string().contains("CreateTable"));
    assert_eq!(
        statements(&LakeGrant::read_only(W)).len(),
        2,
        "nothing to write"
    );
}

#[test]
fn a_drop_deletes_one_tables_files_then_the_table() {
    let grant = LakeGrant {
        drop_tables: vec![table("loans_bronze", "t1", "tables/u-1")],
        ..LakeGrant::on(W)
    };
    let list = &["s3:GetBucketLocation", "s3:ListBucket"];
    let files = &["/tables/u-1/*", "/.*/namespaces/loans_bronze/tables/t1/*"];
    let catalog: Vec<&str> = [
        GETS,
        COMMIT,
        &["admin:DeleteTable", "admin:DeleteTableNamespace"],
    ]
    .concat();
    let rows = [
        (&list[..], &[""][..]),
        (&["s3:GetObject", "s3:DeleteObject"][..], &files[..]),
        (&catalog[..], BUCKET),
    ];
    assert_eq!(pairs(&grant), expect(&rows));
}

#[test]
fn no_statement_mixes_action_families() {
    let grant = LakeGrant {
        create_tables_in: vec!["a_bronze".into()],
        write_tables: vec![table("a_bronze", "t", "tables/u-1")],
        drop_tables: vec![table("a_silver", "t", "tables/u-2")],
        make_namespaces: true,
        write_objects_under: Some("manifests/".into()),
        read: LakeRead::Metadata,
        ..LakeGrant::on(W)
    };
    for s in statements(&grant) {
        let families: BTreeSet<&str> = s["Action"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_str().unwrap().split(':').next().unwrap())
            .collect();
        assert_eq!(families.len(), 1, "{s}");
        assert_eq!(s["Effect"], json!("Allow"));
    }
}

#[test]
fn a_grant_is_translated_alike_each_time_and_refused_when_unsafe() {
    let grant = LakeGrant {
        write_tables: vec![table("a_bronze", "t", "tables/u-1")],
        ..LakeGrant::read_only(W)
    };
    assert_eq!(session_policy(&grant), session_policy(&grant));
    assert!(session_policy(&LakeGrant::read_only("Not*A*Bucket")).is_err());
    assert!(session_policy(&LakeGrant::on(W)).is_err(), "allows nothing");
    let mut climbing = grant;
    climbing.write_tables[0].location = "tables/../other".into();
    let refused = session_policy(&climbing).unwrap_err();
    assert!(!refused.0.contains("Statement"), "{refused:?}");
}
