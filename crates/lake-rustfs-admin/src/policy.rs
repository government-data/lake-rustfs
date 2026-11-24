//! A grant in RustFS's policy dialect (decision 0078, point 3): the
//! session policy the core sends with STS `AssumeRole`. Moved from the
//! policies the core wrote per kind of job (decisions 0017, 0030, 0035,
//! 0037, 0039, 0043, 0055): a grant that asks what one of them allowed gets
//! the same actions on the same resources (a table written in a namespace
//! it creates in also names the table's record, which the namespace's
//! resource already covers).
//!
//! RustFS matches the catalog's actions (`admin:*Table*`) only against the
//! whole warehouse (`tools/verify/lake_drop.py`, `lake_silver.py`): what
//! confines a job to its tables is its S3 statement. It refuses a statement
//! that mixes action families, so each family has its own. A listing reads
//! the tables' metadata files and no data file (`lake_listing.py`).

use contracts::{LakeGrant, LakeRead};
use serde_json::{json, Value};

const CATALOG_READ: [&str; 6] = [
    "admin:GetTableCatalog",
    "admin:GetTableBucket",
    "admin:GetTableNamespace",
    "admin:GetTable",
    "admin:GetTableMetadata",
    "admin:GetTableMetadataLocation",
];
const CATALOG_NAMESPACES: [&str; 4] = [
    "admin:GetTableCatalog",
    "admin:GetTableBucket",
    "admin:GetTableNamespace",
    "admin:SetTableNamespace",
];
const CATALOG_COMMIT: [&str; 3] = [
    "admin:CommitTable",
    "admin:SetTableMetadata",
    "admin:SetTableMetadataLocation",
];
const CATALOG_DROP: [&str; 2] = ["admin:DeleteTable", "admin:DeleteTableNamespace"];
const FILES_WRITE: [&str; 4] = [
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:AbortMultipartUpload",
    "s3:ListMultipartUploadParts",
];
const BUCKET_LIST: [&str; 2] = ["s3:GetBucketLocation", "s3:ListBucket"];

/// Why a grant is not translated: the message names no policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub String);

/// The session policy for `grant`, as RustFS reads it. Pure: the same
/// grant gives the same text.
pub fn session_policy(grant: &LakeGrant) -> Result<String, Invalid> {
    grant.check().map_err(|e| Invalid(e.to_string()))?;
    if grant.is_empty() {
        return Err(Invalid("the grant allows nothing".into()));
    }
    let bucket = format!("arn:aws:s3:::{}", grant.warehouse);
    let all = vec![bucket.clone(), format!("{bucket}/*")];
    let mut statements = reading(grant, &bucket, &all);

    let mut writes: Vec<String> = grant
        .create_tables_in
        .iter()
        .map(|namespace| format!("{bucket}/.*/namespaces/{namespace}/*"))
        .collect();
    writes.extend(
        grant
            .write_tables
            .iter()
            .flat_map(|t| table_files(&bucket, t)),
    );
    if !writes.is_empty() {
        statements.push(allow(&FILES_WRITE, &writes));
    }
    let drops: Vec<String> = grant
        .drop_tables
        .iter()
        .flat_map(|t| table_files(&bucket, t))
        .collect();
    if !drops.is_empty() {
        statements.push(allow(&["s3:GetObject", "s3:DeleteObject"], &drops));
    }
    if let Some(prefix) = &grant.write_objects_under {
        let under = format!("{bucket}/{}/*", prefix.trim_end_matches('/'));
        statements.push(allow(&["s3:PutObject"], &[under]));
    }

    let catalog = catalog_actions(grant);
    if !catalog.is_empty() {
        statements.push(allow(&catalog, &all));
    }
    Ok(json!({ "Version": "2012-10-17", "Statement": statements }).to_string())
}

/// What a grant reads of the objects: the bucket listed, objects got.
fn reading(grant: &LakeGrant, bucket: &str, all: &[String]) -> Vec<Value> {
    let creates = !grant.create_tables_in.is_empty();
    let bucket = bucket.to_string();
    let mut statements = Vec::new();
    match grant.read {
        LakeRead::Warehouse => {
            let mut actions = vec![BUCKET_LIST[0], BUCKET_LIST[1], "s3:GetObject"];
            if creates {
                actions.push("s3:ListBucketMultipartUploads");
            }
            statements.push(allow(&actions, all));
        }
        LakeRead::Metadata => {
            statements.push(allow(&BUCKET_LIST, std::slice::from_ref(&bucket)));
            statements.push(allow(
                &["s3:GetObject"],
                &[format!("{bucket}/*/metadata/*")],
            ));
        }
        LakeRead::Nothing if !grant.drop_tables.is_empty() => {
            statements.push(allow(&BUCKET_LIST, std::slice::from_ref(&bucket)));
        }
        LakeRead::Nothing => {}
    }
    if creates && grant.read != LakeRead::Warehouse {
        statements.push(allow(
            &["s3:ListBucketMultipartUploads"],
            std::slice::from_ref(&bucket),
        ));
    }
    statements
}

/// The catalog's actions a grant needs, each once, in a fixed order.
fn catalog_actions(grant: &LakeGrant) -> Vec<&'static str> {
    let creates = !grant.create_tables_in.is_empty();
    let commits = creates || !grant.write_tables.is_empty() || !grant.drop_tables.is_empty();
    let mut catalog: Vec<&'static str> = Vec::new();
    let mut add = |actions: &[&'static str]| {
        for action in actions {
            if !catalog.contains(action) {
                catalog.push(action);
            }
        }
    };
    if grant.read != LakeRead::Nothing || commits {
        add(&CATALOG_READ);
    }
    if grant.make_namespaces {
        add(&CATALOG_NAMESPACES);
    }
    if creates {
        add(&["admin:CreateTable"]);
    }
    if commits {
        add(&CATALOG_COMMIT);
    }
    if !grant.drop_tables.is_empty() {
        add(&CATALOG_DROP);
    }
    catalog
}

/// A table's files: under its prefix, and the catalog's record of it.
fn table_files(bucket: &str, table: &contracts::LakeTable) -> [String; 2] {
    let (namespace, name) = (&table.namespace, &table.name);
    [
        format!("{bucket}/{}/*", table.location.trim_end_matches('/')),
        format!("{bucket}/.*/namespaces/{namespace}/tables/{name}/*"),
    ]
}

fn allow(actions: &[&str], resources: &[String]) -> Value {
    json!({ "Effect": "Allow", "Action": actions, "Resource": resources })
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
