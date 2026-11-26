//! `PUT /credentials/{kind}` (core decision 0078's table, as amended by
//! decision 0091's rulings 46 and 50): the lake's own users. Served here
//! for `query-engine`, a query engine's user (Trino's coordinator): its
//! keys are given (read-only files the agent generated), so the adapter
//! makes or updates the user **with them** and answers them, and never
//! makes keys of its own. Every call is signed with the lake's admin keys
//! the core sent for it, never root, and none of them is logged.
//!
//! The user's policy is [`POLICY`], the canned policy [`POLICY_NAME`]: the
//! objects and the catalog of the installation's warehouses (`qd-tenant-*`)
//! and nothing else; no bucket made, no admin API. Verified with RustFS
//! 1.0.5 (`tools/verify/rustfs_query_engine.sh`): the admin user may make
//! the three, each answers 200 again on a second run; `add-user` with
//! another secret for the same access key takes it and refuses the old
//! one; `set-user-or-group-policy` replaces a policy attached before.

use contracts::lake_admin::Credentials;
use serde_json::json;

use crate::rustfs::{call, code, Answer, Rustfs};

/// The canned policy a query engine's user gets.
pub const POLICY_NAME: &str = "qd-query-engine";

/// What a query engine may do: read and write objects, and use the
/// catalog, in the installation's warehouses alone. One line, as
/// `tools/verify/rustfs_query_engine.sh` reads it.
pub const POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetBucketLocation","s3:ListBucket","s3:ListBucketMultipartUploads","s3:GetObject","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":["arn:aws:s3:::qd-tenant-*","arn:aws:s3:::qd-tenant-*/*"]},{"Effect":"Allow","Action":["admin:GetTableCatalog","admin:GetTableBucket","admin:GetTableNamespace","admin:SetTableNamespace","admin:UpdateTableNamespaceProperties","admin:DeleteTableNamespace","admin:GetTable","admin:GetTableMetadata","admin:GetTableMetadataLocation","admin:CreateTable","admin:CommitTable","admin:SetTableMetadata","admin:SetTableMetadataLocation","admin:RegisterTable","admin:DeleteTable"],"Resource":["arn:aws:s3:::qd-tenant-*","arn:aws:s3:::qd-tenant-*/*"]}]}"#;

/// The steps, as a failure names them.
pub const STEP_POLICY: &str = "policy";
pub const STEP_USER: &str = "user";
pub const STEP_ATTACH: &str = "attach";

/// Why a user was not made: the step and what RustFS answered, in a few
/// words, never a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    pub step: &'static str,
    pub detail: String,
}

/// Why the given keys cannot be a query engine's user.
pub fn refused(given: &Credentials, admin: &Credentials) -> Option<&'static str> {
    let fits = |key: &str, range: std::ops::RangeInclusive<usize>| {
        range.contains(&key.len()) && key.bytes().all(|b| b.is_ascii_graphic())
    };
    if !fits(&given.access_key, 3..=128) {
        Some("the access key is not one RustFS takes")
    } else if !fits(&given.secret_key, 8..=128) {
        Some("the secret key is not one RustFS takes")
    } else if given.access_key == admin.access_key {
        Some("the access key is the admin's")
    } else {
        None
    }
}

/// Makes the query engine's user with `given`, or updates it to them, and
/// attaches [`POLICY`]: the same calls on every run, each a no-op when it
/// already holds.
pub async fn ensure_query_engine(
    lake: &Rustfs,
    admin: &Credentials,
    given: &Credentials,
) -> Result<(), Failed> {
    let base = lake.base(&lake.source);
    let name = [("name", POLICY_NAME)];
    let mut policy = call(&base, "PUT", admin_path("add-canned-policy"), &name);
    policy.body = POLICY.as_bytes().to_vec();
    passed(STEP_POLICY, lake.send(admin, policy).await)?;

    let user_query = [("accessKey", given.access_key.as_str())];
    let mut user = call(&base, "PUT", admin_path("add-user"), &user_query);
    let body = json!({ "secretKey": given.secret_key, "status": "enabled" });
    user.body = body.to_string().into_bytes();
    passed(STEP_USER, lake.send(admin, user).await)?;

    let attach_query = [
        ("policyName", POLICY_NAME),
        ("userOrGroup", given.access_key.as_str()),
        ("isGroup", "false"),
    ];
    let attach = call(
        &base,
        "PUT",
        admin_path("set-user-or-group-policy"),
        &attach_query,
    );
    passed(STEP_ATTACH, lake.send(admin, attach).await)
}

fn admin_path(operation: &str) -> String {
    format!("/rustfs/admin/v3/{operation}")
}

/// A step's answer: 200 passes; anything else fails it.
fn passed(step: &'static str, answer: Answer) -> Result<(), Failed> {
    match answer {
        Ok((200, _)) => Ok(()),
        Ok((status, text)) => {
            let detail = format!("HTTP {status} {}", code(&text))
                .trim_end()
                .to_string();
            Err(Failed { step, detail })
        }
        Err(detail) => Err(Failed { step, detail }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(access: &str, secret: &str) -> Credentials {
        Credentials {
            access_key: access.into(),
            secret_key: secret.into(),
        }
    }

    #[test]
    fn the_policy_names_the_warehouses_alone() {
        let policy: serde_json::Value = serde_json::from_str(POLICY).unwrap();
        let statements = policy["Statement"].as_array().unwrap();
        assert_eq!(statements.len(), 2);
        for statement in statements {
            assert_eq!(statement["Effect"], "Allow");
            assert_eq!(
                statement["Resource"],
                json!(["arn:aws:s3:::qd-tenant-*", "arn:aws:s3:::qd-tenant-*/*"])
            );
            for action in statement["Action"].as_array().unwrap() {
                let action = action.as_str().unwrap();
                assert!(!action.contains('*'), "{action}");
                let catalog = action.starts_with("admin:") && action.contains("Table");
                assert!(action.starts_with("s3:") || catalog, "{action}");
                assert_ne!(action, "s3:CreateBucket");
            }
        }
    }

    #[test]
    fn keys_rustfs_would_refuse_or_the_admins_are_refused() {
        let admin = keys("qd-platform-admin", "an-admin-secret-0123");
        let given = keys("Ab-_0123456789abcdefgh", "a-secret-the-agent-generated");
        assert_eq!(refused(&given, &admin), None);
        let short = keys("ab", "a-secret-the-agent-generated");
        assert!(refused(&short, &admin).is_some());
        let spaced = keys("Ab-_0123456789abcdefgh", "a secret with spaces");
        assert!(refused(&spaced, &admin).is_some());
        let theirs = keys("qd-platform-admin", "a-secret-the-agent-generated");
        assert_eq!(
            refused(&theirs, &admin),
            Some("the access key is the admin's")
        );
    }
}
