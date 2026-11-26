//! `PUT /credentials/{kind}` (core decision 0078's table, as amended by
//! decision 0091's rulings 46, 50 and 51): the lake's own users whose keys
//! are given (read-only files the agent generated). Served here for
//! `query-engine` (Trino's coordinator) and `sts-issuer` (the user the
//! core calls STS `AssumeRole` with): the adapter makes or updates the
//! user **with the given keys** and answers them, and never makes keys of
//! its own. Every call is signed with the lake's admin keys the core sent
//! for it, never root, and none of them is logged.
//!
//! Each kind's user gets its canned policy ([`User`]): the objects and the
//! catalog of the installation's warehouses (`qd-tenant-*`) and nothing
//! else; no bucket made, no admin API. Verified with RustFS 1.0.5
//! (`tools/verify/rustfs_lake_users.sh`): the admin user may make the
//! three, each answers 200 again on a second run; `add-user` with another
//! secret for the same access key takes it and refuses the old one;
//! `set-user-or-group-policy` replaces a policy attached before; the STS
//! issuer's `AssumeRole` with a session policy gives credentials narrowed
//! to it.

use contracts::lake_admin::{CredentialKind, Credentials};
use serde_json::json;

use crate::rustfs::{call, code, Answer, Rustfs};

/// What a query engine may do: read and write objects, and use the
/// catalog, in the installation's warehouses alone. One line, as
/// `tools/verify/rustfs_lake_users.sh` reads it.
pub const QUERY_ENGINE_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetBucketLocation","s3:ListBucket","s3:ListBucketMultipartUploads","s3:GetObject","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":["arn:aws:s3:::qd-tenant-*","arn:aws:s3:::qd-tenant-*/*"]},{"Effect":"Allow","Action":["admin:GetTableCatalog","admin:GetTableBucket","admin:GetTableNamespace","admin:SetTableNamespace","admin:UpdateTableNamespaceProperties","admin:DeleteTableNamespace","admin:GetTable","admin:GetTableMetadata","admin:GetTableMetadataLocation","admin:CreateTable","admin:CommitTable","admin:SetTableMetadata","admin:SetTableMetadataLocation","admin:RegisterTable","admin:DeleteTable"],"Resource":["arn:aws:s3:::qd-tenant-*","arn:aws:s3:::qd-tenant-*/*"]}]}"#;

/// The STS issuer's ceiling (decision 0030; the core's
/// `infra/rustfs/issuer/policy.json`, moved here by decision 0078): every
/// job's session policy narrows it, so it holds what any grant may ask
/// (`crate::policy`) in the warehouses, and nothing else. One line, as
/// `tools/verify/rustfs_lake_users.sh` reads it.
pub const STS_ISSUER_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetBucketLocation","s3:ListBucket","s3:ListBucketMultipartUploads","s3:GetObject","s3:PutObject","s3:DeleteObject","s3:AbortMultipartUpload","s3:ListMultipartUploadParts"],"Resource":["arn:aws:s3:::qd-tenant-*","arn:aws:s3:::qd-tenant-*/*"]},{"Effect":"Allow","Action":["admin:GetTableCatalog","admin:GetTableBucket","admin:GetTableNamespace","admin:SetTableNamespace","admin:GetTable","admin:GetTableMetadata","admin:GetTableMetadataLocation","admin:CreateTable","admin:CommitTable","admin:SetTableMetadata","admin:SetTableMetadataLocation","admin:DeleteTable","admin:DeleteTableNamespace"],"Resource":["arn:aws:s3:::qd-tenant-*","arn:aws:s3:::qd-tenant-*/*"]}]}"#;

/// A kind of user whose keys are given: its canned policy's name and text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct User {
    pub policy_name: &'static str,
    pub policy: &'static str,
}

/// A query engine's user.
pub const QUERY_ENGINE: User = User {
    policy_name: "qd-query-engine",
    policy: QUERY_ENGINE_POLICY,
};

/// The STS issuer's user, its policy named as the core's script named it.
pub const STS_ISSUER: User = User {
    policy_name: "qd-sts-issuer",
    policy: STS_ISSUER_POLICY,
};

/// The user of `kind`, if this adapter serves it.
pub fn served(kind: CredentialKind) -> Option<User> {
    match kind {
        CredentialKind::QueryEngine => Some(QUERY_ENGINE),
        CredentialKind::StsIssuer => Some(STS_ISSUER),
        _ => None,
    }
}

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

/// Makes `user`'s user with `given`, or updates it to them, and attaches
/// its policy: the same calls on every run, each a no-op when it already
/// holds.
pub async fn ensure(
    lake: &Rustfs,
    user_kind: User,
    admin: &Credentials,
    given: &Credentials,
) -> Result<(), Failed> {
    let base = lake.base(&lake.source);
    let name = [("name", user_kind.policy_name)];
    let mut policy = call(&base, "PUT", admin_path("add-canned-policy"), &name);
    policy.body = user_kind.policy.as_bytes().to_vec();
    passed(STEP_POLICY, lake.send(admin, policy).await)?;

    let user_query = [("accessKey", given.access_key.as_str())];
    let mut user = call(&base, "PUT", admin_path("add-user"), &user_query);
    let body = json!({ "secretKey": given.secret_key, "status": "enabled" });
    user.body = body.to_string().into_bytes();
    passed(STEP_USER, lake.send(admin, user).await)?;

    let attach_query = [
        ("policyName", user_kind.policy_name),
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
    fn each_policy_names_the_warehouses_alone() {
        for user in [QUERY_ENGINE, STS_ISSUER] {
            warehouses_alone(user.policy);
        }
        assert_ne!(QUERY_ENGINE.policy_name, STS_ISSUER.policy_name);
        assert_eq!(served(CredentialKind::Root), None);
        assert_eq!(served(CredentialKind::Admin), None);
    }

    fn warehouses_alone(policy: &str) {
        let policy: serde_json::Value = serde_json::from_str(policy).unwrap();
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
