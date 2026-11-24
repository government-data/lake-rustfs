//! `PUT` and `GET /warehouses/{name}/replication` (decision 0078, step 11;
//! 0027, 0028 and 0066 step 11, the user's rulings of 2026-11-13): the
//! replica's bucket with object lock and a default retention, versioning
//! and a lifecycle on the source, the remote target through the source's
//! replication proxy, and the rule, without delete markers; each call
//! signed with its lake's admin keys, the core's for this call alone.
//! Verified with RustFS 1.0.5 (`tools/verify/rustfs_replication_gate.sh`,
//! `rustfs_replication_lifecycle.sh`): every step answers 200 again on a
//! second run and changes nothing, a bucket made again answers 200, the
//! target set again answers the same ARN, and no `Content-MD5` is needed
//! with the payload's hash signed. The replica's keys travel only in the
//! remote target's body, to the source.

use contracts::lake_admin::{Credentials, ReplicaTarget, ReplicationState};

use crate::rustfs::{call, Call, Rustfs};
use crate::warehouse::passed;

const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
/// The rule's id, so a person reading the bucket knows whose it is.
pub const RULE_ID: &str = "qd-replica";
/// The lifecycle rule's id.
pub const LIFECYCLE_ID: &str = "qd-noncurrent";
/// The replica's default retention, `COMPLIANCE`, in days (ruling 4).
pub const REPLICA_RETENTION_DAYS: u32 = 30;
/// After how many days the source's noncurrent versions expire (ruling 5).
pub const SOURCE_NONCURRENT_DAYS: u32 = 7;
/// The port of the source's replication proxy, on the source node's
/// loopback (`infra/rustfs/replication.yml`).
pub const PROXY_PORT: u16 = 9100;
/// The name each node of a pool maps to its own loopback for its proxy
/// (0066 step 11, ruling 5).
pub const POOL_ALIAS: &str = "qd-lake-replication";
/// The region the remote target names.
const REGION: &str = "us-east-1";

/// What a replication ended in: configured, a warehouse the source does
/// not have, or a step that failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Configured,
    NoWarehouse,
    Failed { step: String, detail: String },
}

impl Outcome {
    /// As the protocol answers it; `None` for a warehouse not there.
    pub fn state(self) -> Option<ReplicationState> {
        match self {
            Self::Configured => Some(ReplicationState::Configured),
            Self::NoWarehouse => None,
            Self::Failed { step, detail } => Some(ReplicationState::Failed { step, detail }),
        }
    }
}

/// Where the source reaches its replication proxy: a pool's nodes each
/// their own, by [`POOL_ALIAS`], plain; a single node, its own name, over
/// TLS; on [`PROXY_PORT`].
pub fn proxy(node: &str, pool: bool) -> (String, bool) {
    if pool {
        (format!("{POOL_ALIAS}:{PROXY_PORT}"), false)
    } else {
        (format!("{node}:{PROXY_PORT}"), true)
    }
}

/// The replica's default retention, `COMPLIANCE`.
pub fn retention_xml() -> String {
    format!(
        "<ObjectLockConfiguration xmlns=\"{S3_XMLNS}\"><ObjectLockEnabled>Enabled</ObjectLockEnabled>\
         <Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>{REPLICA_RETENTION_DAYS}</Days>\
         </DefaultRetention></Rule></ObjectLockConfiguration>"
    )
}

/// Versioning on the source.
pub fn versioning_xml() -> String {
    format!("<VersioningConfiguration xmlns=\"{S3_XMLNS}\"><Status>Enabled</Status></VersioningConfiguration>")
}

/// The source's noncurrent versions expire.
pub fn lifecycle_xml() -> String {
    format!(
        "<LifecycleConfiguration xmlns=\"{S3_XMLNS}\"><Rule><ID>{LIFECYCLE_ID}</ID>\
         <Filter><Prefix></Prefix></Filter><Status>Enabled</Status><NoncurrentVersionExpiration>\
         <NoncurrentDays>{SOURCE_NONCURRENT_DAYS}</NoncurrentDays></NoncurrentVersionExpiration>\
         </Rule></LifecycleConfiguration>"
    )
}

/// The rule: everything, to the target, without delete markers.
pub fn rule_xml(arn: &str) -> String {
    let arn = xml_escape(arn);
    format!(
        "<ReplicationConfiguration xmlns=\"{S3_XMLNS}\"><Role>{arn}</Role><Rule><ID>{RULE_ID}</ID>\
         <Status>Enabled</Status><Priority>1</Priority><Filter><Prefix></Prefix></Filter>\
         <DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>\
         <Destination><Bucket>{arn}</Bucket></Destination></Rule></ReplicationConfiguration>"
    )
}

/// The remote target's body: the replica's keys, given to the source.
pub fn target_json(warehouse: &str, proxy: &(String, bool), replica: &Credentials) -> String {
    serde_json::json!({
        "endpoint": proxy.0,
        "secure": proxy.1,
        "targetbucket": warehouse,
        "type": "replication",
        "region": REGION,
        "credentials": { "accessKey": replica.access_key, "secretKey": replica.secret_key },
    })
    .to_string()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// A `PUT` of a bucket's configuration `sub` (`?versioning`, …) with `body`.
fn put_xml<'a>(base: &'a str, bucket: &str, sub: &'a str, body: String) -> Call<'a> {
    let mut c = call(base, "PUT", bucket.to_string(), &[(sub, "")]);
    c.body = body.into_bytes();
    c
}

/// Replicates `warehouse` of this lake into `target`, with this lake's
/// keys (`source`) and the replica's.
pub async fn configure(
    lake: &Rustfs,
    warehouse: &str,
    target: &ReplicaTarget,
    source: &Credentials,
    replica: &Credentials,
) -> Outcome {
    match steps(lake, warehouse, target, source, replica).await {
        Ok(outcome) => outcome,
        Err((step, detail)) => Outcome::Failed { step, detail },
    }
}

async fn steps(
    lake: &Rustfs,
    warehouse: &str,
    target: &ReplicaTarget,
    source: &Credentials,
    replica: &Credentials,
) -> Result<Outcome, (String, String)> {
    let (src, dst) = (lake.base(&lake.source), lake.base(&target.endpoint));
    let bucket = format!("/{warehouse}");
    match lake
        .send(source, call(&src, "HEAD", bucket.clone(), &[]))
        .await
    {
        Ok((404, _)) => return Ok(Outcome::NoWarehouse),
        other => passed("source_bucket", other)?,
    };
    let mut make = call(&dst, "PUT", bucket.clone(), &[]);
    make.headers
        .push(("x-amz-bucket-object-lock-enabled", "true"));
    passed("replica_bucket", lake.send(replica, make).await)?;
    let lock = put_xml(&dst, &bucket, "object-lock", retention_xml());
    passed("replica_retention", lake.send(replica, lock).await)?;
    let versioning = put_xml(&src, &bucket, "versioning", versioning_xml());
    passed("source_versioning", lake.send(source, versioning).await)?;
    let lifecycle = put_xml(&src, &bucket, "lifecycle", lifecycle_xml());
    passed("source_lifecycle", lake.send(source, lifecycle).await)?;
    let path = "/rustfs/admin/v3/set-remote-target".to_string();
    let mut remote = call(&src, "PUT", path, &[("bucket", warehouse)]);
    let proxy = proxy(&lake.node, target.source_pool);
    remote.body = target_json(warehouse, &proxy, replica).into_bytes();
    let arn = passed("remote_target", lake.send(source, remote).await)?;
    let arn = arn.trim().trim_matches('"').to_string();
    if !arn.starts_with("arn:") {
        return Err(("remote_target".into(), "no ARN in the answer".into()));
    }
    let rule = put_xml(&src, &bucket, "replication", rule_xml(&arn));
    passed("rule", lake.send(source, rule).await)?;
    Ok(Outcome::Configured)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bodies_say_what_was_ruled() {
        assert!(retention_xml().contains("<Mode>COMPLIANCE</Mode><Days>30</Days>"));
        assert!(lifecycle_xml().contains("<NoncurrentDays>7</NoncurrentDays>"));
        assert!(versioning_xml().contains("<Status>Enabled</Status>"));
        let rule = rule_xml("arn:minio:replication:us-east-1:x:qd-tenant-a");
        assert!(rule.contains("<DeleteMarkerReplication><Status>Disabled</Status>"));
        assert!(rule.contains("<Role>arn:minio:replication:us-east-1:x:qd-tenant-a</Role>"));
        assert!(rule.contains(
            "<Destination><Bucket>arn:minio:replication:us-east-1:x:qd-tenant-a</Bucket>"
        ));
        assert!(rule_xml("a<b&c").contains("<Role>a&lt;b&amp;c</Role>"));
    }

    #[test]
    fn a_pools_target_is_its_alias_without_tls_and_a_single_nodes_its_name_with() {
        let keys = Credentials {
            access_key: "qd-platform-admin".into(),
            secret_key: "0".repeat(64),
        };
        let target = |pool: bool| {
            let body = target_json("qd-tenant-a", &proxy("lake-1", pool), &keys);
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            (body["endpoint"].clone(), body["secure"].clone())
        };
        assert_eq!(
            target(true),
            ("qd-lake-replication:9100".into(), false.into())
        );
        assert_eq!(target(false), ("lake-1:9100".into(), true.into()));
    }
}
