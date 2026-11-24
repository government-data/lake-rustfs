//! `PUT /warehouses/{name}` (decision 0078, step 11; 0028's "a tenant's
//! warehouse"): the bucket when `HEAD` says it is missing, then its Iceberg
//! table bucket, every call signed with the lake's admin keys the core
//! sent, never root. Verified with RustFS 1.0.5
//! (`tools/verify/rustfs_warehouse.sh`): the table bucket of a missing
//! bucket is refused and makes none, so the bucket goes first; both answer
//! 200 again on a second run and keep the catalog's namespaces and tables.
//! Versioning is the replication's step, not this one.

use contracts::lake_admin::{Credentials, WarehouseOutcome};

use crate::rustfs::{call, code, Answer, Rustfs};

/// The steps, as the core's list names them.
pub const BUCKET: &str = "warehouse_bucket";
pub const TABLES: &str = "warehouse_tables";

/// A step's answer: 200 passes; anything else fails it, in a few words.
pub(crate) fn passed(step: &str, answer: Answer) -> Result<String, (String, String)> {
    match answer {
        Ok((200, text)) => Ok(text),
        Ok((status, text)) => {
            let code = code(&text);
            let detail = format!("HTTP {status} {code}").trim_end().to_string();
            Err((step.to_string(), detail))
        }
        Err(detail) => Err((step.to_string(), detail)),
    }
}

/// Makes `warehouse` on this lake unless it is there.
pub async fn ensure(lake: &Rustfs, warehouse: &str, keys: &Credentials) -> WarehouseOutcome {
    match make(lake, warehouse, keys).await {
        Ok(outcome) => outcome,
        Err((step, detail)) => WarehouseOutcome::Failed { step, detail },
    }
}

async fn make(
    lake: &Rustfs,
    warehouse: &str,
    keys: &Credentials,
) -> Result<WarehouseOutcome, (String, String)> {
    let base = lake.base(&lake.source);
    let bucket = format!("/{warehouse}");
    let head = lake.send(keys, call(&base, "HEAD", bucket.clone(), &[]));
    let made = match head.await {
        Ok((404, _)) => {
            let put = lake.send(keys, call(&base, "PUT", bucket, &[])).await;
            passed(BUCKET, put)?;
            true
        }
        other => {
            passed(BUCKET, other)?;
            false
        }
    };
    let tables = format!("/iceberg/v1/buckets/{warehouse}");
    let put = lake.send(keys, call(&base, "PUT", tables, &[])).await;
    passed(TABLES, put)?;
    Ok(if made {
        WarehouseOutcome::Made
    } else {
        WarehouseOutcome::Present
    })
}
