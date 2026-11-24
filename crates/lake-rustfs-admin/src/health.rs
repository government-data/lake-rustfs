//! `GET /health` (decision 0078, step 11): RustFS's admin `info`, signed
//! with the admin keys the core sent. Verified on 2026-11-13 with RustFS
//! 1.0.5 (`tools/verify/rustfs_replication_gate.sh`): `info` answers its
//! drives under `info.backend`.

use contracts::lake_admin::{Credentials, ErrorCode, Health};

use crate::routes::Error;
use crate::rustfs::{call, code, Rustfs};

const INFO: &str = "/rustfs/admin/v3/info";

/// What RustFS answers when it refuses the keys themselves.
const REFUSED: [&str; 3] = [
    "SignatureDoesNotMatch",
    "InvalidAccessKeyId",
    "AccessDenied",
];

/// The lake's health with `keys`; without them, nothing is asked.
pub async fn health(lake: &Rustfs, keys: Option<&Credentials>) -> Result<Health, Error> {
    let Some(keys) = keys else {
        return Ok(Health::NoKeys);
    };
    let what = "GET health";
    let base = lake.base(&lake.source);
    let answer = lake.send(keys, call(&base, "GET", INFO.into(), &[])).await;
    let (status, text) =
        answer.map_err(|detail| Error::new(ErrorCode::Lake, format!("{what}: {detail}")))?;
    read(status, &text).map_err(|detail| Error::new(ErrorCode::Lake, format!("{what}: {detail}")))
}

/// What `info`'s answer says, or why it says nothing.
fn read(status: u16, text: &str) -> Result<Health, String> {
    let code = code(text);
    if status == 403 && REFUSED.contains(&code.as_str()) {
        return Ok(Health::KeysRefused { code });
    }
    if status != 200 {
        return Err(format!("HTTP {status} {code}").trim_end().to_string());
    }
    let body: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
    let backend = &body["info"]["backend"];
    let count = |name: &str| backend[name].as_u64().and_then(|n| u32::try_from(n).ok());
    match (count("onlineDisks"), count("offlineDisks")) {
        (Some(drives_online), Some(drives_offline)) => Ok(Health::Answered {
            drives_online,
            drives_offline,
        }),
        _ => Err("info without its drives".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_drives_and_the_refusals() {
        let info =
            r#"{"info":{"backend":{"backendType":"Erasure","onlineDisks":2,"offlineDisks":1}}}"#;
        let drives = Health::Answered {
            drives_online: 2,
            drives_offline: 1,
        };
        assert_eq!(read(200, info), Ok(drives));
        let error = |c: &str| format!("<Error><Code>{c}</Code><Message>m</Message></Error>");
        for c in REFUSED {
            let refused = Health::KeysRefused { code: c.into() };
            assert_eq!(read(403, &error(c)), Ok(refused));
        }
        assert_eq!(
            read(403, &error("Forbidden")),
            Err("HTTP 403 Forbidden".into())
        );
        assert_eq!(read(502, "Bad Gateway"), Err("HTTP 502".into()));
        assert_eq!(read(200, "{}"), Err("info without its drives".into()));
    }
}
