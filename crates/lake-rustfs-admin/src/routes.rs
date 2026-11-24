//! `lake-admin/1`'s routes (decision 0078): the caller check, `GET /about`,
//! `GET /health`, `PUT /warehouses/{name}`, its replication (`PUT`, and
//! `GET` with what waits and what failed), `POST
//! /policies/session` and the error shape. The keys an operation needs
//! come in its headers (`contracts::lake_admin::headers`), held for that
//! call alone and never logged. The other operations (the managed
//! policies, the credentials and the pools) answer
//! `404 unknown` until their steps.

use std::sync::Arc;

use axum::body::Body;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use contracts::lake_admin::{self as wire, headers, Credentials, ErrorBody, ErrorCode};
use contracts::LakeGrant;

use crate::rustfs::Rustfs;
use crate::tls::Peer;
use crate::{health, policy, replication, warehouse};

/// The only role whose certificate is answered: the core server's (0066).
pub const CALLER_ROLE: &str = "app";

/// The implementation's name, as `GET /about` gives it.
pub const IMPLEMENTATION: &str = "lake-rustfs";

/// Every route of the adapter for the lake `lake`, behind the caller check.
pub fn router(lake: Arc<Rustfs>) -> Router {
    Router::new()
        .route(&wire::paths::about(), get(about))
        .route(&wire::paths::health(), get(lake_health).fallback(unserved))
        .route(
            &wire::paths::warehouse("{name}"),
            put(ensure_warehouse).fallback(unserved),
        )
        .route(
            &wire::paths::replication("{name}"),
            put(replicate).get(replication).fallback(unserved),
        )
        .route(&wire::paths::session_policy(), post(session_policy))
        .fallback(unserved)
        .layer(middleware::from_fn(caller_check))
        .with_state(lake)
}

async fn about() -> Json<wire::About> {
    Json(wire::About {
        protocols: vec![wire::PROTOCOL.into()],
        implementation: IMPLEMENTATION.into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

/// The keys in `header`, if it came; a value that is not keys is `400`.
fn keys(map: &HeaderMap, header: &str, what: &str) -> Result<Option<Credentials>, Error> {
    let Some(value) = map.get(header) else {
        return Ok(None);
    };
    let keys = value.to_str().ok().and_then(headers::decode);
    let invalid = || Error::new(ErrorCode::Invalid, format!("{what}: {header} is not keys"));
    keys.map(Some).ok_or_else(invalid)
}

/// The keys in `header`, which the operation needs.
fn needed(map: &HeaderMap, header: &str, what: &str) -> Result<Credentials, Error> {
    let missing = || Error::new(ErrorCode::Invalid, format!("{what}: no {header}"));
    keys(map, header, what)?.ok_or_else(missing)
}

/// A warehouse's name as a bucket's: 3 to 63 of `a-z`, `0-9`, `-`, `.`.
fn checked(name: &str, what: &str) -> Result<(), Error> {
    let fits = (3..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    if fits {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCode::Invalid,
            format!("{what}: not a warehouse's name"),
        ))
    }
}

fn body<T: serde::de::DeserializeOwned>(bytes: &Bytes, what: &str) -> Result<T, Error> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::new(ErrorCode::Invalid, format!("{what}: {e}")))
}

/// The lake's health, with the admin keys if they came.
async fn lake_health(
    State(lake): State<Arc<Rustfs>>,
    map: HeaderMap,
) -> Result<Json<wire::Health>, Error> {
    let keys = keys(&map, headers::ADMIN_KEYS, "GET health")?;
    health::health(&lake, keys.as_ref()).await.map(Json)
}

/// The warehouse made unless it is there: `201` made, else `200`.
async fn ensure_warehouse(
    State(lake): State<Arc<Rustfs>>,
    Path(name): Path<String>,
    map: HeaderMap,
    bytes: Bytes,
) -> Result<Response, Error> {
    let what = format!("PUT warehouses/{name}");
    checked(&name, &what)?;
    let _: wire::RetentionRules = body(&bytes, &what)?;
    let keys = needed(&map, headers::ADMIN_KEYS, &what)?;
    let outcome = warehouse::ensure(&lake, &name, &keys).await;
    let status = match outcome {
        wire::WarehouseOutcome::Made => StatusCode::CREATED,
        _ => StatusCode::OK,
    };
    Ok((status, Json(outcome)).into_response())
}

/// The warehouse replicated into the replica, with both lakes' keys.
async fn replicate(
    State(lake): State<Arc<Rustfs>>,
    Path(name): Path<String>,
    map: HeaderMap,
    bytes: Bytes,
) -> Result<Json<wire::ReplicationState>, Error> {
    let what = format!("PUT warehouses/{name}/replication");
    checked(&name, &what)?;
    let target: wire::ReplicaTarget = body(&bytes, &what)?;
    let source = needed(&map, headers::ADMIN_KEYS, &what)?;
    let replica = needed(&map, headers::REPLICA_KEYS, &what)?;
    let outcome = replication::configure(&lake, &name, &target, &source, &replica).await;
    let unknown = || Error::new(ErrorCode::Unknown, format!("{what}: no such warehouse"));
    outcome.state().map(Json).ok_or_else(unknown)
}

/// How far behind the warehouse's replication is; changes nothing.
async fn replication(
    State(lake): State<Arc<Rustfs>>,
    Path(name): Path<String>,
    map: HeaderMap,
) -> Result<Json<wire::ReplicationSync>, Error> {
    let what = format!("GET warehouses/{name}/replication");
    checked(&name, &what)?;
    let keys = needed(&map, headers::ADMIN_KEYS, &what)?;
    let sync = replication::sync(&lake, &name, &keys).await;
    let lake_error = |e: String| Error::new(ErrorCode::Lake, format!("{what}: {e}"));
    let unknown = || Error::new(ErrorCode::Unknown, format!("{what}: no such warehouse"));
    sync.map_err(lake_error)?.map(Json).ok_or_else(unknown)
}

/// A grant in RustFS's dialect; changes nothing. The policy is answered,
/// never logged.
async fn session_policy(body: Bytes) -> Result<Json<wire::SessionPolicy>, Error> {
    let what = "POST policies/session";
    let grant: LakeGrant = serde_json::from_slice(&body)
        .map_err(|e| Error::new(ErrorCode::Invalid, format!("{what}: not a grant: {e}")))?;
    let policy = policy::session_policy(&grant).map_err(|e| {
        let message = format!("{what} on {}: {}", grant.warehouse, e.0);
        Error::new(ErrorCode::Invalid, message)
    })?;
    Ok(Json(wire::SessionPolicy { policy }))
}

async fn unserved(method: Method, request: Request<Body>) -> Error {
    let path = request.uri().path();
    Error::new(ErrorCode::Unknown, format!("{method} {path}: not served"))
}

/// Refuses any caller but the core server, then logs what was answered:
/// the operation, its status and code, never a body.
async fn caller_check(
    ConnectInfo(peer): ConnectInfo<Peer>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let operation = format!("{} {}", request.method(), request.uri().path());
    let response = if peer.role.as_deref() == Some(CALLER_ROLE) {
        next.run(request).await
    } else {
        let message = format!("{operation}: not the core server's certificate");
        Error::new(ErrorCode::Refused, message).into_response()
    };
    let status = response.status().as_u16();
    match code_of(status) {
        Some(code) => {
            tracing::warn!(%operation, status, code = ?code, role = ?peer.role, "answered")
        }
        None => tracing::info!(%operation, status, "answered"),
    }
    response
}

fn code_of(status: u16) -> Option<ErrorCode> {
    [
        ErrorCode::Invalid,
        ErrorCode::Refused,
        ErrorCode::Unknown,
        ErrorCode::Conflict,
        ErrorCode::Lake,
        ErrorCode::Unavailable,
    ]
    .into_iter()
    .find(|c| c.status() == status)
}

/// A non-2xx answer in the protocol's shape. Its message names the
/// operation and the warehouse or pool, never a key or a policy.
#[derive(Debug)]
pub struct Error(ErrorBody);

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self(ErrorBody::new(code, message))
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.code.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self.0)).into_response()
    }
}
