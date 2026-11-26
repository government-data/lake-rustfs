//! The lake admin adapter of `lake-rustfs` (decision 0078, point 8): it
//! serves `lake-admin/1` to the core's server alone, with mTLS of the
//! installation's CA both ways, and keeps no secret or state of its own
//! (point 9). Built in the core's `crates/` until it moves to the module's
//! repository (step 15); never a dependency of `server`.

use std::sync::Arc;

use tokio::net::TcpListener;

pub mod credentials;
pub mod health;
pub mod policy;
pub mod replication;
pub mod routes;
pub mod rustfs;
pub mod tls;
pub mod warehouse;

pub use rustfs::Rustfs;
pub use tls::Certs;

/// Serves `lake-admin/1` for `lake` on `tcp` until `shutdown` resolves.
pub async fn serve(
    tcp: TcpListener,
    certs: Arc<Certs>,
    lake: Arc<Rustfs>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = tls::MtlsListener::new(tcp, certs)?;
    let app = routes::router(lake).into_make_service_with_connect_info::<tls::Peer>();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}
