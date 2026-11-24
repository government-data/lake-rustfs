//! mTLS both ways with the installation's CA (decision 0078, `lake-admin/1`'s
//! auth): the adapter presents its machine's certificate and asks every
//! caller for one of the CA. Which role may call is the router's to say;
//! here the caller's role is read from its certificate's `OU` (0066).
//!
//! The certificate is the node agent's: `ca.crt` and `machine.pem` (the
//! certificate then the key) in its directory, renamed whole at each
//! renewal, so they are read again whenever either changes.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::extract::connect_info::Connected;
use axum::serve::{IncomingStream, Listener};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// How long a caller has to finish the handshake.
const HANDSHAKE: Duration = Duration::from_secs(10);

/// Where the adapter's certificate comes from.
#[derive(Debug)]
pub struct Certs {
    source: Source,
    current: Mutex<Option<(Stamp, Arc<ServerConfig>)>>,
}

#[derive(Debug)]
enum Source {
    /// The node agent's directory, read again when its files change.
    Dir(PathBuf),
    /// Given whole, as a test gives it.
    Pem { ca: String, bundle: String },
}

type Stamp = Option<(SystemTime, SystemTime)>;

impl Certs {
    /// `ca.crt` and `machine.pem` in `dir`.
    pub fn from_dir(dir: impl Into<PathBuf>) -> Self {
        Self::new(Source::Dir(dir.into()))
    }

    /// The CA's certificate and the adapter's own (certificate then key).
    pub fn from_pem(ca: &str, bundle: &str) -> Self {
        Self::new(Source::Pem {
            ca: ca.to_string(),
            bundle: bundle.to_string(),
        })
    }

    fn new(source: Source) -> Self {
        Self {
            source,
            current: Mutex::new(None),
        }
    }

    /// The server's configuration, built again when the files changed.
    pub fn config(&self) -> Result<Arc<ServerConfig>, String> {
        let stamp = match &self.source {
            Source::Dir(dir) => Some((
                modified(&dir.join("ca.crt"))?,
                modified(&dir.join("machine.pem"))?,
            )),
            Source::Pem { .. } => None,
        };
        let mut current = self.current.lock().map_err(|_| "a poisoned lock")?;
        if let Some((held, config)) = current.as_ref() {
            if *held == stamp {
                return Ok(config.clone());
            }
        }
        let config = Arc::new(match &self.source {
            Source::Dir(dir) => build(
                &read(&dir.join("ca.crt"))?,
                &read(&dir.join("machine.pem"))?,
            )?,
            Source::Pem { ca, bundle } => build(ca, bundle)?,
        });
        *current = Some((stamp, config.clone()));
        Ok(config)
    }
}

impl Certs {
    /// The CA's certificate and the adapter's own (certificate then key),
    /// as they are now: what the adapter presents when it calls RustFS.
    pub fn pems(&self) -> Result<(String, String), String> {
        match &self.source {
            Source::Dir(dir) => Ok((read(&dir.join("ca.crt"))?, read(&dir.join("machine.pem"))?)),
            Source::Pem { ca, bundle } => Ok((ca.clone(), bundle.clone())),
        }
    }
}

fn modified(path: &Path) -> Result<SystemTime, String> {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// A server that presents `bundle` and asks for a client certificate of
/// `ca` alone.
fn build(ca: &str, bundle: &str) -> Result<ServerConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca.as_bytes()) {
        let cert = cert.map_err(|e| format!("the CA's certificate: {e}"))?;
        roots
            .add(cert)
            .map_err(|e| format!("the CA as a root: {e}"))?;
    }
    let verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(roots.into(), provider.clone())
            .build()
            .map_err(|e| format!("a client verifier: {e}"))?;
    let chain = CertificateDer::pem_slice_iter(bundle.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("the machine's certificate: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(bundle.as_bytes())
        .map_err(|e| format!("the machine's key: {e}"))?;
    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS versions: {e}"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| format!("the machine's certificate: {e}"))
}

/// Who is calling: where from, and the role its certificate carries.
#[derive(Debug, Clone)]
pub struct Peer {
    pub addr: SocketAddr,
    pub role: Option<String>,
}

impl Connected<IncomingStream<'_, MtlsListener>> for Peer {
    fn connect_info(stream: IncomingStream<'_, MtlsListener>) -> Self {
        stream.remote_addr().clone()
    }
}

/// TCP connections that finished an mTLS handshake. Each handshake runs
/// on its own, so a slow caller holds no other.
#[derive(Debug)]
pub struct MtlsListener {
    accepted: mpsc::Receiver<(TlsStream<TcpStream>, Peer)>,
    local: SocketAddr,
}

impl MtlsListener {
    pub fn new(tcp: TcpListener, certs: Arc<Certs>) -> std::io::Result<Self> {
        let local = tcp.local_addr()?;
        let (tx, accepted) = mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                let (stream, addr) = match tcp.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(error = %e, "accepting a connection");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let config = match certs.config() {
                    Ok(config) => config,
                    Err(e) => {
                        tracing::error!(error = %e, "the adapter's certificate");
                        continue;
                    }
                };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let handshake = TlsAcceptor::from(config).accept(stream);
                    match tokio::time::timeout(HANDSHAKE, handshake).await {
                        Ok(Ok(tls)) => {
                            let role = tls
                                .get_ref()
                                .1
                                .peer_certificates()
                                .and_then(|c| c.first())
                                .and_then(role_of);
                            let _ = tx.send((tls, Peer { addr, role })).await;
                        }
                        Ok(Err(e)) => {
                            tracing::info!(peer = %addr, error = %e, "a handshake refused")
                        }
                        Err(_) => tracing::info!(peer = %addr, "a handshake timed out"),
                    }
                });
            }
        });
        Ok(Self { accepted, local })
    }
}

impl Listener for MtlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = Peer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.accepted.recv().await {
            Some(pair) => pair,
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(Peer {
            addr: self.local,
            role: None,
        })
    }
}

/// A certificate's `OU`: the machine's role (0066).
fn role_of(der: &CertificateDer<'_>) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).ok()?;
    let ou = cert.subject().iter_organizational_unit().next()?;
    ou.as_str().ok().map(str::to_string)
}
