//! The adapter's own RustFS (decision 0078, step 11): its S3 and admin
//! APIs, each call signed with the admin keys the core sent for it, held
//! for that call alone (point 9). Verified with RustFS 1.0.5
//! (`tools/verify/rustfs_replication_gate.sh`): refused keys are a 403
//! with `SignatureDoesNotMatch`, `InvalidAccessKeyId` or `AccessDenied`.
//! No key, secret or signature is logged or answered.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use contracts::lake_admin::Credentials;

use crate::tls::Certs;

/// The port a lake node's gate listens on: its compose file publishes it
/// as `RUSTFS_PORT`, 9000 unless a person changed it.
pub const GATE_PORT: u16 = 9000;

/// How the adapter reaches RustFS.
#[derive(Debug, Clone)]
enum Http {
    /// The installation's CA trusted and the machine's certificate
    /// presented, both read again when renewed.
    Certs(Arc<Certs>),
    /// A client given whole, as a test gives it.
    Fixed(reqwest::Client),
}

/// The lake this adapter serves, and how it reaches it and the replica.
#[derive(Debug, Clone)]
pub struct Rustfs {
    /// Its own RustFS's base URL, through its gate.
    pub(crate) source: String,
    /// Its machine's name, as the replication reaches it.
    pub(crate) node: String,
    http: Http,
    scheme: &'static str,
    port: u16,
}

impl Rustfs {
    /// RustFS at `source`, on the machine `node`, reached with the
    /// adapter's certificate; another lake's node on [`GATE_PORT`].
    pub fn new(source: &str, node: &str, certs: Arc<Certs>) -> Self {
        Self {
            source: source.trim_end_matches('/').to_string(),
            node: node.to_string(),
            http: Http::Certs(certs),
            scheme: "https",
            port: GATE_PORT,
        }
    }

    /// With `http` as it is, another lake's node reached over `scheme` on
    /// `port` (tests).
    pub fn with_client(mut self, http: reqwest::Client, scheme: &'static str, port: u16) -> Self {
        self.http = Http::Fixed(http);
        self.scheme = scheme;
        self.port = port;
        self
    }

    /// Another lake's node reached over `scheme` on `port`.
    pub fn at(mut self, scheme: &'static str, port: u16) -> Self {
        self.scheme = scheme;
        self.port = port;
        self
    }

    /// Where `node` answers: a base URL as it is, or a node's name on the
    /// gate's port.
    pub(crate) fn base(&self, node: &str) -> String {
        if node.contains("://") {
            node.trim_end_matches('/').to_string()
        } else {
            format!("{}://{node}:{}", self.scheme, self.port)
        }
    }

    fn client(&self) -> Result<reqwest::Client, String> {
        match &self.http {
            Http::Fixed(http) => Ok(http.clone()),
            Http::Certs(certs) => {
                let (ca, bundle) = certs.pems()?;
                let ca =
                    reqwest::Certificate::from_pem(ca.as_bytes()).map_err(|e| e.to_string())?;
                let me =
                    reqwest::Identity::from_pem(bundle.as_bytes()).map_err(|e| e.to_string())?;
                reqwest::Client::builder()
                    .use_rustls_tls()
                    .add_root_certificate(ca)
                    .identity(me)
                    .timeout(Duration::from_secs(10))
                    .build()
                    .map_err(|e| e.to_string())
            }
        }
    }

    /// One call signed with `keys` (service `s3`, the length, the host,
    /// the payload's hash and the date, as RustFS checks them).
    pub(crate) async fn send(&self, keys: &Credentials, call: Call<'_>) -> Answer {
        let url = format!("{}{}", call.base, call.path);
        let host = sigv4::host(&url).ok_or_else(|| format!("not a lake's address: {url}"))?;
        let hash = sigv4::payload_hash(&call.body);
        let length = call.body.len().to_string();
        let mut headers = vec![
            ("content-length", length.as_str()),
            ("host", host.as_str()),
            ("x-amz-content-sha256", hash.as_str()),
        ];
        headers.extend(call.headers.iter().copied());
        let query: Vec<(&str, &str)> = call.query.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let request = sigv4::Request {
            method: call.method,
            path: &call.path,
            query: &query,
            headers: &headers,
        };
        let signed = sigv4::sign_request(
            "s3",
            &keys.access_key,
            &keys.secret_key,
            &request,
            Utc::now(),
        );
        let qs = sigv4::query_string(&query);
        let full = if qs.is_empty() {
            url
        } else {
            format!("{url}?{qs}")
        };
        let method =
            reqwest::Method::from_bytes(call.method.as_bytes()).map_err(|e| e.to_string())?;
        let mut req = self.client()?.request(method, &full);
        for (name, value) in headers.iter().filter(|(n, _)| *n != "host") {
            req = req.header(*name, *value);
        }
        let sent = req
            .header("x-amz-date", &signed.date)
            .header("authorization", &signed.authorization)
            .body(call.body)
            .send()
            .await
            .map_err(|e| chain(&e))?;
        let status = sent.status().as_u16();
        let text = sent.text().await.map_err(|e| chain(&e))?;
        Ok((status, text))
    }
}

/// One signed call: where, what, and the body.
pub(crate) struct Call<'a> {
    pub(crate) base: &'a str,
    pub(crate) method: &'a str,
    pub(crate) path: String,
    pub(crate) query: Vec<(&'a str, String)>,
    pub(crate) headers: Vec<(&'a str, &'a str)>,
    pub(crate) body: Vec<u8>,
}

/// A call of `method` to `path` at `base`, with `query`.
pub(crate) fn call<'a>(
    base: &'a str,
    method: &'a str,
    path: String,
    query: &[(&'a str, &str)],
) -> Call<'a> {
    Call {
        base,
        method,
        path,
        query: query.iter().map(|(k, v)| (*k, v.to_string())).collect(),
        headers: Vec::new(),
        body: Vec::new(),
    }
}

/// What a call answered, or why it was not answered.
pub(crate) type Answer = Result<(u16, String), String>;

/// An S3 error's `<Code>`, or nothing.
pub(crate) fn code(xml: &str) -> String {
    roxmltree::Document::parse(xml)
        .ok()
        .and_then(|doc| {
            let node = doc.descendants().find(|n| n.has_tag_name("Code"))?;
            node.text().map(str::to_string)
        })
        .unwrap_or_default()
}

/// An error and its causes, in a few words: the address and what failed
/// (a refused connection, a certificate, a timeout), never a header.
pub(crate) fn chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut words = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        words.push_str(": ");
        words.push_str(&c.to_string());
        cause = c.source();
    }
    words.chars().take(300).collect()
}
