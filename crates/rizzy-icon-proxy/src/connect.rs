// SPDX-License-Identifier: AGPL-3.0-only

//! Connecting to an upstream host: resolve once, check every address, connect to exactly one
//! checked address, then TLS ([ADR 0052] point 2; INV-51; INV-77).
//!
//! [`PinnedTls`] is the production [`Connector`]:
//!
//! 1. resolve `(host, 443)` with the OS resolver (`tokio::net::lookup_host`), within
//!    [`RESOLVE_TIMEOUT`], reading at most [`MAX_ADDRESSES`] answers;
//! 2. take the first answer that passes the INV-51 allow-list
//!    ([`crate::allow::pick_address`]), refusing when none does;
//! 3. open TCP to exactly that address within [`CONNECT_TIMEOUT`], never resolving again (DNS
//!    rebinding cannot swap the address after the check);
//! 4. run TLS 1.3 over that connection with [`client_config`], verifying the certificate
//!    against the **hostname**, not the address.
//!
//! The breach check passes only port 443: plain HTTP is never used for it (INV-77). Tests
//! implement [`Connector`] themselves to reach a local fake upstream; no setting can do that.
//!
//! [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::allow::{HTTPS_PORT, pick_address};

/// How long the OS resolver may take.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the TCP connection and the TLS handshake may take, together.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// At most this many resolved addresses are read and checked.
pub const MAX_ADDRESSES: usize = 32;

/// The ALPN protocol offered: HTTP/1.1 only.
const ALPN_HTTP_1_1: &[u8] = b"http/1.1";

/// A connection to an upstream: TLS in production, anything in tests.
pub trait Io: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

/// A boxed [`Io`].
pub type BoxIo = Box<dyn Io>;

/// The future a [`Connector`] returns.
pub type ConnectFuture<'a> = Pin<Box<dyn Future<Output = Result<BoxIo, ConnectError>> + Send + 'a>>;

/// Opens a connection to `host` on port 443.
pub trait Connector: Send + Sync {
    /// Connects to `host` (a fixed, compiled-in hostname for the breach check).
    fn connect<'a>(&'a self, host: &'a str) -> ConnectFuture<'a>;
}

/// Why a connection failed. Carries no address and no host answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectError {
    /// The name did not resolve, or the resolver timed out.
    Resolve,
    /// No resolved address passed the INV-51 allow-list.
    Refused,
    /// The TCP connection failed or timed out.
    Connect,
    /// The TLS handshake or the certificate check failed.
    Tls,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Resolve => "the upstream name did not resolve",
            Self::Refused => "no upstream address passed the allow-list",
            Self::Connect => "the upstream connection failed",
            Self::Tls => "the upstream TLS handshake failed",
        })
    }
}

impl std::error::Error for ConnectError {}

/// The rustls client configuration of [ADR 0052] point 2: TLS 1.3 only, the `ring` provider
/// passed explicitly, Mozilla's roots (`webpki-roots`) and no other trust anchor, ALPN
/// `http/1.1`, SNI on, no early data, no key log. The same settings as `rv`'s ([ADR 0030]
/// Decision 2) but this crate's own value: there is no private-CA option.
///
/// # Errors
/// rustls' error if the provider offers no TLS 1.3 suite (never with the pinned `ring`).
///
/// [ADR 0030]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0030-client-tls-rv.md
/// [ADR 0052]: https://github.com/lyuksovannyy/rizzy-vault/blob/main/docs/adr/0052-icon-proxy-role.md
pub fn client_config() -> Result<ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_HTTP_1_1.to_vec()];
    // The defaults, restated so that a change of default upstream does not change this crate.
    config.enable_sni = true;
    config.enable_early_data = false;
    config.key_log = Arc::new(rustls::NoKeyLog);
    Ok(config)
}

/// The production connector (module docs).
#[derive(Clone)]
pub struct PinnedTls {
    /// The TLS settings of [`client_config`].
    tls: TlsConnector,
}

impl fmt::Debug for PinnedTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedTls").finish_non_exhaustive()
    }
}

impl PinnedTls {
    /// A connector with [`client_config`].
    ///
    /// # Errors
    /// [`ConnectError::Tls`] if the TLS configuration cannot be built.
    pub fn new() -> Result<Self, ConnectError> {
        let config = client_config().map_err(|_| ConnectError::Tls)?;
        Ok(Self {
            tls: TlsConnector::from(Arc::new(config)),
        })
    }

    /// Steps 1–4 of the module docs.
    async fn open(&self, host: &str) -> Result<BoxIo, ConnectError> {
        let name = ServerName::try_from(host.to_owned()).map_err(|_| ConnectError::Resolve)?;
        let resolved =
            tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, HTTPS_PORT)))
                .await
                .map_err(|_| ConnectError::Resolve)?
                .map_err(|_| ConnectError::Resolve)?;
        let address =
            pick_address(resolved.take(MAX_ADDRESSES), HTTPS_PORT).ok_or(ConnectError::Refused)?;
        let handshake = async {
            let tcp = TcpStream::connect(address)
                .await
                .map_err(|_| ConnectError::Connect)?;
            let _ = tcp.set_nodelay(true);
            self.tls
                .connect(name, tcp)
                .await
                .map_err(|_| ConnectError::Tls)
        };
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, handshake)
            .await
            .map_err(|_| ConnectError::Connect)??;
        Ok(Box::new(stream))
    }
}

impl Connector for PinnedTls {
    fn connect<'a>(&'a self, host: &'a str) -> ConnectFuture<'a> {
        Box::pin(self.open(host))
    }
}

#[cfg(test)]
mod tests {
    //! The TLS settings (the connection itself needs the network; the address rule is
    //! `allow`'s).

    use super::*;

    #[test]
    fn tls_is_1_3_only_with_mozilla_roots() {
        let config = client_config().unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(config.enable_sni);
        assert!(!config.enable_early_data);
    }

    #[test]
    fn errors_name_no_address() {
        for e in [
            ConnectError::Resolve,
            ConnectError::Refused,
            ConnectError::Connect,
            ConnectError::Tls,
        ] {
            let text = e.to_string();
            assert!(!text.chars().any(|c| c.is_ascii_digit()), "{text}");
        }
    }

    #[test]
    fn a_refused_address_is_never_dialled() {
        // localhost resolves to loopback only, which the allow-list refuses: the connector
        // stops before any TCP connection (no network is used).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let connector = PinnedTls::new().unwrap();
        let result = rt.block_on(connector.connect("localhost"));
        assert!(matches!(
            result.map(|_| ()),
            Err(ConnectError::Refused | ConnectError::Resolve)
        ));
    }
}
