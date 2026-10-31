//! A single HTTP client connection, plain TCP or terminated TLS.
use tokio::net::TcpStream;

/// A waiting browser connection may be plaintext HTTP or an intercepted TLS
/// session. Both must be able to receive Forward/Drop decisions.
pub enum ProxyStream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl ProxyStream {
    pub(super) async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        match self {
            Self::Plain(stream) => {
                stream.write_all(bytes).await?;
                stream.flush().await
            }
            Self::Tls(stream) => {
                stream.write_all(bytes).await?;
                stream.flush().await
            }
        }
    }
}
