//! Opening TLS connections, for the TLS and HTTPS transports.

use std::net::TcpStream;
use std::time::Duration;

use native_tls::{HandshakeError, TlsConnector, TlsStream};

use super::{net, Error};


/// Connects to the host and port and performs a TLS handshake, all within
/// the timeout, trusting the certificates the system’s TLS library trusts.
pub(crate) fn connect(host: &str, port: u16, timeout: Duration) -> Result<TlsStream<TcpStream>, Error> {
    let connector = TlsConnector::new().map_err(Error::TlsError)?;
    let stream = net::connect_tcp(host, port, timeout)?;
    connector.connect(host, stream).map_err(|e| handshake_error(e, timeout))
}

/// A socket whose timeout runs out during the handshake reports that the
/// handshake would block, which for dog’s blocking sockets means it timed out.
fn handshake_error(error: HandshakeError<TcpStream>, timeout: Duration) -> Error {
    match error {
        HandshakeError::WouldBlock(_)        => Error::Timeout(timeout),
        failure @ HandshakeError::Failure(_) => Error::TlsHandshakeError(failure),
    }
}
