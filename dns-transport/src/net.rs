//! Socket plumbing shared by the transports: connecting within a time
//! limit, and telling a timeout from any other failure.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use log::*;

use super::Error;


/// Connects to the first address of the host that accepts a connection
/// within the timeout, and sets that timeout for reading and writing too.
pub(crate) fn connect_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, Error> {
    let mut last_error = no_addresses(host);
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return configure(stream, timeout),
            Err(e) => {
                debug!("Could not connect to {addr}: {e}");
                last_error = e;
            }
        }
    }

    Err(io_error(last_error, timeout))
}

fn configure(stream: TcpStream, timeout: Duration) -> Result<TcpStream, Error> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

/// Opens a UDP socket connected to the first address of the host that it
/// can be connected to, bound to a local address of the same family.
pub(crate) fn connect_udp(host: &str, port: u16, timeout: Duration) -> Result<UdpSocket, Error> {
    let mut last_error = no_addresses(host);
    for addr in (host, port).to_socket_addrs()? {
        match open_udp(addr) {
            Ok(socket) => return Ok(socket),
            Err(e) => {
                debug!("Could not use {addr}: {e}");
                last_error = e;
            }
        }
    }

    Err(io_error(last_error, timeout))
}

fn open_udp(server: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(local_address_for(server))?;
    socket.connect(server)?;
    Ok(socket)
}

/// Any local address, on any port, of the same family as the server’s.
fn local_address_for(server: SocketAddr) -> SocketAddr {
    if server.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() }
}

fn no_addresses(host: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("{host} has no addresses"))
}

/// Turns an I/O error into a transport error, recognising both of the ways
/// a socket reports that its timeout ran out.
pub(crate) fn io_error(error: io::Error, timeout: Duration) -> Error {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Error::Timeout(timeout),
        _ => Error::NetworkError(error),
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use std::net::TcpListener;

    const TIMEOUT: Duration = Duration::from_millis(300);

    fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn timeouts_are_recognised() {
        assert!(matches!(io_error(io::ErrorKind::WouldBlock.into(), TIMEOUT), Error::Timeout(TIMEOUT)));
        assert!(matches!(io_error(io::ErrorKind::TimedOut.into(), TIMEOUT), Error::Timeout(TIMEOUT)));
        assert!(matches!(io_error(io::ErrorKind::ConnectionReset.into(), TIMEOUT), Error::NetworkError(_)));
    }

    #[test]
    fn connecting_to_a_listening_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = connect_tcp("127.0.0.1", listener.local_addr().unwrap().port(), TIMEOUT).unwrap();
        assert_eq!(stream.read_timeout().unwrap(), Some(TIMEOUT));
        assert_eq!(stream.write_timeout().unwrap(), Some(TIMEOUT));
    }

    #[test]
    fn connecting_to_a_closed_port() {
        let error = connect_tcp("127.0.0.1", closed_port(), TIMEOUT).unwrap_err();
        assert!(matches!(&error, Error::NetworkError(e) if e.kind() == io::ErrorKind::ConnectionRefused), "{error:?}");
    }

    #[test]
    fn udp_sockets_are_connected_to_the_server() {
        let socket = connect_udp("127.0.0.1", 53, TIMEOUT).unwrap();
        assert_eq!(socket.peer_addr().unwrap(), "127.0.0.1:53".parse().unwrap());
        assert!(socket.local_addr().unwrap().is_ipv4());
    }

    #[test]
    fn local_addresses_match_the_server_family() {
        assert_eq!(local_address_for("192.0.2.1:53".parse().unwrap()), "0.0.0.0:0".parse().unwrap());
        assert_eq!(local_address_for("[2001:db8::1]:53".parse().unwrap()), "[::]:0".parse().unwrap());
    }

    #[test]
    fn unusable_udp_addresses() {
        // Sending to the broadcast address needs a permission (SO_BROADCAST)
        // that a DNS client has no business asking for.
        assert!(matches!(connect_udp("255.255.255.255", 53, TIMEOUT), Err(Error::NetworkError(_))));
    }

    #[test]
    fn a_host_with_no_addresses() {
        assert_eq!(no_addresses("nowhere").to_string(), "nowhere has no addresses");
    }
}
