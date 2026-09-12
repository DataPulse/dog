//! Creating DNS transports based on the user’s input arguments.

use dns_transport::*;


/// A **transport type** creates a `Transport` that determines which protocols
/// should be used to send and receive DNS wire data over the network.
///
/// The encrypted transports only exist when dog is compiled with them; the
/// options parser refuses `--tls` and `--https` otherwise.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum TransportType {

    /// Send packets over UDP or TCP.
    /// UDP is used by default. If the request packet would be too large, send
    /// a TCP packet instead; if a UDP _response_ packet is truncated, try
    /// again with TCP.
    Automatic,

    /// Send packets over UDP only.
    /// If the request packet is too large or the response packet is
    /// truncated, fail with an error.
    UDP,

    /// Send packets over TCP only.
    TCP,

    /// Send encrypted DNS-over-TLS packets.
    #[cfg(feature = "with_tls")]
    TLS,

    /// Send encrypted DNS-over-HTTPS packets.
    #[cfg(feature = "with_https")]
    HTTPS,
}

impl TransportType {

    /// Creates a boxed `Transport` depending on the transport type. The
    /// parameter will be a URL for the HTTPS transport type, and a
    /// stringified address for the others.
    pub fn make_transport(self, param: String) -> Box<dyn Transport> {
        match self {
            Self::Automatic  => Box::new(AutoTransport::new(param)),
            Self::UDP        => Box::new(UdpTransport::new(param)),
            Self::TCP        => Box::new(TcpTransport::new(param)),
            #[cfg(feature = "with_tls")]
            Self::TLS        => Box::new(TlsTransport::new(param)),
            #[cfg(feature = "with_https")]
            Self::HTTPS      => Box::new(HttpsTransport::new(param)),
        }
    }

    /// Checks that a nameserver given on the command line can be used with
    /// this transport: an address with an optional port, or for HTTPS, a
    /// URL. This lets dog reject a bad one before sending anything.
    pub fn check_nameserver(self, nameserver: &str) -> Result<(), InvalidAddress> {
        match self {
            Self::Automatic | Self::UDP | Self::TCP  => parse_host_port(nameserver, 53).map(drop),
            #[cfg(feature = "with_tls")]
            Self::TLS                                => parse_host_port(nameserver, 853).map(drop),
            #[cfg(feature = "with_https")]
            Self::HTTPS                              => parse_https_url(nameserver).map(drop),
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn nameservers() {
        assert!(TransportType::Automatic.check_nameserver("1.1.1.1").is_ok());
        assert!(TransportType::UDP.check_nameserver("[::1]:5353").is_ok());
        assert!(TransportType::TCP.check_nameserver("dns.google:53").is_ok());
        assert!(TransportType::TCP.check_nameserver("dns.google:tcp").is_err());
    }

    #[cfg(feature = "with_tls")]
    #[test]
    fn tls_nameservers() {
        assert!(TransportType::TLS.check_nameserver("1.1.1.1:853").is_ok());
        assert!(TransportType::TLS.check_nameserver("1.1.1.1:").is_err());
    }

    #[cfg(feature = "with_https")]
    #[test]
    fn https_nameservers() {
        assert!(TransportType::HTTPS.check_nameserver("https://dns.google/dns-query").is_ok());
        assert!(TransportType::HTTPS.check_nameserver("dns.google").is_err());
    }
}
