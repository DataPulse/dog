//! Reading the nameserver addresses that users give.

use std::fmt;
use std::net::Ipv6Addr;


/// A nameserver address that cannot be used, with the reason why.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct InvalidAddress(String);

impl fmt::Display for InvalidAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<InvalidAddress> for super::Error {
    fn from(invalid: InvalidAddress) -> Self {
        Self::InvalidNameserver(invalid.0)
    }
}


/// Splits a nameserver address into its host and port. It can be a host
/// alone, `host:port`, a bare IPv6 address, or `[IPv6 address]:port`; the
/// port defaults to `default_port`.
///
/// # Errors
///
/// Returns an error if there is no host, the port is not a number that fits
/// in 16 bits, or an IPv6 bracket is not closed.
pub fn parse_host_port(addr: &str, default_port: u16) -> Result<(&str, u16), InvalidAddress> {
    if addr.parse::<Ipv6Addr>().is_ok() {
        return Ok((addr, default_port));
    }

    let (host, port) = match addr.strip_prefix('[') {
        Some(bracketed) => split_bracketed(addr, bracketed)?,
        None            => addr.rsplit_once(':').map_or((addr, None), |(host, port)| (host, Some(port))),
    };

    if host.is_empty() {
        return Err(invalid(addr, "it has no host"));
    }

    match port {
        None        => Ok((host, default_port)),
        Some(port)  => port.parse().map(|port| (host, port)).map_err(|_| invalid(addr, "its port is not a number from 0 to 65535")),
    }
}

/// Splits `[host]:port` or `[host]`, given what follows the `[`.
fn split_bracketed<'a>(addr: &str, bracketed: &'a str) -> Result<(&'a str, Option<&'a str>), InvalidAddress> {
    let (host, rest) = bracketed.split_once(']')
        .ok_or_else(|| invalid(addr, "its '[' is never closed"))?;

    match rest.strip_prefix(':') {
        Some(port)                => Ok((host, Some(port))),
        None if rest.is_empty()   => Ok((host, None)),
        None                      => Err(invalid(addr, "something other than a port follows its ']'")),
    }
}

fn invalid(addr: &str, reason: &str) -> InvalidAddress {
    InvalidAddress(format!("Invalid nameserver {addr:?}: {reason}"))
}


/// The parts of a DNS-over-HTTPS URL, `https://host[:port]/path`.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct HttpsUrl<'a> {

    /// The server’s host name or address.
    pub host: &'a str,

    /// The server’s port, 443 unless the URL says otherwise.
    pub port: u16,

    /// The path to send requests to, starting with `/`.
    pub path: &'a str,
}

/// Splits a DNS-over-HTTPS URL into its host, port, and path.
///
/// # Errors
///
/// Returns an error if the URL is not `https`, has no path, or has an
/// invalid host or port.
pub fn parse_https_url(url: &str) -> Result<HttpsUrl<'_>, InvalidAddress> {
    let rest = url.strip_prefix("https://")
        .ok_or_else(|| invalid_url(url, "it does not start with 'https://'"))?;

    let slash = rest.find('/')
        .ok_or_else(|| invalid_url(url, "it has no path, such as '/dns-query'"))?;

    let (authority, path) = rest.split_at(slash);
    let (host, port) = parse_host_port(authority, 443)
        .map_err(|_| invalid_url(url, "its host or port is not valid"))?;

    Ok(HttpsUrl { host, port, path })
}

fn invalid_url(url: &str, reason: &str) -> InvalidAddress {
    InvalidAddress(format!("Invalid DNS-over-HTTPS URL {url:?}: {reason}"))
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::Error;

    fn message<T: fmt::Debug>(result: Result<T, InvalidAddress>) -> String {
        result.unwrap_err().to_string()
    }

    #[test]
    fn hosts_and_ports() {
        assert_eq!(parse_host_port("dns.google", 53).unwrap(), ("dns.google", 53));
        assert_eq!(parse_host_port("1.1.1.1", 853).unwrap(), ("1.1.1.1", 853));
        assert_eq!(parse_host_port("1.1.1.1:5353", 53).unwrap(), ("1.1.1.1", 5353));
        assert_eq!(parse_host_port("localhost:0", 53).unwrap(), ("localhost", 0));
        assert_eq!(parse_host_port("::1", 53).unwrap(), ("::1", 53));
        assert_eq!(parse_host_port("2001:db8::53", 853).unwrap(), ("2001:db8::53", 853));
        assert_eq!(parse_host_port("[::1]", 53).unwrap(), ("::1", 53));
        assert_eq!(parse_host_port("[2001:db8::53]:5353", 53).unwrap(), ("2001:db8::53", 5353));
    }

    #[test]
    fn invalid_addresses() {
        assert_eq!(message(parse_host_port("127.0.0.1:dns", 53)), r#"Invalid nameserver "127.0.0.1:dns": its port is not a number from 0 to 65535"#);
        assert_eq!(message(parse_host_port("127.0.0.1:", 53)), r#"Invalid nameserver "127.0.0.1:": its port is not a number from 0 to 65535"#);
        assert_eq!(message(parse_host_port("127.0.0.1:65536", 53)), r#"Invalid nameserver "127.0.0.1:65536": its port is not a number from 0 to 65535"#);
        assert_eq!(message(parse_host_port("", 53)), r#"Invalid nameserver "": it has no host"#);
        assert_eq!(message(parse_host_port(":53", 53)), r#"Invalid nameserver ":53": it has no host"#);
        assert_eq!(message(parse_host_port("[::1", 53)), r#"Invalid nameserver "[::1": its '[' is never closed"#);
        assert_eq!(message(parse_host_port("[::1]53", 53)), r#"Invalid nameserver "[::1]53": something other than a port follows its ']'"#);
        assert_eq!(message(parse_host_port("[]:53", 53)), r#"Invalid nameserver "[]:53": it has no host"#);
    }

    #[test]
    fn https_urls() {
        assert_eq!(parse_https_url("https://cloudflare-dns.com/dns-query").unwrap(),
                   HttpsUrl { host: "cloudflare-dns.com", port: 443, path: "/dns-query" });
        assert_eq!(parse_https_url("https://localhost:8443/").unwrap(),
                   HttpsUrl { host: "localhost", port: 8443, path: "/" });
        assert_eq!(parse_https_url("https://[::1]:8443/dns-query?x=1").unwrap(),
                   HttpsUrl { host: "::1", port: 8443, path: "/dns-query?x=1" });
    }

    #[test]
    fn invalid_https_urls() {
        assert_eq!(message(parse_https_url("http://example.com/dns-query")),
                   r#"Invalid DNS-over-HTTPS URL "http://example.com/dns-query": it does not start with 'https://'"#);
        assert_eq!(message(parse_https_url("https://example.com")),
                   r#"Invalid DNS-over-HTTPS URL "https://example.com": it has no path, such as '/dns-query'"#);
        assert_eq!(message(parse_https_url("https://example.com:http/")),
                   r#"Invalid DNS-over-HTTPS URL "https://example.com:http/": its host or port is not valid"#);
        assert_eq!(message(parse_https_url("https:///dns-query")),
                   r#"Invalid DNS-over-HTTPS URL "https:///dns-query": its host or port is not valid"#);
    }

    #[test]
    fn invalid_addresses_are_invalid_nameservers() {
        let error = Error::from(parse_host_port("", 53).unwrap_err());
        assert!(matches!(error, Error::InvalidNameserver(message) if message == r#"Invalid nameserver "": it has no host"#));
    }
}
