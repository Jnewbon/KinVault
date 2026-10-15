//! Public addresses an instance owner configures themselves (a static IP or a
//! (dynamic) DNS name with a forwarded port), put in invites and dialled in
//! addition to whatever iroh discovers. Domains are resolved at every
//! connection, so a dynamic-DNS name keeps working when the IP changes.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use iroh::EndpointAddr;
use tokio::task::JoinSet;

/// Why a configured address couldn't be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid address {input:?}: {reason}")]
pub struct InvalidHostAddr {
    input: String,
    reason: &'static str,
}

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// An IP address or domain name, with an optional UDP port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostAddr {
    host: String,
    port: Option<u16>,
}

impl HostAddr {
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Fills in `port` if no port was given.
    pub fn or_port(mut self, port: u16) -> Self {
        self.port = self.port.or(Some(port));
        self
    }

    async fn resolve(&self) -> Vec<SocketAddr> {
        let Some(port) = self.port else {
            return Vec::new();
        };
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return vec![SocketAddr::new(ip, port)];
        }
        let lookup = tokio::net::lookup_host((self.host.as_str(), port));
        self.await_lookup(lookup, RESOLVE_TIMEOUT).await
    }

    /// Waits up to `timeout` for a lookup of this address.
    async fn await_lookup<I: Iterator<Item = SocketAddr>>(
        &self,
        lookup: impl Future<Output = io::Result<I>>,
        timeout: Duration,
    ) -> Vec<SocketAddr> {
        match tokio::time::timeout(timeout, lookup).await {
            Ok(Ok(addrs)) => addrs.collect(),
            Ok(Err(e)) => {
                tracing::debug!("could not resolve {self}: {e}");
                Vec::new()
            }
            Err(_) => {
                tracing::debug!("resolving {self} timed out");
                Vec::new()
            }
        }
    }
}

impl FromStr for HostAddr {
    type Err = InvalidHostAddr;

    fn from_str(s: &str) -> Result<Self, InvalidHostAddr> {
        let s = s.trim();
        let invalid = |reason| InvalidHostAddr {
            input: s.to_string(),
            reason,
        };
        let parse_port = |p: &str| match p.parse::<u16>() {
            Ok(0) | Err(_) => Err(invalid("the port must be a number from 1 to 65535")),
            Ok(port) => Ok(Some(port)),
        };
        if s.is_empty() {
            return Err(invalid("it is empty"));
        }
        // [v6] or [v6]:port
        if let Some(rest) = s.strip_prefix('[') {
            let (ip, after) = rest.split_once(']').ok_or_else(|| invalid("missing ']'"))?;
            let ip: std::net::Ipv6Addr = ip.parse().map_err(|_| invalid("bad IPv6 address"))?;
            let port = match after {
                "" => None,
                p => parse_port(
                    p.strip_prefix(':')
                        .ok_or_else(|| invalid("expected ':port'"))?,
                )?,
            };
            return Ok(Self {
                host: ip.to_string(),
                port,
            });
        }
        // A bare IP (an IPv6 address with a port needs brackets).
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self {
                host: ip.to_string(),
                port: None,
            });
        }
        let (host, port) = match s.rsplit_once(':') {
            Some((host, port)) => (host, parse_port(port)?),
            None => (s, None),
        };
        if host.contains(':') {
            return Err(invalid(
                "write IPv6 addresses with a port as [address]:port",
            ));
        }
        if host.parse::<IpAddr>().is_err() && !valid_domain(host) {
            return Err(invalid("not an IP address or domain name"));
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

impl fmt::Display for HostAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.host.contains(':'), self.port) {
            (true, Some(port)) => write!(f, "[{}]:{port}", self.host),
            (false, Some(port)) => write!(f, "{}:{port}", self.host),
            (_, None) => f.write_str(&self.host),
        }
    }
}

fn valid_domain(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Resolves `hosts` (entries without a port, or that fail to parse or
/// resolve, are skipped) and adds the results to `addr`.
pub async fn with_hosts(mut addr: EndpointAddr, hosts: &[String]) -> EndpointAddr {
    let mut lookups = JoinSet::new();
    for entry in hosts {
        match entry.parse::<HostAddr>() {
            Ok(host) => {
                lookups.spawn(async move { host.resolve().await });
            }
            Err(e) => tracing::debug!("skipping address: {e}"),
        }
    }
    while let Some(result) = lookups.join_next().await {
        for socket in result.unwrap_or_default() {
            addr = addr.with_ip_addr(socket);
        }
    }
    addr
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<String, InvalidHostAddr> {
        s.parse::<HostAddr>().map(|h| h.to_string())
    }

    #[test]
    fn parses_ips_and_domains() {
        assert_eq!(parse("203.0.113.7").unwrap(), "203.0.113.7");
        assert_eq!(parse(" 203.0.113.7:4433 ").unwrap(), "203.0.113.7:4433");
        assert_eq!(parse("2001:db8::1").unwrap(), "2001:db8::1");
        assert_eq!(parse("[2001:db8::1]").unwrap(), "2001:db8::1");
        assert_eq!(parse("[2001:db8::1]:4433").unwrap(), "[2001:db8::1]:4433");
        assert_eq!(
            parse("Home.Example.org:9000").unwrap(),
            "home.example.org:9000"
        );
        assert_eq!(parse("nas").unwrap(), "nas");

        for bad in [
            "",
            "host:0",
            "host:70000",
            "host:",
            "-bad.example",
            "under_score.example",
            "2001:db8::1:4433:x",
            "[2001:db8::1",
            "[2001:db8::1]4433",
            "http://example.org",
            "[2001:db8::1]:0",
            "a:b:80",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn default_port_only_fills_missing() {
        let h: HostAddr = "example.org".parse().unwrap();
        assert_eq!(h.or_port(1234).to_string(), "example.org:1234");
        let h: HostAddr = "example.org:80".parse().unwrap();
        assert_eq!(h.port(), Some(80));
        assert_eq!(h.or_port(1234).to_string(), "example.org:80");
    }

    #[tokio::test]
    async fn unresolvable_names_give_no_addresses() {
        let h: HostAddr = "no-such-host.invalid:80".parse().unwrap();
        assert!(h.resolve().await.is_empty());
        // Gives up on lookups that take too long.
        let never = std::future::pending::<io::Result<std::vec::IntoIter<SocketAddr>>>();
        assert!(
            h.await_lookup(never, Duration::from_millis(1))
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn resolves_into_endpoint_addr() {
        let id = iroh::SecretKey::generate().public();
        let addr = with_hosts(
            EndpointAddr::new(id),
            &[
                "192.0.2.1:4433".into(),
                "localhost:4434".into(),
                "no-port.example".into(),
                "not valid".into(),
            ],
        )
        .await;
        let ips: Vec<_> = addr.ip_addrs().copied().collect();
        assert!(ips.contains(&"192.0.2.1:4433".parse().unwrap()), "{ips:?}");
        assert!(
            ips.iter().any(|a| a.port() == 4434 && a.ip().is_loopback()),
            "{ips:?}"
        );
        assert!(ips.iter().all(|a| a.port() == 4433 || a.port() == 4434));
    }
}
