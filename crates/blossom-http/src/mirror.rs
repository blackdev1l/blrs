use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

/// A rejected `PUT /mirror` origin.
///
/// BUD-04 calls out server-side request forgery explicitly: the endpoint
/// fetches a user-supplied URL, so the destination address must be checked on
/// every connection, including after DNS resolution and across redirects.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MirrorError {
    #[error("the origin URL is invalid")]
    BadUrl,
    #[error("only http and https origins may be mirrored")]
    BadScheme,
    #[error("the origin resolved to a disallowed address")]
    DisallowedAddress,
}

/// Rejects non-http(s) schemes, credentials, and absent hosts.
///
/// Address policy is deliberately separate: a hostname has no address until it
/// is resolved, and this function must stay usable on redirect targets whose
/// address is only known after [`check_addresses`] runs on the resolution.
pub fn check_url(url: &Url, _allow_private: bool) -> Result<(), MirrorError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(MirrorError::BadScheme);
    }
    // Credentials in the URL would be forwarded to the origin and can be used
    // to smuggle a host expression past a naive check; refuse them outright.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(MirrorError::BadUrl);
    }
    if url.host_str().is_none() {
        return Err(MirrorError::BadUrl);
    }
    Ok(())
}

/// Rejects loopback, private, link-local, and unspecified addresses.
///
/// Applied to the full resolved address list before connecting, so a hostname
/// resolving to a mix of public and private addresses is refused outright.
pub fn check_addresses(addrs: &[IpAddr], allow_private: bool) -> Result<(), MirrorError> {
    if allow_private {
        return Ok(());
    }
    if addrs.iter().any(|addr| is_disallowed(*addr)) {
        return Err(MirrorError::DisallowedAddress);
    }
    Ok(())
}

/// Whether an address may not be reached by `/mirror`.
fn is_disallowed(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_disallowed_v4(v4),
        IpAddr::V6(v6) => {
            // `::ffff:a.b.c.d` is how an IPv4 destination is carried over an
            // IPv6 socket; unwrap it so the IPv4 policy applies.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_disallowed_v4(v4);
            }
            is_disallowed_v6(v6)
        }
    }
}

fn is_disallowed_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()          // 127.0.0.0/8
        || v4.is_private()    // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local() // 169.254.0.0/16, cloud metadata
        || v4.is_unspecified()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_documentation() // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
}

fn is_disallowed_v6(v6: Ipv6Addr) -> bool {
    // `is_unique_local`/`is_unicast_link_local` are newer than this crate's
    // MSRV, so test the prefixes on the first segment directly.
    const UNIQUE_LOCAL: u16 = 0xfc00;
    const UNIQUE_LOCAL_MASK: u16 = 0xfe00;
    const LINK_LOCAL: u16 = 0xfe80;
    const LINK_LOCAL_MASK: u16 = 0xffc0;
    let first = v6.segments()[0];
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || (first & UNIQUE_LOCAL_MASK) == UNIQUE_LOCAL // fc00::/7
        || (first & LINK_LOCAL_MASK) == LINK_LOCAL // fe80::/10
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    const PUBLIC_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0, 0, 0, 0, 0, 1));

    fn url(raw: &str) -> Url {
        Url::parse(raw).expect("valid test url")
    }

    #[test]
    fn check_url_allows_http_and_https() {
        assert_eq!(
            check_url(&url("https://cdn.example.com/a.pdf"), false),
            Ok(())
        );
        assert_eq!(
            check_url(&url("http://cdn.example.com/a.pdf"), false),
            Ok(())
        );
    }

    #[test]
    fn check_url_rejects_non_http_schemes() {
        assert_eq!(
            check_url(&url("ftp://cdn.example.com/a.pdf"), false),
            Err(MirrorError::BadScheme)
        );
        assert_eq!(
            check_url(&url("file:///etc/passwd"), false),
            Err(MirrorError::BadScheme)
        );
        assert_eq!(
            check_url(&url("data:text/plain,hello"), false),
            Err(MirrorError::BadScheme)
        );
    }

    #[test]
    fn check_url_rejects_embedded_credentials() {
        assert_eq!(
            check_url(&url("https://user:pass@cdn.example.com/a"), false),
            Err(MirrorError::BadUrl)
        );
        assert_eq!(
            check_url(&url("https://user@cdn.example.com/a"), false),
            Err(MirrorError::BadUrl)
        );
    }

    #[test]
    fn check_addresses_rejects_internal_ipv4() {
        for raw in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "0.0.0.0",
        ] {
            let addr: IpAddr = raw.parse().unwrap();
            assert_eq!(
                check_addresses(&[addr], false),
                Err(MirrorError::DisallowedAddress),
                "{raw} should be refused"
            );
        }
    }

    #[test]
    fn check_addresses_rejects_internal_ipv6() {
        for raw in ["::1", "::", "fc00::1", "fd12::34", "fe80::1"] {
            let addr: IpAddr = raw.parse().unwrap();
            assert_eq!(
                check_addresses(&[addr], false),
                Err(MirrorError::DisallowedAddress),
                "{raw} should be refused"
            );
        }
    }

    #[test]
    fn check_addresses_rejects_ipv4_mapped_ipv6() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(
            check_addresses(&[mapped], false),
            Err(MirrorError::DisallowedAddress)
        );
        let mapped_private: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(
            check_addresses(&[mapped_private], false),
            Err(MirrorError::DisallowedAddress)
        );
    }

    #[test]
    fn check_addresses_allows_public_addresses() {
        assert_eq!(check_addresses(&[PUBLIC_V4, PUBLIC_V6], false), Ok(()));
    }

    #[test]
    fn check_addresses_rejects_mixed_public_and_private() {
        // A hostname resolving to a mix is refused outright, not merely filtered.
        assert_eq!(
            check_addresses(&[PUBLIC_V4, "127.0.0.1".parse().unwrap()], false),
            Err(MirrorError::DisallowedAddress)
        );
    }

    #[test]
    fn allow_private_override_honoured() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let v6_loopback: IpAddr = "::1".parse().unwrap();
        assert_eq!(check_addresses(&[loopback, v6_loopback], true), Ok(()));
    }
}
