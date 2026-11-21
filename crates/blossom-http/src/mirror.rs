use std::net::IpAddr;

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

/// Rejects non-http(s) schemes, credentials, and private destination hosts.
pub fn check_url(url: &Url, allow_private: bool) -> Result<(), MirrorError> {
    todo!("lane C: scheme + host policy")
}

/// Rejects loopback, private, link-local, and unspecified addresses.
///
/// Applied to the full resolved address list before connecting, so a hostname
/// resolving to a mix of public and private addresses is refused outright.
pub fn check_addresses(addrs: &[IpAddr], allow_private: bool) -> Result<(), MirrorError> {
    todo!("lane C: address policy for IPv4 and IPv6")
}
