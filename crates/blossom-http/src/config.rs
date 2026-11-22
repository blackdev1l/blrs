use std::net::SocketAddr;
use std::path::PathBuf;

use blossom_core::auth::Action;
use clap::{Parser, ValueEnum};
use url::Url;

/// Which endpoints require a BUD-11 authorization token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AuthMode {
    /// No endpoint requires a token. Blobs are stored without an owner.
    None,
    /// Writes require a token; reads do not. The default.
    Writes,
    /// Every endpoint requires a token.
    All,
}

/// Per-action authorization switches, derived from [`AuthMode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthPolicy {
    pub get: bool,
    pub upload: bool,
    pub list: bool,
    pub delete: bool,
    pub media: bool,
}

impl AuthPolicy {
    pub fn for_mode(mode: AuthMode) -> Self {
        match mode {
            AuthMode::None => Self {
                get: false,
                upload: false,
                list: false,
                delete: false,
                media: false,
            },
            AuthMode::Writes => Self {
                get: false,
                upload: true,
                list: false,
                delete: true,
                media: true,
            },
            AuthMode::All => Self {
                get: true,
                upload: true,
                list: true,
                delete: true,
                media: true,
            },
        }
    }

    /// Whether `action` needs a verified token.
    pub fn requires(&self, action: Action) -> bool {
        match action {
            Action::Get => self.get,
            Action::Upload => self.upload,
            Action::List => self.list,
            Action::Delete => self.delete,
            Action::Media => self.media,
        }
    }
}

/// Runtime configuration.
#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    /// Absolute base URL with no trailing slash, used to build descriptor URLs.
    pub public_base: String,
    /// Bare lowercase domain, matched against BUD-11 `server` tags.
    pub host: String,
    pub max_blob_size: u64,
    /// Total committed blob bytes allowed, or `None` for unlimited.
    pub max_total_bytes: Option<u64>,
    pub auth: AuthPolicy,
    pub enable_list: bool,
    pub enable_mirror: bool,
    pub enable_media: bool,
    pub mirror_allow_private: bool,
    /// MIME types refused on upload, matched exactly.
    pub blocked_mime: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("public_url must be an absolute http(s) URL: {0}")]
    BadPublicUrl(String),
    #[error(
        "invalid size {0:?}: expected a number of bytes with an optional k/m/g/t suffix \
         (optionally b or ib, all binary), for example 4G"
    )]
    BadSize(String),
}

/// Parses a disk-size flag into bytes.
///
/// Suffixes `k`, `m`, `g` and `t` are binary (1024-based) and may be followed by
/// `b` or `ib`; a bare number is bytes. Matching is case-insensitive. `0` and an
/// empty value mean no limit (`None`). Anything else — a sign, an unknown
/// suffix, or an overflowing value — is [`ConfigError::BadSize`].
pub fn parse_max_total_size(raw: &str) -> Result<Option<u64>, ConfigError> {
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let digits_end = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    if digits_end == 0 {
        return Err(ConfigError::BadSize(raw.to_string()));
    }
    let (digits, suffix) = value.split_at(digits_end);
    let number: u64 = digits
        .parse()
        .map_err(|_| ConfigError::BadSize(raw.to_string()))?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "" | "b" => 1u64,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        _ => return Err(ConfigError::BadSize(raw.to_string())),
    };
    let bytes = number
        .checked_mul(multiplier)
        .ok_or_else(|| ConfigError::BadSize(raw.to_string()))?;
    Ok((bytes != 0).then_some(bytes))
}

#[derive(Parser, Debug)]
#[command(name = "blrs", about = "A Blossom blob server", version)]
struct Cli {
    #[arg(long, env = "BLOSSOM_BIND", default_value = "0.0.0.0:3000")]
    bind: SocketAddr,

    #[arg(long, env = "BLOSSOM_DATA_DIR", default_value = "./data")]
    data_dir: PathBuf,

    #[arg(
        long,
        env = "BLOSSOM_PUBLIC_URL",
        default_value = "http://localhost:3000"
    )]
    public_url: String,

    /// Largest single blob accepted, in bytes.
    #[arg(long, env = "BLOSSOM_MAX_BLOB_SIZE", default_value_t = 100 * 1024 * 1024)]
    max_blob_size: u64,

    /// Total disk budget for stored blobs, for example `4G` (all suffixes are
    /// binary). `0` or absent means unlimited.
    #[arg(
        long = "max-total-size",
        env = "BLOSSOM_MAX_TOTAL_SIZE",
        default_value = "0"
    )]
    max_total_size: String,

    #[arg(long, env = "BLOSSOM_AUTH", value_enum, default_value_t = AuthMode::Writes)]
    auth: AuthMode,

    #[arg(long, env = "BLOSSOM_ENABLE_LIST", default_value_t = true)]
    enable_list: bool,

    #[arg(long, env = "BLOSSOM_ENABLE_MIRROR", default_value_t = true)]
    enable_mirror: bool,

    // Enabled like `list` and `mirror`. The endpoint is implemented and a
    // no-op optimiser is spec-legal (BUD-05 leaves the optimisation policy to
    // the server), so shipping it off only turned it into a bare 404.
    #[arg(long, env = "BLOSSOM_ENABLE_MEDIA", default_value_t = true)]
    enable_media: bool,

    /// Allow mirroring from loopback and private addresses. Off by default:
    /// the endpoint fetches user-supplied URLs (BUD-04 SSRF guidance).
    #[arg(long, env = "BLOSSOM_MIRROR_ALLOW_PRIVATE", default_value_t = false)]
    mirror_allow_private: bool,

    #[arg(
        long = "blocked-mime",
        env = "BLOSSOM_BLOCKED_MIME",
        value_delimiter = ','
    )]
    blocked_mime: Vec<String>,
}

impl Config {
    /// Parses configuration from CLI flags and environment variables.
    ///
    /// `--help` and `--version` print to stdout and exit 0 rather than being
    /// reported as a failure, which is what clap's own `exit` does. Usage errors
    /// print to stderr and exit 2.
    pub fn from_env() -> Result<Self, ConfigError> {
        let cli = Cli::try_parse().unwrap_or_else(|err| err.exit());
        Self::from_cli(cli)
    }

    fn from_cli(cli: Cli) -> Result<Self, ConfigError> {
        // `public_url` builds every descriptor URL, so it must be an absolute
        // http(s) URL with a host. A bare `localhost:3000` parses as a URL whose
        // scheme is `localhost`, which is why the scheme is checked explicitly.
        let parsed = Url::parse(&cli.public_url)
            .map_err(|_| ConfigError::BadPublicUrl(cli.public_url.clone()))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(ConfigError::BadPublicUrl(cli.public_url.clone()));
        }
        // `Url::as_str` round-trips an absolute URL and appends the default
        // path `/`; trimming it yields the no-trailing-slash base the
        // descriptor builder and the route table expect.
        let public_base = parsed.as_str().trim_end_matches('/').to_string();
        // BUD-11 `server` tags are lowercase domains with no scheme or port, so
        // the host is the parsed domain only and is compared case-insensitively.
        let host = parsed
            .host_str()
            .expect("host was checked above")
            .to_ascii_lowercase();
        let max_total_bytes = parse_max_total_size(&cli.max_total_size)?;

        Ok(Self {
            bind: cli.bind,
            data_dir: cli.data_dir,
            public_base,
            host,
            max_blob_size: cli.max_blob_size,
            max_total_bytes,
            auth: AuthPolicy::for_mode(cli.auth),
            enable_list: cli.enable_list,
            enable_mirror: cli.enable_mirror,
            enable_media: cli.enable_media,
            mirror_allow_private: cli.mirror_allow_private,
            blocked_mime: cli.blocked_mime,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_args(args: &[&str]) -> Result<Config, ConfigError> {
        let cli = Cli::try_parse_from(args).expect("valid cli arguments");
        Config::from_cli(cli)
    }

    #[test]
    fn public_url_derives_base_and_host() {
        let config = from_args(&["blrs", "--public-url", "HTTPS://CDN.Example.COM/"]).unwrap();
        assert_eq!(config.public_base, "https://cdn.example.com");
        assert_eq!(config.host, "cdn.example.com");
    }

    #[test]
    fn public_url_keeps_a_path_without_a_trailing_slash() {
        let config =
            from_args(&["blrs", "--public-url", "https://cdn.example.com/media/"]).unwrap();
        assert_eq!(config.public_base, "https://cdn.example.com/media");
    }

    #[test]
    fn public_url_rejects_non_http_schemes() {
        assert!(matches!(
            from_args(&["blrs", "--public-url", "ftp://cdn.example.com"]),
            Err(ConfigError::BadPublicUrl(_))
        ));
        assert!(matches!(
            from_args(&["blrs", "--public-url", "cdn.example.com:3000"]),
            Err(ConfigError::BadPublicUrl(_))
        ));
    }

    #[test]
    fn max_total_size_parses_every_binary_suffix_and_a_bare_number() {
        // Every suffix is 1024-based: 4G == 4GiB == 4 * 1024^3.
        for spelling in ["4G", "4g", "4gb", "4gB", "4GiB", "4gib"] {
            assert_eq!(
                parse_max_total_size(spelling).unwrap(),
                Some(4 * 1024 * 1024 * 1024),
                "{spelling}"
            );
        }
        assert_eq!(parse_max_total_size("500M").unwrap(), Some(500 << 20));
        assert_eq!(parse_max_total_size("2kib").unwrap(), Some(2 << 10));
        assert_eq!(parse_max_total_size("1T").unwrap(), Some(1 << 40));
        assert_eq!(parse_max_total_size("1024").unwrap(), Some(1024));
        assert_eq!(parse_max_total_size("1024b").unwrap(), Some(1024));
        assert_eq!(parse_max_total_size("0").unwrap(), None);
        assert_eq!(parse_max_total_size("").unwrap(), None);
    }

    #[test]
    fn max_total_size_rejects_bad_values() {
        for bad in ["4X", "-1", "4GG", "G", "4.5G", "4 G"] {
            assert!(
                matches!(parse_max_total_size(bad), Err(ConfigError::BadSize(_))),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn max_total_size_flag_feeds_the_config() {
        let config = from_args(&["blrs", "--max-total-size", "4GiB"]).unwrap();
        assert_eq!(config.max_total_bytes, Some(4 * 1024 * 1024 * 1024));

        let unlimited = from_args(&["blrs", "--max-total-size", "0"]).unwrap();
        assert_eq!(unlimited.max_total_bytes, None);
    }

    #[test]
    fn optional_endpoints_are_enabled_by_default() {
        // `/media` shipped off by default from the scaffold, which turned the
        // implemented endpoint into a bare 404. It is enabled like the others.
        let config = from_args(&["blrs"]).unwrap();
        assert!(config.enable_media);
        assert!(config.enable_mirror);
        assert!(config.enable_list);
    }
}
