use std::net::SocketAddr;
use std::path::PathBuf;

use blossom_core::auth::Action;
use clap::{Parser, ValueEnum};

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
    #[error("invalid configuration: {0}")]
    Cli(#[from] clap::Error),
    #[error("public_url must be an absolute http(s) URL: {0}")]
    BadPublicUrl(String),
}

#[derive(Parser, Debug)]
#[command(name = "blossom", about = "A Blossom blob server", version)]
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

    #[arg(long, env = "BLOSSOM_AUTH", value_enum, default_value_t = AuthMode::Writes)]
    auth: AuthMode,

    #[arg(long, env = "BLOSSOM_ENABLE_LIST", default_value_t = true)]
    enable_list: bool,

    #[arg(long, env = "BLOSSOM_ENABLE_MIRROR", default_value_t = true)]
    enable_mirror: bool,

    #[arg(long, env = "BLOSSOM_ENABLE_MEDIA", default_value_t = false)]
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
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_cli(Cli::try_parse()?)
    }

    fn from_cli(cli: Cli) -> Result<Self, ConfigError> {
        todo!("lane C: validate public_url, derive public_base and host")
    }
}
