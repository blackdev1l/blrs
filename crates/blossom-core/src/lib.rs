//! Pure Blossom domain logic.
//!
//! This crate has no I/O and no HTTP: it is the shared vocabulary the rest of
//! the server speaks. Everything here is deterministic and directly testable.
//!
//! Spec references are to the BUDs in <https://github.com/hzrd149/blossom>.

#![forbid(unsafe_code)]

pub mod auth;
pub mod descriptor;
pub mod error;
pub mod mime;
pub mod path;
pub mod range;
pub mod sha256;

pub use descriptor::BlobDescriptor;
pub use error::{AuthError, CoreError};
pub use mime::MimeType;
pub use path::parse_blob_path;
pub use range::{ByteRange, RangeOutcome};
pub use sha256::Sha256;
