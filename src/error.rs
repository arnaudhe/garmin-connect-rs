use thiserror::Error;

/// Mirrors `garminconnect.exceptions` from the Python implementation.
#[derive(Error, Debug)]
pub enum GarminError {
    /// Generic communication / transport failure.
    #[error("Garmin Connect error: {0}")]
    Connection(String),

    /// HTTP 404 — subtype of `Connection` so callers who only match on
    /// `Connection` still see these, but callers who care can match this
    /// variant specifically.
    #[error("Garmin Connect resource not found: {0}")]
    NotFound(String),

    /// HTTP 429 anywhere in the login or request chain.
    #[error("Garmin Connect rate limited (429): {0}")]
    TooManyRequests(String),

    /// Wrong credentials, or MFA verification rejected.
    #[error("Garmin Connect authentication failed: {0}")]
    Authentication(String),

    /// Login succeeded partially but requires an MFA code to finish.
    /// Call [`crate::client::GarminClient::resume_login`] with the code
    /// obtained from the user, using the [`MfaContext`] returned here.
    #[error("MFA code required to complete login")]
    MfaRequired(crate::client::MfaContext),

    #[error("invalid file format: {0}")]
    InvalidFileFormat(String),

    #[error(transparent)]
    Http(#[from] wreq::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, GarminError>;
