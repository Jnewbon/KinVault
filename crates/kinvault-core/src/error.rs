#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("index database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("encoding error: {0}")]
    Encoding(#[from] postcard::Error),
    #[error("decryption failed: wrong key or corrupted data")]
    Decrypt,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("corrupt data: {0}")]
    Corrupt(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("storage backend: {0}")]
    Backend(String),
    #[error("system random number generator failed")]
    Rng,
}

pub type Result<T> = std::result::Result<T, Error>;
