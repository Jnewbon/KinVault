use std::fmt::Display;
use std::io;

use crate::protocol::ErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("connection error: {0}")]
    Transport(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("remote refused access: {0}")]
    Denied(String),
    #[error("not found on remote: {0}")]
    NotFound(String),
    #[error("remote storage quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("remote rejected request: {0}")]
    BadRequest(String),
    #[error("remote error: {0}")]
    Remote(String),
    #[error("{0}")]
    OutsideWindow(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("encoding error: {0}")]
    Encoding(#[from] postcard::Error),
}

pub(crate) fn transport(e: impl Display) -> NetError {
    NetError::Transport(e.to_string())
}

impl NetError {
    pub(crate) fn from_code(code: ErrorCode, message: String) -> Self {
        match code {
            ErrorCode::Denied => Self::Denied(message),
            ErrorCode::NotFound => Self::NotFound(message),
            ErrorCode::QuotaExceeded => Self::QuotaExceeded(message),
            ErrorCode::BadRequest => Self::BadRequest(message),
            ErrorCode::Internal => Self::Remote(message),
            ErrorCode::OutsideWindow => Self::OutsideWindow(message),
        }
    }
}

impl From<NetError> for kinvault_core::Error {
    fn from(e: NetError) -> Self {
        match e {
            NetError::NotFound(m) => Self::NotFound(m),
            NetError::Io(e) => Self::Io(e),
            other => Self::Backend(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_core_errors_map_across() {
        let window = NetError::from_code(ErrorCode::OutsideWindow, "closed".into());
        assert_eq!(window.to_string(), "closed");
        let internal = NetError::from_code(ErrorCode::Internal, "disk full".into());
        assert_eq!(internal.to_string(), "remote error: disk full");
        let core: kinvault_core::Error = NetError::Io(io::Error::other("x")).into();
        assert!(matches!(core, kinvault_core::Error::Io(_)));
        let core: kinvault_core::Error = transport("reset").into();
        assert!(matches!(core, kinvault_core::Error::Backend(m) if m == "connection error: reset"));
    }
}
