use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Usage(String),
    InvalidFormat(&'static str),
    AuthenticationFailed,
}

impl fmt::Display for Error {
    // formats domain errors at the boundary before they reach stderr
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "io error: {err}"),
            Error::Usage(msg) => write!(f, "usage error: {msg}"),
            Error::InvalidFormat(msg) => write!(f, "invalid file format: {msg}"),
            Error::AuthenticationFailed => {
                write!(f, "authentication failed: wrong key or corrupted file")
            }
        }
    }
}

impl std::error::Error for Error {
    // exposes underlying io errors to callers walking the error chain
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    // lifts standard io failures into the shared crate error type
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}
