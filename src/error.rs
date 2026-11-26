use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Io(io::Error),
    EmptyPassphrase,
    InvalidFormat(&'static str),
    AuthenticationFailed,
    MessageTooLarge,
    KeyDerivationFailed,
}

impl fmt::Display for Error {
    // formats domain errors at the boundary before they reach stderr
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::EmptyPassphrase => write!(f, "passphrase cannot be empty"),
            Self::InvalidFormat(msg) => write!(f, "invalid file format: {msg}"),
            Self::AuthenticationFailed => {
                write!(f, "authentication failed: wrong key or corrupted file")
            }
            Self::MessageTooLarge => write!(f, "message exceeds cipher block counter limit"),
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
        }
    }
}

impl std::error::Error for Error {
    // exposes underlying io errors to callers walking the error chain
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    // lifts standard io failures into the shared crate error type
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}
