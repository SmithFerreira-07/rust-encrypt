use crate::cipher::NONCE_LEN;
use crate::error::{Error, Result};

pub const MAGIC: [u8; 4] = *b"RENC";
pub const VERSION: u8 = 1;
pub const SALT_LEN: usize = 16;
pub const TAG_LEN: usize = 32;
pub const HEADER_PREFIX_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN;
pub const HEADER_LEN: usize = HEADER_PREFIX_LEN + TAG_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub tag: [u8; TAG_LEN],
    pub payload: Vec<u8>,
}

impl Envelope {
    // packs version metadata, salt, and nonce for header authentication
    #[must_use]
    pub fn authenticated_header(&self) -> [u8; HEADER_PREFIX_LEN] {
        let mut out = [0u8; HEADER_PREFIX_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5..21].copy_from_slice(&self.salt);
        out[21..33].copy_from_slice(&self.nonce);
        out
    }

    // serializes the structured envelope into a flat byte buffer for storage
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.authenticated_header());
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&self.payload);
        out
    }

    // validates magic bytes and version while decoding raw file bytes into an envelope
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::InvalidFormat("file is shorter than header"));
        }

        if bytes[0..4] != MAGIC {
            return Err(Error::InvalidFormat("unrecognized file magic"));
        }

        if bytes[4] != VERSION {
            return Err(Error::InvalidFormat("unsupported envelope version"));
        }

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        let mut tag = [0u8; TAG_LEN];

        salt.copy_from_slice(&bytes[5..21]);
        nonce.copy_from_slice(&bytes[21..33]);
        tag.copy_from_slice(&bytes[33..65]);

        Ok(Self {
            salt,
            nonce,
            tag,
            payload: bytes[HEADER_LEN..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // verifies that framing encode and decode preserve all envelope fields
    #[test]
    fn roundtrips_envelope() {
        let env = Envelope {
            salt: [1u8; SALT_LEN],
            nonce: [2u8; NONCE_LEN],
            tag: [3u8; TAG_LEN],
            payload: b"ciphertext".to_vec(),
        };

        let raw = env.encode();
        let decoded = Envelope::decode(&raw).unwrap();
        assert_eq!(decoded, env);
    }

    // verifies that malformed magic bytes are rejected by the format parser
    #[test]
    fn rejects_bad_magic() {
        let mut raw = vec![0u8; HEADER_LEN];
        raw[0..4].copy_from_slice(b"NOPE");
        raw[4] = VERSION;

        let err = Envelope::decode(&raw).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)));
    }
}
