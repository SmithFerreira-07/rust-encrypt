use crate::cipher::{NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::error::{Error, Result};

pub const MAGIC: [u8; 4] = *b"RENC";
pub const VERSION: u8 = 2;

const VERSION_OFFSET: usize = MAGIC.len();
const SALT_OFFSET: usize = VERSION_OFFSET + 1;
const NONCE_OFFSET: usize = SALT_OFFSET + SALT_LEN;
const TAG_OFFSET: usize = NONCE_OFFSET + NONCE_LEN;

pub const HEADER_PREFIX_LEN: usize = TAG_OFFSET;
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
    pub fn authenticated_header(
        salt: &[u8; SALT_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> [u8; HEADER_PREFIX_LEN] {
        let mut out = [0u8; HEADER_PREFIX_LEN];
        out[..VERSION_OFFSET].copy_from_slice(&MAGIC);
        out[VERSION_OFFSET] = VERSION;
        out[SALT_OFFSET..NONCE_OFFSET].copy_from_slice(salt);
        out[NONCE_OFFSET..TAG_OFFSET].copy_from_slice(nonce);
        out
    }

    // serializes the structured envelope into a flat byte buffer for storage
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&Self::authenticated_header(&self.salt, &self.nonce));
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&self.payload);
        out
    }

    // validates magic bytes and version while decoding raw file bytes into an envelope
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::InvalidFormat("file is shorter than header"));
        }

        if bytes[..VERSION_OFFSET] != MAGIC {
            return Err(Error::InvalidFormat("unrecognized file magic"));
        }

        if bytes[VERSION_OFFSET] != VERSION {
            return Err(Error::InvalidFormat("unsupported envelope version"));
        }

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        let mut tag = [0u8; TAG_LEN];

        salt.copy_from_slice(&bytes[SALT_OFFSET..NONCE_OFFSET]);
        nonce.copy_from_slice(&bytes[NONCE_OFFSET..TAG_OFFSET]);
        tag.copy_from_slice(&bytes[TAG_OFFSET..HEADER_LEN]);

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
