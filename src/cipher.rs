use std::io;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm as RawAes256Gcm, Key, Nonce, Tag};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::format::{SALT_LEN, TAG_LEN};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

// owasp-aligned argon2id parameters: 64 mib memory, 3 iterations, 1 lane
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

pub(crate) struct DerivedKey {
    pub(crate) key: [u8; KEY_LEN],
}

impl Drop for DerivedKey {
    // clears derived encryption key material when it leaves scope
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub trait Cipher {
    // encrypts plaintext and authenticates both ciphertext and associated data
    fn seal(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; TAG_LEN])>;

    // verifies the authentication tag over aad and ciphertext before decrypting
    fn open(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Vec<u8>>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Aes256Gcm;

impl Cipher for Aes256Gcm {
    // seals plaintext with aes-256-gcm and returns ciphertext alongside its 128-bit tag
    fn seal(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; TAG_LEN])> {
        let cipher = RawAes256Gcm::new(Key::<RawAes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce);
        let mut buffer = plaintext.to_vec();

        let tag = cipher
            .encrypt_in_place_detached(nonce, aad, &mut buffer)
            .map_err(|_| Error::MessageTooLarge)?;

        let mut tag_bytes = [0u8; TAG_LEN];
        tag_bytes.copy_from_slice(tag.as_slice());
        Ok((buffer, tag_bytes))
    }

    // authenticates aad and ciphertext with aes-256-gcm before returning plaintext
    fn open(
        &self,
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Vec<u8>> {
        let cipher = RawAes256Gcm::new(Key::<RawAes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce);
        let tag = Tag::from_slice(tag);
        let mut buffer = ciphertext.to_vec();

        cipher
            .decrypt_in_place_detached(nonce, aad, &mut buffer, tag)
            .map_err(|_| {
                buffer.zeroize();
                Error::AuthenticationFailed
            })?;

        Ok(buffer)
    }
}

// stretches a user passphrase and salt into a 256-bit key using argon2id
pub(crate) fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<DerivedKey> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::KeyDerivationFailed)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| {
            key.zeroize();
            Error::KeyDerivationFailed
        })?;

    Ok(DerivedKey { key })
}

// reads fresh entropy from the operating system csprng to seed salts and nonces
pub(crate) fn fill_random(dest: &mut [u8]) -> Result<()> {
    getrandom::fill(dest).map_err(|err| io::Error::other(err.to_string()).into())
}

// overwrites sensitive byte buffers using zeroize to prevent compiler elision
pub(crate) fn wipe(bytes: &mut [u8]) {
    bytes.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    // validates aes-256-gcm against nist sp 800-38d test case 14
    #[test]
    fn matches_nist_aes256_gcm_vector() {
        let key = [0u8; KEY_LEN];
        let nonce = [0u8; NONCE_LEN];
        let plaintext = [0u8; 16];

        let (ciphertext, tag) = Aes256Gcm.seal(&key, &nonce, b"", &plaintext).unwrap();

        let expected_ciphertext = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18,
        ];
        let expected_tag = [
            0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
            0xb9, 0x19,
        ];

        assert_eq!(ciphertext.as_slice(), &expected_ciphertext);
        assert_eq!(tag, expected_tag);

        let recovered = Aes256Gcm
            .open(&key, &nonce, b"", &ciphertext, &tag)
            .unwrap();
        assert_eq!(recovered.as_slice(), &plaintext);
    }

    // confirms that aes-256-gcm roundtrips plaintext and binds associated data
    #[test]
    fn roundtrips_aead_cipher() {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let aad = b"header-metadata";
        let plain = b"hello from rust-encrypt";

        let (encrypted, tag) = Aes256Gcm.seal(&key, &nonce, aad, plain).unwrap();
        assert_ne!(encrypted.as_slice(), plain);

        let decrypted = Aes256Gcm.open(&key, &nonce, aad, &encrypted, &tag).unwrap();
        assert_eq!(decrypted.as_slice(), plain);
    }

    // confirms that modifying associated data or tag fails authentication
    #[test]
    fn detects_tampered_aad_or_tag() {
        let key = [3u8; KEY_LEN];
        let nonce = [5u8; NONCE_LEN];
        let (ciphertext, tag) = Aes256Gcm.seal(&key, &nonce, b"header", b"payload").unwrap();

        let bad_aad = Aes256Gcm.open(&key, &nonce, b"tamper", &ciphertext, &tag);
        assert!(matches!(bad_aad, Err(Error::AuthenticationFailed)));

        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let bad_tag_res = Aes256Gcm.open(&key, &nonce, b"header", &ciphertext, &bad_tag);
        assert!(matches!(bad_tag_res, Err(Error::AuthenticationFailed)));
    }

    // confirms that argon2id key derivation is deterministic and salt-sensitive
    #[test]
    fn derives_deterministic_keys() {
        let k1 = derive_key(b"passphrase", &[1u8; SALT_LEN]).unwrap();
        let k2 = derive_key(b"passphrase", &[1u8; SALT_LEN]).unwrap();
        let k3 = derive_key(b"passphrase", &[2u8; SALT_LEN]).unwrap();

        assert_eq!(k1.key, k2.key);
        assert_ne!(k1.key, k3.key);
    }

    // confirms that memory wiping clears every byte of a secret buffer
    #[test]
    fn wipes_secret_buffer() {
        let mut secret = [0xaa; 32];
        wipe(&mut secret);
        assert_eq!(secret, [0u8; 32]);
    }
}
