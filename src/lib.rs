pub mod cipher;
pub mod error;
mod format;
pub mod tui;

use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use crate::cipher::{NONCE_LEN, SALT_LEN, derive_key, fill_random, open, seal};
use crate::error::Result;
use crate::format::Envelope;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

// reads plaintext from disk, seals it into an envelope, and writes the result
pub fn encrypt_file(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    passphrase: &[u8],
) -> Result<()> {
    let plaintext = Zeroizing::new(fs::read(input)?);
    let sealed = encrypt_bytes(&plaintext, passphrase)?;
    fs::write(output, sealed)?;
    Ok(())
}

// reads an envelope from disk, authenticates and decrypts it, and writes plaintext
pub fn decrypt_file(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    passphrase: &[u8],
) -> Result<()> {
    let raw = fs::read(input)?;
    let plaintext = Zeroizing::new(decrypt_bytes(&raw, passphrase)?);
    fs::write(output, &*plaintext)?;
    Ok(())
}

// derives a per-message key, encrypts bytes with aead, and frames them into an envelope
pub fn encrypt_bytes(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;

    let derived = derive_key(passphrase, &salt)?;
    let header = Envelope::authenticated_header(&salt, &nonce);
    let (payload, tag) = seal(&derived, &nonce, &header, plaintext)?;
    let envelope = Envelope {
        salt,
        nonce,
        tag,
        payload,
    };

    Ok(envelope.encode())
}

// parses a framed envelope, verifies its aead tag and header, and recovers plaintext
pub fn decrypt_bytes(raw: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    let envelope = Envelope::decode(raw)?;
    let derived = derive_key(passphrase, &envelope.salt)?;
    let header = Envelope::authenticated_header(&envelope.salt, &envelope.nonce);

    open(
        &derived,
        &envelope.nonce,
        &header,
        &envelope.payload,
        &envelope.tag,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    // checks end-to-end byte encryption and decryption across format and cipher layers
    #[test]
    fn roundtrips_sealed_bytes() {
        let plaintext = b"top secret architecture notes";
        let sealed = encrypt_bytes(plaintext, b"hunter2").unwrap();
        let recovered = decrypt_bytes(&sealed, b"hunter2").unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    // checks that decrypting with the wrong passphrase fails before returning data
    #[test]
    fn rejects_wrong_passphrase() {
        let sealed = encrypt_bytes(b"payload", b"right-key").unwrap();
        let err = decrypt_bytes(&sealed, b"wrong-key").unwrap_err();
        assert!(matches!(err, Error::AuthenticationFailed));
    }

    // checks that modifying a ciphertext byte trips aead authentication
    #[test]
    fn rejects_corrupted_ciphertext() {
        let mut sealed = encrypt_bytes(b"payload", b"right-key").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;

        let err = decrypt_bytes(&sealed, b"right-key").unwrap_err();
        assert!(matches!(err, Error::AuthenticationFailed));
    }

    // checks that modifying an authenticated header byte trips aead authentication
    #[test]
    fn rejects_tampered_header() {
        let mut sealed = encrypt_bytes(b"payload", b"right-key").unwrap();
        sealed[5] ^= 0x01; // flip a bit in the salt

        let err = decrypt_bytes(&sealed, b"right-key").unwrap_err();
        assert!(matches!(err, Error::AuthenticationFailed));
    }

    // checks that empty passphrases are rejected at the library boundary
    #[test]
    fn rejects_empty_passphrase() {
        let err = encrypt_bytes(b"payload", b"").unwrap_err();
        assert!(matches!(err, Error::EmptyPassphrase));
    }
}
