pub mod cipher;
pub mod cli;
pub mod error;
pub mod format;

use std::fs;
use std::path::Path;

use crate::cipher::{ChaCha20, Cipher, compute_tag, derive_keys, fill_random, verify_tag};
use crate::cli::{Command, Mode};
use crate::error::{Error, Result};
use crate::format::{Envelope, NONCE_LEN, SALT_LEN};

// dispatches a parsed cli command through the configured cipher pipeline
pub fn run(cmd: &Command) -> Result<()> {
    let engine = ChaCha20;
    match cmd.mode {
        Mode::Encrypt => encrypt_file(&engine, &cmd.input, &cmd.output, cmd.passphrase.as_bytes()),
        Mode::Decrypt => decrypt_file(&engine, &cmd.input, &cmd.output, cmd.passphrase.as_bytes()),
    }
}

// reads plaintext from disk, seals it into an envelope, and writes the result
pub fn encrypt_file<C: Cipher>(
    cipher: &C,
    input: &Path,
    output: &Path,
    passphrase: &[u8],
) -> Result<()> {
    let plaintext = fs::read(input)?;
    let sealed = encrypt_bytes(cipher, &plaintext, passphrase)?;
    fs::write(output, sealed)?;
    Ok(())
}

// reads an envelope from disk, authenticates and decrypts it, and writes plaintext
pub fn decrypt_file<C: Cipher>(
    cipher: &C,
    input: &Path,
    output: &Path,
    passphrase: &[u8],
) -> Result<()> {
    let raw = fs::read(input)?;
    let plaintext = decrypt_bytes(cipher, &raw, passphrase)?;
    fs::write(output, plaintext)?;
    Ok(())
}

// derives per-message keys, encrypts bytes, and frames them with an auth tag
pub fn encrypt_bytes<C: Cipher>(
    cipher: &C,
    plaintext: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;

    let keys = derive_keys(passphrase, &salt);
    let payload = cipher.apply(&keys.enc_key, &nonce, plaintext);

    let mut envelope = Envelope {
        salt,
        nonce,
        tag: [0u8; format::TAG_LEN],
        payload,
    };
    let header = envelope.authenticated_header();
    envelope.tag = compute_tag(&keys.mac_key, &header, &envelope.payload);

    Ok(envelope.encode())
}

// parses a framed envelope, verifies its integrity tag, and recovers plaintext
pub fn decrypt_bytes<C: Cipher>(cipher: &C, raw: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    let envelope = Envelope::decode(raw)?;
    let keys = derive_keys(passphrase, &envelope.salt);
    let header = envelope.authenticated_header();
    let expected = compute_tag(&keys.mac_key, &header, &envelope.payload);

    if !verify_tag(&expected, &envelope.tag) {
        return Err(Error::AuthenticationFailed);
    }

    Ok(cipher.apply(&keys.enc_key, &envelope.nonce, &envelope.payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    // checks end-to-end byte encryption and decryption across format and cipher layers
    #[test]
    fn roundtrips_sealed_bytes() {
        let plaintext = b"top secret architecture notes";
        let sealed = encrypt_bytes(&ChaCha20, plaintext, b"hunter2").unwrap();
        let recovered = decrypt_bytes(&ChaCha20, &sealed, b"hunter2").unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    // checks that decrypting with the wrong passphrase fails before returning data
    #[test]
    fn rejects_wrong_passphrase() {
        let sealed = encrypt_bytes(&ChaCha20, b"payload", b"right-key").unwrap();
        let err = decrypt_bytes(&ChaCha20, &sealed, b"wrong-key").unwrap_err();
        assert!(matches!(err, Error::AuthenticationFailed));
    }

    // checks that modifying a ciphertext byte trips envelope authentication
    #[test]
    fn rejects_corrupted_ciphertext() {
        let mut sealed = encrypt_bytes(&ChaCha20, b"payload", b"right-key").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;

        let err = decrypt_bytes(&ChaCha20, &sealed, b"right-key").unwrap_err();
        assert!(matches!(err, Error::AuthenticationFailed));
    }
}
