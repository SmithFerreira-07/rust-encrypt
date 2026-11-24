use std::hint::black_box;
use std::ptr;
use std::sync::atomic::{Ordering, compiler_fence};

use crate::error::{Error, Result};
use crate::format::{HEADER_PREFIX_LEN, SALT_LEN, TAG_LEN};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
const CHACHA_CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
const KDF_ROUNDS: u32 = 4096;

pub(crate) struct DerivedKeys {
    pub(crate) enc_key: [u8; KEY_LEN],
    pub(crate) mac_key: [u8; KEY_LEN],
}

impl Drop for DerivedKeys {
    // clears derived encryption and authentication keys when they leave scope
    fn drop(&mut self) {
        wipe(&mut self.enc_key);
        wipe(&mut self.mac_key);
    }
}

pub trait Cipher {
    // transforms plaintext or ciphertext using the cipher stream boundary
    fn apply(&self, key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], data: &[u8]) -> Result<Vec<u8>>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ChaCha20;

impl Cipher for ChaCha20 {
    // xors input bytes against sequential chacha20 keystream blocks
    fn apply(&self, key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(data.len());
        let mut counter: u32 = 1;

        for chunk in data.chunks(64) {
            let block = chacha_block(key, counter, nonce);
            for (plain, stream) in chunk.iter().zip(block.iter()) {
                out.push(plain ^ stream);
            }
            counter = counter.checked_add(1).ok_or(Error::MessageTooLarge)?;
        }

        Ok(out)
    }
}

// stretches a user passphrase and salt into separated encryption and mac keys
#[must_use]
pub(crate) fn derive_keys(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> DerivedKeys {
    let mut state = [0u8; KEY_LEN];
    for (i, byte) in salt.iter().enumerate() {
        state[i] = *byte;
        state[i + SALT_LEN] = *byte ^ 0x5c;
    }

    let mut counter = 0u32;
    for chunk in passphrase.chunks(NONCE_LEN) {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..chunk.len()].copy_from_slice(chunk);
        absorb(&mut state, counter, &nonce);
        counter = counter.wrapping_add(1);
    }

    let mut len_nonce = [0u8; NONCE_LEN];
    let pass_len = u64::try_from(passphrase.len()).unwrap_or(u64::MAX);
    len_nonce[..8].copy_from_slice(&pass_len.to_le_bytes());
    absorb(&mut state, counter, &len_nonce);

    for round in 0..KDF_ROUNDS {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..12].copy_from_slice(&salt[..12]);
        absorb(&mut state, round, &nonce);
    }

    let enc_block = chacha_block(&state, 1, b"rust-enc-key");
    let mac_block = chacha_block(&state, 2, b"rust-mac-key");
    wipe(&mut state);

    let mut enc_key = [0u8; KEY_LEN];
    let mut mac_key = [0u8; KEY_LEN];
    enc_key.copy_from_slice(&enc_block[..KEY_LEN]);
    mac_key.copy_from_slice(&mac_block[..KEY_LEN]);

    DerivedKeys { enc_key, mac_key }
}

// computes a keyed authentication tag over the envelope header and ciphertext
#[must_use]
pub(crate) fn compute_tag(
    mac_key: &[u8; KEY_LEN],
    header: &[u8; HEADER_PREFIX_LEN],
    ciphertext: &[u8],
) -> [u8; TAG_LEN] {
    let mut state = *mac_key;
    let mut counter = 0u32;

    for chunk in header.chunks(NONCE_LEN) {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..chunk.len()].copy_from_slice(chunk);
        absorb(&mut state, counter, &nonce);
        counter = counter.wrapping_add(1);
    }

    for chunk in ciphertext.chunks(NONCE_LEN) {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..chunk.len()].copy_from_slice(chunk);
        absorb(&mut state, counter, &nonce);
        counter = counter.wrapping_add(1);
    }

    let mut domain = [0u8; NONCE_LEN];
    let header_len = u32::try_from(header.len()).unwrap_or(u32::MAX);
    let cipher_len = u64::try_from(ciphertext.len()).unwrap_or(u64::MAX);
    domain[..4].copy_from_slice(&header_len.to_le_bytes());
    domain[4..12].copy_from_slice(&cipher_len.to_le_bytes());
    absorb(&mut state, counter, &domain);

    let final_block = chacha_block(&state, u32::MAX, b"renc-tag-v01");
    wipe(&mut state);

    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&final_block[..TAG_LEN]);
    tag
}

// compares two authentication tags in constant time to avoid timing leaks
#[must_use]
pub(crate) fn verify_tag(expected: &[u8; TAG_LEN], actual: &[u8; TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(actual.iter()) {
        diff |= a ^ b;
    }
    black_box(diff) == 0
}

// reads fresh entropy from the operating system to seed salts and nonces
#[cfg(unix)]
pub(crate) fn fill_random(dest: &mut [u8]) -> Result<()> {
    use std::fs::File;
    use std::io::Read;

    let mut urandom = File::open("/dev/urandom")?;
    urandom.read_exact(dest)?;
    Ok(())
}

// rejects unsupported platforms until a cross-platform entropy source is wired in
#[cfg(not(unix))]
pub(crate) fn fill_random(_dest: &mut [u8]) -> Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "os randomness requires a unix target in this scaffold",
    )
    .into())
}

// overwrites sensitive byte buffers with volatile stores to prevent elision
pub(crate) fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

// folds one block of input into the chaining key state via chacha20
fn absorb(state: &mut [u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) {
    let block = chacha_block(state, counter, nonce);
    for (slot, byte) in state.iter_mut().zip(block.iter()) {
        *slot ^= *byte;
    }
}

// produces one 64-byte chacha20 keystream block from key, counter, and nonce
fn chacha_block(key: &[u8; KEY_LEN], counter: u32, nonce: &[u8; NONCE_LEN]) -> [u8; 64] {
    let mut initial = [0u32; 16];
    initial[0..4].copy_from_slice(&CHACHA_CONSTANTS);

    let (key_words, _) = key.as_chunks::<4>();
    for (slot, chunk) in initial[4..12].iter_mut().zip(key_words) {
        *slot = u32::from_le_bytes(*chunk);
    }

    initial[12] = counter;

    let (nonce_words, _) = nonce.as_chunks::<4>();
    for (slot, chunk) in initial[13..16].iter_mut().zip(nonce_words) {
        *slot = u32::from_le_bytes(*chunk);
    }

    let mut working = initial;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);

        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    let (out_chunks, _) = out.as_chunks_mut::<4>();
    for ((slot, work), init) in out_chunks.iter_mut().zip(working).zip(initial) {
        *slot = work.wrapping_add(init).to_le_bytes();
    }
    out
}

// mixes four state words in place as the core chacha20 arx primitive
const fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    // validates the chacha20 block core against the rfc 8439 test vector
    #[test]
    fn matches_rfc8439_block_vector() {
        let key: [u8; KEY_LEN] = std::array::from_fn(|i| u8::try_from(i).unwrap());
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];

        let block = chacha_block(&key, 1, &nonce);
        let expected_prefix = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4,
        ];
        assert_eq!(&block[..16], &expected_prefix);
    }

    // confirms that stream encryption is symmetric for the same key and nonce
    #[test]
    fn roundtrips_stream_cipher() {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let plain = b"hello from rust-encrypt";

        let encrypted = ChaCha20.apply(&key, &nonce, plain).unwrap();
        assert_ne!(encrypted.as_slice(), plain);

        let decrypted = ChaCha20.apply(&key, &nonce, &encrypted).unwrap();
        assert_eq!(decrypted.as_slice(), plain);
    }

    // confirms that tag verification detects single-bit payload tampering
    #[test]
    fn detects_tampered_tag() {
        let keys = derive_keys(b"passphrase", &[4u8; SALT_LEN]);
        let header = [5u8; HEADER_PREFIX_LEN];
        let tag = compute_tag(&keys.mac_key, &header, b"payload");
        assert!(verify_tag(&tag, &tag));

        let mut bad = tag;
        bad[0] ^= 1;
        assert!(!verify_tag(&tag, &bad));
    }

    // confirms that memory wiping clears every byte of a secret buffer
    #[test]
    fn wipes_secret_buffer() {
        let mut secret = [0xaa; 32];
        wipe(&mut secret);
        assert_eq!(secret, [0u8; 32]);
    }
}
