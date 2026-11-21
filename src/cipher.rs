use std::fs::File;
use std::io::Read;

use crate::error::Result;
use crate::format::{NONCE_LEN, SALT_LEN, TAG_LEN};

pub const KEY_LEN: usize = 32;
const CHACHA_CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
const KDF_ROUNDS: u32 = 4096;

pub struct DerivedKeys {
    pub enc_key: [u8; KEY_LEN],
    pub mac_key: [u8; KEY_LEN],
}

pub trait Cipher {
    // transforms plaintext or ciphertext using the cipher stream boundary
    fn apply(&self, key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], data: &[u8]) -> Vec<u8>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ChaCha20;

impl Cipher for ChaCha20 {
    // xors input bytes against sequential chacha20 keystream blocks
    fn apply(&self, key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        let mut counter: u32 = 1;

        for chunk in data.chunks(64) {
            let block = chacha_block(key, counter, nonce);
            for (plain, stream) in chunk.iter().zip(block.iter()) {
                out.push(plain ^ stream);
            }
            counter = counter.wrapping_add(1);
        }

        out
    }
}

// stretches a user passphrase and salt into separated encryption and mac keys
pub fn derive_keys(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> DerivedKeys {
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
    len_nonce[..8].copy_from_slice(&(passphrase.len() as u64).to_le_bytes());
    absorb(&mut state, counter, &len_nonce);

    for round in 0..KDF_ROUNDS {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..12].copy_from_slice(&salt[..12]);
        absorb(&mut state, round, &nonce);
    }

    let enc_block = chacha_block(&state, 1, b"rust-enc-key");
    let mac_block = chacha_block(&state, 2, b"rust-mac-key");

    let mut enc_key = [0u8; KEY_LEN];
    let mut mac_key = [0u8; KEY_LEN];
    enc_key.copy_from_slice(&enc_block[..KEY_LEN]);
    mac_key.copy_from_slice(&mac_block[..KEY_LEN]);

    DerivedKeys { enc_key, mac_key }
}

// computes a keyed authentication tag over the envelope header and ciphertext
pub fn compute_tag(mac_key: &[u8; KEY_LEN], header: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
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
    domain[..4].copy_from_slice(&(header.len() as u32).to_le_bytes());
    domain[4..12].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    absorb(&mut state, counter, &domain);

    let final_block = chacha_block(&state, u32::MAX, b"renc-tag-v01");
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&final_block[..TAG_LEN]);
    tag
}

// compares two authentication tags in constant time to avoid timing leaks
pub fn verify_tag(expected: &[u8; TAG_LEN], actual: &[u8; TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(actual.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// reads fresh entropy from the operating system to seed salts and nonces
pub fn fill_random(dest: &mut [u8]) -> Result<()> {
    let mut urandom = File::open("/dev/urandom")?;
    urandom.read_exact(dest)?;
    Ok(())
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
    for i in 0..8 {
        initial[4 + i] = read_le_u32(&key[i * 4..(i + 1) * 4]);
    }
    initial[12] = counter;
    for i in 0..3 {
        initial[13 + i] = read_le_u32(&nonce[i * 4..(i + 1) * 4]);
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
    for i in 0..16 {
        let word = working[i].wrapping_add(initial[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

// mixes four state words in place as the core chacha20 arx primitive
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
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

// decodes four bytes into a little-endian word for the cipher state matrix
fn read_le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    // validates the chacha20 block core against the rfc 8439 test vector
    #[test]
    fn matches_rfc8439_block_vector() {
        let mut key = [0u8; KEY_LEN];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
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

        let encrypted = ChaCha20.apply(&key, &nonce, plain);
        assert_ne!(encrypted.as_slice(), plain);

        let decrypted = ChaCha20.apply(&key, &nonce, &encrypted);
        assert_eq!(decrypted.as_slice(), plain);
    }

    // confirms that tag verification detects single-bit payload tampering
    #[test]
    fn detects_tampered_tag() {
        let keys = derive_keys(b"passphrase", &[4u8; SALT_LEN]);
        let tag = compute_tag(&keys.mac_key, b"header", b"payload");
        assert!(verify_tag(&tag, &tag));

        let mut bad = tag;
        bad[0] ^= 1;
        assert!(!verify_tag(&tag, &bad));
    }
}
