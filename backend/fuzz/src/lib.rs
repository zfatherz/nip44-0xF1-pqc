// src/lib.rs — v0xF1 packet format + AEAD verification in Rust
//
// Tests the packet parser and XChaCha20-Poly1305 authentication boundary.
// ML-KEM-768 encapsulation is tested by @noble/post-quantum's own test suite;
// here we verify that:
//   1. The packet slicer never panics on arbitrary input
//   2. AEAD encrypt→decrypt roundtrips correctly
//   3. Any bit-flip in ciphertext causes clean authentication failure

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};

// ── Packet constants — must match nip44.ts exactly ───────────────────────────

pub const VERSION:     u8    = 0xf1;
pub const MLKEM_CT:    usize = 1088; // ML-KEM-768 ciphertext
pub const X25519_EPK:  usize = 32;   // X25519 ephemeral public key slot
pub const KEM_CT_SIZE: usize = MLKEM_CT + X25519_EPK; // 1120
pub const NONCE_SIZE:  usize = 24;   // XChaCha20 nonce
pub const MAC_SIZE:    usize = 16;   // Poly1305 tag
pub const MIN_LEN:     usize = 1 + KEM_CT_SIZE + NONCE_SIZE + MAC_SIZE; // 1161

pub const VERSION_AAD: &[u8] = &[0xf1];

// ── Malformed packet decoder ─────────────────────────────────────────────────

/// Decode a v0xF1 packet with a dummy key. Tests structural safety.
/// Must NEVER panic — only return Err.
pub fn try_decode(payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    if payload.len() < MIN_LEN {
        return Err("payload too short");
    }
    if payload[0] != VERSION {
        return Err("version mismatch");
    }

    let nonce_bytes = &payload[1 + KEM_CT_SIZE..1 + KEM_CT_SIZE + NONCE_SIZE];
    let aead_ct     = &payload[1 + KEM_CT_SIZE + NONCE_SIZE..];

    // Use a fixed dummy key — AEAD auth will fail, proving it fails cleanly
    let dummy_key = Sha256::digest(b"vault_fuzz_dummy_key_0xF1");
    let cipher = XChaCha20Poly1305::new(dummy_key[..].into());
    let nonce  = chacha20poly1305::XNonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, Payload { msg: aead_ct, aad: VERSION_AAD })
        .map_err(|_| "aead authentication failed")
}

// ── AEAD-only encrypt/decrypt (tests the symmetric layer) ────────────────────

/// Encrypt plaintext with a given 32-byte key, producing a full v0xF1 packet.
/// The KEM CT region is filled with the key hash (placeholder for testing).
pub fn encrypt_aead(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let nonce_bytes: [u8; 24] = rand::random();
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce  = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let aead_ct = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: VERSION_AAD })
        .expect("encrypt failed");

    // Pack: [0xF1] + [KEM CT placeholder 1120B] + [nonce 24B] + [AEAD CT]
    let kem_placeholder = Sha256::digest(key); // deterministic fill
    let mut payload = Vec::with_capacity(1 + KEM_CT_SIZE + NONCE_SIZE + aead_ct.len());
    payload.push(VERSION);
    // Fill 1120B KEM CT region with repeated hash (not real KEM, just testing AEAD)
    for _ in 0..(KEM_CT_SIZE / 32) {
        payload.extend_from_slice(kem_placeholder.as_ref());
    }
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&aead_ct);
    payload
}

/// Decrypt a v0xF1 packet with a given 32-byte key (AEAD layer only).
pub fn decrypt_aead(key: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    if payload.len() < MIN_LEN { return Err("too short"); }
    if payload[0] != VERSION   { return Err("version mismatch"); }

    let nonce_bytes = &payload[1 + KEM_CT_SIZE..1 + KEM_CT_SIZE + NONCE_SIZE];
    let aead_ct     = &payload[1 + KEM_CT_SIZE + NONCE_SIZE..];

    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce  = chacha20poly1305::XNonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, Payload { msg: aead_ct, aad: VERSION_AAD })
        .map_err(|_| "aead authentication failed")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests_malformed {
    use super::*;

    #[test]
    fn empty_payload() {
        assert_eq!(try_decode(&[]), Err("payload too short"));
    }

    #[test]
    fn one_byte_short() {
        let p = vec![0xf1u8; MIN_LEN - 1];
        assert_eq!(try_decode(&p), Err("payload too short"));
    }

    #[test]
    fn wrong_version() {
        let mut p = vec![0u8; MIN_LEN];
        p[0] = 0x01;
        assert_eq!(try_decode(&p), Err("version mismatch"));
    }

    #[test]
    fn correct_version_garbage_returns_aead_error() {
        let mut p = vec![0u8; MIN_LEN];
        p[0] = VERSION;
        assert_eq!(try_decode(&p), Err("aead authentication failed"));
    }

    #[test]
    fn all_ff_does_not_panic() {
        let mut p = vec![0xffu8; MIN_LEN];
        p[0] = VERSION;
        assert!(try_decode(&p).is_err());
    }

    #[test]
    fn truncated_at_every_boundary() {
        let cuts = [0, 1, 1 + MLKEM_CT, 1 + KEM_CT_SIZE, 1 + KEM_CT_SIZE + NONCE_SIZE];
        for &cut in &cuts {
            let p = vec![VERSION; cut];
            assert!(try_decode(&p).is_err(), "panicked at cut={}", cut);
        }
    }

    #[test]
    fn oversized_payload() {
        let mut p = vec![0u8; MIN_LEN + 65536];
        p[0] = VERSION;
        assert!(try_decode(&p).is_err());
    }
}

#[cfg(test)]
mod tests_roundtrip {
    use super::*;

    const TEST_KEY: &[u8; 32] = b"vault_test_key__0xF1_roundtrip!x";

    #[test]
    fn empty_plaintext() {
        let ct = encrypt_aead(TEST_KEY, b"");
        assert_eq!(decrypt_aead(TEST_KEY, &ct).unwrap(), b"");
    }

    #[test]
    fn short_message() {
        let msg = b"hello vault";
        assert_eq!(decrypt_aead(TEST_KEY, &encrypt_aead(TEST_KEY, msg)).unwrap(), msg);
    }

    #[test]
    fn long_message() {
        let msg = vec![0xABu8; 4096];
        assert_eq!(decrypt_aead(TEST_KEY, &encrypt_aead(TEST_KEY, &msg)).unwrap(), msg);
    }

    #[test]
    fn version_byte_is_0xf1() {
        let ct = encrypt_aead(TEST_KEY, b"test");
        assert_eq!(ct[0], VERSION);
    }

    #[test]
    fn correct_packet_size() {
        let ct = encrypt_aead(TEST_KEY, b"x");
        // 1 + 1120 + 24 + (1 plaintext + 16 MAC) = 1162
        assert_eq!(ct.len(), 1 + KEM_CT_SIZE + NONCE_SIZE + 1 + MAC_SIZE);
    }

    #[test]
    fn bitflip_in_aead_fails_auth() {
        let mut ct = encrypt_aead(TEST_KEY, b"sensitive");
        let flip_pos = 1 + KEM_CT_SIZE + NONCE_SIZE;
        ct[flip_pos] ^= 0x01;
        assert_eq!(decrypt_aead(TEST_KEY, &ct), Err("aead authentication failed"));
    }

    #[test]
    fn wrong_key_fails_auth() {
        let ct = encrypt_aead(TEST_KEY, b"secret");
        let wrong_key = b"wrong_key_should_fail_auth_0xF1!";
        assert_eq!(decrypt_aead(wrong_key, &ct), Err("aead authentication failed"));
    }

    #[test]
    fn wrong_version_rejected() {
        let mut ct = encrypt_aead(TEST_KEY, b"test");
        ct[0] = 0x01;
        assert_eq!(decrypt_aead(TEST_KEY, &ct), Err("version mismatch"));
    }
}
