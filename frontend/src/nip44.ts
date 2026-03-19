// frontend/src/nip44.ts
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes, concatBytes } from '@noble/hashes/utils.js';

const VERSION_BYTE = new Uint8Array([0xf1]);
const HKDF_SALT = new TextEncoder().encode('NIP44_0xF1_XWING_KEYGEN_V1');

// KEM ciphertext is ML-KEM-768 (1088B) + X25519 ephemeral key (32B) = 1120B
const KEM_CT_SIZE = 1120;
const NONCE_SIZE = 24;

export function deriveXWingKeypair(secret: Uint8Array) {
    // Derive a 32-byte deterministic seed from the nsec via HKDF-SHA256
    const seed = hkdf(sha256, secret, HKDF_SALT, new Uint8Array(), 32);
    return ml_kem768_x25519.keygen(seed);
}

export function encrypt_v0xF1(recipientPub: Uint8Array, plaintext: Uint8Array): Uint8Array {
    // 1. Encapsulate: produces a 64B raw hybrid shared secret + 1120B KEM ciphertext
    const { sharedSecret: rawSecret, cipherText: kemCt } = ml_kem768_x25519.encapsulate(recipientPub);

    // 2. Compress the 64B raw shared secret to 32B via SHA-256 for XChaCha20 key input
    const finalSymmetricKey = sha256(rawSecret);

    // 3. Symmetric encryption (XChaCha20-Poly1305)
    const nonce = randomBytes(NONCE_SIZE);
    const cipher = xchacha20poly1305(finalSymmetricKey, nonce, VERSION_BYTE);
    const encryptedPayload = cipher.encrypt(plaintext);

    // 4. Pack payload: [version 1B] + [KEM CT 1120B] + [nonce 24B] + [AEAD CT + MAC]
    const finalPayload = concatBytes(VERSION_BYTE, kemCt, nonce, encryptedPayload);

    // Zeroize sensitive key material from memory
    finalSymmetricKey.fill(0);
    rawSecret.fill(0);

    return finalPayload;
}

export function decrypt_v0xF1(recipientSecret: Uint8Array, payload: Uint8Array): Uint8Array {
    if (payload[0] !== 0xf1) {
        throw new Error(`Version mismatch: expected 0xF1`);
    }

    const kemCt = payload.subarray(1, 1 + KEM_CT_SIZE);
    const nonce = payload.subarray(1 + KEM_CT_SIZE, 1 + KEM_CT_SIZE + NONCE_SIZE);
    const cipherText = payload.subarray(1 + KEM_CT_SIZE + NONCE_SIZE);

    // 1. Decapsulate: recover the 64B raw hybrid shared secret
    const rawSecret = ml_kem768_x25519.decapsulate(kemCt, recipientSecret);

    // 2. Same SHA-256 compression to 32B for the decryption key
    const finalSymmetricKey = sha256(rawSecret);

    const cipher = xchacha20poly1305(finalSymmetricKey, nonce, VERSION_BYTE);
    const plaintext = cipher.decrypt(cipherText);

    // Zeroize sensitive key material from memory
    finalSymmetricKey.fill(0);
    rawSecret.fill(0);

    return plaintext;
}