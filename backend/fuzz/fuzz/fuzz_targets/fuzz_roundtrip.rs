#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_fuzz::{encrypt_aead, decrypt_aead};

const TEST_KEY: &[u8; 32] = b"vault_test_key__0xF1_roundtrip!x";

fuzz_target!(|plaintext: &[u8]| {
    let ct = encrypt_aead(TEST_KEY, plaintext);
    let recovered = decrypt_aead(TEST_KEY, &ct)
        .expect("roundtrip decrypt failed on valid ciphertext");
    assert_eq!(plaintext, recovered.as_slice(), "ROUNDTRIP FAILURE");
});
