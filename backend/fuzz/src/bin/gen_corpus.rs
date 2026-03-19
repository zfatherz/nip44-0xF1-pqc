/// gen_corpus — writes seed files into both fuzz corpus directories.
///
/// Run once before fuzzing to unlock deep AEAD coverage:
///   cargo run --bin gen_corpus
///
/// Without seeds, fuzz_malformed never passes the MIN_LEN (1161 B) guard,
/// so libFuzzer stays at cov=24 forever.  One valid-shaped packet lets
/// every mutation reach the XChaCha20-Poly1305 authentication paths.

use std::{fs, path::Path};
use vault_fuzz::{encrypt_aead, MIN_LEN, VERSION, KEM_CT_SIZE, NONCE_SIZE};

fn main() {
    // ── fuzz_malformed seeds ─────────────────────────────────────────────────
    // Needs a structurally valid packet (right length + version byte).
    // We generate several variants so the fuzzer has diverse starting points.

    let malformed_dir = Path::new("fuzz/corpus/fuzz_malformed");
    fs::create_dir_all(malformed_dir).unwrap();

    let key: &[u8; 32] = b"vault_seed_key__0xF1_gen_corpus!";

    // Seed 0: valid empty-plaintext packet  → reaches AEAD auth fail
    let seed0 = encrypt_aead(key, b"");
    fs::write(malformed_dir.join("seed_empty_plaintext"), &seed0).unwrap();

    // Seed 1: valid 32-byte plaintext packet
    let seed1 = encrypt_aead(key, &[0xABu8; 32]);
    fs::write(malformed_dir.join("seed_32b_plaintext"), &seed1).unwrap();

    // Seed 2: minimum-length all-zeros packet with correct version byte
    //   (fails AEAD auth — tests the parser boundary exactly at MIN_LEN)
    let mut seed2 = vec![0u8; MIN_LEN];
    seed2[0] = VERSION;
    fs::write(malformed_dir.join("seed_min_len_zeros"), &seed2).unwrap();

    // Seed 3: minimum-length all-0xFF packet with correct version byte
    let mut seed3 = vec![0xFFu8; MIN_LEN];
    seed3[0] = VERSION;
    fs::write(malformed_dir.join("seed_min_len_ff"), &seed3).unwrap();

    // Seed 4: valid packet but nonce zeroed out  → AEAD auth fail
    let mut seed4 = encrypt_aead(key, b"nonce-zero test");
    let nonce_start = 1 + KEM_CT_SIZE;
    seed4[nonce_start..nonce_start + NONCE_SIZE].fill(0);
    fs::write(malformed_dir.join("seed_zero_nonce"), &seed4).unwrap();

    println!(
        "✓  fuzz/corpus/fuzz_malformed/ — {} seeds written ({} bytes each min)",
        5, MIN_LEN
    );

    // ── fuzz_roundtrip seeds ─────────────────────────────────────────────────
    // fuzz_roundtrip already builds a rich corpus from scratch (cov=498),
    // but a seed for an empty and a large plaintext speeds up early coverage.

    let roundtrip_dir = Path::new("fuzz/corpus/fuzz_roundtrip");
    fs::create_dir_all(roundtrip_dir).unwrap();

    fs::write(roundtrip_dir.join("seed_empty"), b"").unwrap();
    fs::write(roundtrip_dir.join("seed_one_byte"), b"\x00").unwrap();
    fs::write(roundtrip_dir.join("seed_ascii"), b"hello nip44 vault").unwrap();
    fs::write(roundtrip_dir.join("seed_binary_256"), &(0u8..=255).collect::<Vec<_>>()).unwrap();

    println!("✓  fuzz/corpus/fuzz_roundtrip/ — 4 seeds written");
    println!("\nNow run:");
    println!("  cargo +nightly fuzz run fuzz_malformed -- -max_total_time=60");
    println!("  cargo +nightly fuzz run fuzz_roundtrip  -- -max_total_time=60");
}
