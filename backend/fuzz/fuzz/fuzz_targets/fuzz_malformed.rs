#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_fuzz::try_decode;

fuzz_target!(|data: &[u8]| {
    let _ = try_decode(data);
});
