#![no_main]

use libfuzzer_sys::fuzz_target;
use oboromi_core::loader::nso::NsoImage;

fuzz_target!(|data: &[u8]| {
    let _ = NsoImage::parse_with_max_section_size(data, 1024 * 1024);
});
