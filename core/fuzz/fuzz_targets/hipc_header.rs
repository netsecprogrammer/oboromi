#![no_main]

use libfuzzer_sys::fuzz_target;
use oboromi_core::nn::hipc::Header;

fuzz_target!(|data: &[u8]| {
    let header = Header::parse(data);
    assert_eq!(header.is_ok(), data.len() >= Header::SIZE);

    if Header::parse_message(data).is_ok() {
        assert!(header.is_ok());
    }
});
