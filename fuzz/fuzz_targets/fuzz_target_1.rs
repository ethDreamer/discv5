#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate discv5;

use discv5::packet::Packet;

fuzz_target!(|data: &[u8]| {
    if data.len() > 32 {
        let mut magic_data = [0u8;32];
        magic_data.copy_from_slice(&data[..32]);
        Packet::decode(&data[32..], &magic_data);
    }
});
