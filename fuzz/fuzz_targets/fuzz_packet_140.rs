#![no_main]
use discv5::packet::{Packet, AUTH_TAG_LENGTH, MAGIC_LENGTH, TAG_LENGTH};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > TAG_LENGTH + AUTH_TAG_LENGTH + MAGIC_LENGTH {
        // Prepare fixed length Magic
        let mut magic_data = [0u8; MAGIC_LENGTH];
        magic_data.copy_from_slice(&data[..MAGIC_LENGTH]);

        // Set data tag to 140 (bytes / list)
        let mut data_140 = data[MAGIC_LENGTH..].to_vec();
        data_140[TAG_LENGTH] = 140;

        // Fuzz decode packet
        if let Ok(packet) = Packet::decode(&data_140, &magic_data) {
            packet.encode();
        }
    }
});
