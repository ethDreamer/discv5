#![no_main]
use discv5::rpc::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::decode(data.to_vec()) {
        message.encode();
    }
});
