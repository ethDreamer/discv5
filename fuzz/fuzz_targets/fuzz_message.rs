#![no_main]
use libfuzzer_sys::fuzz_target;
use discv5::rpc::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::decode(data.to_vec()) {
        message.encode();
    }
});
