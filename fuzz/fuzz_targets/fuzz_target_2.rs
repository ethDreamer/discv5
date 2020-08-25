#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate discv5;

use discv5::rpc::Message;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here

    Message::decode(data.to_vec());
});
