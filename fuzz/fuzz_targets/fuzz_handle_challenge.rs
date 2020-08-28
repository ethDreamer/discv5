#![no_main]
use discv5::enr::{CombinedKey, EnrBuilder};
use discv5::{handler::Handler, packet::Packet, Discv5ConfigBuilder, Enr, InboundPacket};
use libfuzzer_sys::fuzz_target;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub type Magic = [u8; 32];
#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref KEY: CombinedKey = CombinedKey::generate_secp256k1();
    static ref ENR: Enr = {
        let combined_key: &CombinedKey = &KEY;
        EnrBuilder::new("v4").build(combined_key).unwrap()
    };
    static ref HANDLER: Arc<RwLock<Handler>> = {
        let config = Discv5ConfigBuilder::new().build();
        let mut bytes = KEY.encode();

        let combined_key = CombinedKey::secp256k1_from_bytes(&mut bytes).unwrap();
        let enr: Enr = ENR.clone();
        Arc::new(RwLock::new(Handler::new_fuzz(
            Arc::new(RwLock::new(enr)),
            Arc::new(RwLock::new(combined_key)),
            config,
        )))
    };
    static ref MAGIC: Magic = {
        let mut hasher = Sha256::new();
        hasher.input(ENR.node_id().raw());
        hasher.input(b"WHOAREYOU");
        let mut magic: Magic = Default::default();
        magic.copy_from_slice(&hasher.result());
        magic
    };
}

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = Packet::decode(&data, &MAGIC) {
        let inbound_packet = InboundPacket {
            src: "127.0.0.1:9000".parse().unwrap(),
            packet,
        };
        send_message(inbound_packet);
    }
});

fn send_message(inbound_packet: InboundPacket) {
    let _ = env_logger::builder().is_test(true).try_init();

    futures::executor::block_on(async move {
        HANDLER.write().process_inbound_packet(inbound_packet).await;
    })
}
