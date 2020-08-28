#![no_main]
use discv5::enr::{CombinedKey, EnrBuilder, NodeId};
use discv5::handler::{crypto, Handler, Keys, NodeAddress, NodeContact, Session};
use discv5::packet::{Packet, Tag};
use discv5::{Discv5ConfigBuilder, Enr, InboundPacket};
use libfuzzer_sys::fuzz_target;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub type Magic = [u8; 32];
#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref KEY_A: CombinedKey = CombinedKey::generate_secp256k1();
    static ref ENR_A: Enr = {
        let combined_key: &CombinedKey = &KEY_A;
        EnrBuilder::new("v4").build(combined_key).unwrap()
    };
    static ref KEY_B: CombinedKey = CombinedKey::generate_secp256k1();
    static ref ENR_B: Enr = {
        let combined_key: &CombinedKey = &KEY_B;
        EnrBuilder::new("v4").build(combined_key).unwrap()
    };
    // Handler for A to receive messages
    static ref HANDLER: Arc<RwLock<Handler>> = {
        let config = Discv5ConfigBuilder::new().build();
        let mut bytes = KEY_A.encode();

        let combined_key = CombinedKey::secp256k1_from_bytes(&mut bytes).unwrap();
        let enr: Enr = ENR_A.clone();
        Arc::new(RwLock::new(Handler::new_fuzz(
            Arc::new(RwLock::new(enr)),
            Arc::new(RwLock::new(combined_key)),
            config,
        )))
    };
    // Magic Packets for A
    static ref MAGIC: Magic = {
        let mut hasher = Sha256::new();
        hasher.input(ENR_A.node_id().raw());
        hasher.input(b"WHOAREYOU");
        let mut magic: Magic = Default::default();
        magic.copy_from_slice(&hasher.result());
        magic
    };
    // [Session A, Session B]
    static ref SESSIONS: [Session; 2] = {
        let nonce = [1u8; 32];
        // Session A keys
        let (encryption_key, decryption_key, auth_resp_key, ephem_pubkey) =
            crypto::generate_session_keys(&ENR_A.node_id(), &NodeContact::Enr(Box::new(ENR_B.clone())), &nonce).unwrap();
        let session_a = Session::new(Keys {
            auth_resp_key,
            encryption_key,
            decryption_key,
        });
        // Session B keys (requires ephemeral public key from A)
        let (decryption_key, encryption_key, auth_resp_key) = crypto::derive_keys_from_pubkey(
            &KEY_B,
            &ENR_B.node_id(),
            &ENR_A.node_id(),
            &nonce,
            &ephem_pubkey,
        ).unwrap();
        let session_b = Session::new(Keys {
            auth_resp_key,
            encryption_key,
            decryption_key,
        });
        [session_a, session_b]
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

fn send_message(mut inbound_packet: InboundPacket) {
    let _ = env_logger::builder().is_test(true).try_init();

    // Handler A has a Session with B
    let node_address = NodeAddress::new(inbound_packet.src, ENR_B.node_id());
    HANDLER
        .write()
        .new_session(node_address.clone(), SESSIONS[0].clone());

    // Update packet.tag to match node_id
    let tag = tag(&ENR_B.node_id(), &ENR_A.node_id());
    inbound_packet.packet.set_tag(tag);

    // Note: We will only get as far a decrypt_message before it errors,
    // so this is essentially fuzzing decrypt message and earlier.
    // Handler A process Packet from B
    futures::executor::block_on(async move {
        HANDLER.write().process_inbound_packet(inbound_packet).await;
    })
}

/// Calculates the tag given a `NodeId`.
fn tag(src: &NodeId, dst_id: &NodeId) -> Tag {
    let hash = Sha256::digest(&dst_id.raw());
    let mut tag: Tag = Default::default();
    for i in 0..32 {
        tag[i] = hash[i] ^ src.raw()[i];
    }
    tag
}
