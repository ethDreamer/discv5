#![no_main]
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, SocketAddr};
use discv5::packet::Packet;
use discv5::{Discv5ConfigBuilder, handler::Handler, InboundPacket, TokioExecutor};
use discv5::enr::{CombinedKey, EnrBuilder};
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::{time::delay_for, select};
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    if data.len() > 32 {
        let mut magic_data = [0u8;32];
        magic_data.copy_from_slice(&data[..32]);
        if let Ok(packet) = Packet::decode(&data[32..], &magic_data) {
            init();

            let sender_port = 5000;
            let receiver_port = 5001;
            let ip: IpAddr = "127.0.0.1".parse().unwrap();

            let key1 = CombinedKey::generate_secp256k1();
            let key2 = CombinedKey::generate_secp256k1();

            let config = Discv5ConfigBuilder::new()
                .executor(Box::new(TokioExecutor(tokio::runtime::Handle::current())))
                .build();

            let sender_enr = EnrBuilder::new("v4")
                .ip(ip)
                .udp(sender_port)
                .build(&key1)
                .unwrap();
            let receiver_enr = EnrBuilder::new("v4")
                .ip(ip)
                .udp(receiver_port)
                .build(&key2)
                .unwrap();

            let (_exit_send, sender_handler, _, sender_socket) = Handler::spawn(
                arc_rw!(sender_enr.clone()),
                arc_rw!(key1),
                sender_enr.udp_socket().unwrap(),
                config.clone(),
            )
            .unwrap();

            let (_exit_recv, recv_send, mut receiver_handler, _) = Handler::spawn(
                arc_rw!(receiver_enr.clone()),
                arc_rw!(key2),
                receiver_enr.udp_socket().unwrap(),
                config,
            )
            .unwrap();

            // Convert Packet to socket::InboundPacket
            let outbound_packet = OutboundPacket {
                src: SocketAddr::new(ip, receiver_port), // source address
                packet: packet,
            };

            // Note this will have limited coverage in whoareyou and auth_header packets
            // TODO: sender needs to send this packet
        }
    }
});
