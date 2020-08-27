#![no_main]
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, SocketAddr};
use discv5::rpc::{Message, Request};
use discv5::{Discv5ConfigBuilder, handler::{Handler, HandlerRequest, HandlerResponse}, InboundPacket, TokioExecutor};
use discv5::enr::{CombinedKey, EnrBuilder};
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::{time::delay_for, select};
use std::time::Duration;

macro_rules! arc_rw {
    ( $x: expr ) => {
        Arc::new(RwLock::new($x))
    };
}

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::decode(data.to_vec()) {
        send_message(message);
    }
});

fn send_message(message: Message) {
    let _ = env_logger::builder().is_test(true).try_init();

    let sender_port = 5000;
    let receiver_port = 5001;
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    let key1 = CombinedKey::generate_secp256k1();
    let key2 = CombinedKey::generate_secp256k1();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = Discv5ConfigBuilder::new()
        .executor(Box::new(TokioExecutor(rt.handle().clone())))
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

    let (_exit_send, sender_handler, _) = Handler::spawn(
        arc_rw!(sender_enr.clone()),
        arc_rw!(key1),
        sender_enr.udp_socket().unwrap(),
        config.clone(),
    )
    .unwrap();

    let (_exit_recv, recv_send, mut receiver_handler) = Handler::spawn(
        arc_rw!(receiver_enr.clone()),
        arc_rw!(key2),
        receiver_enr.udp_socket().unwrap(),
        config,
    )
    .unwrap();


    // Send HandlerRequest to receiver
    match message {
        Message::Request(req) => {
            let send_message = Box::new(req);
            let _ = sender_handler.send(HandlerRequest::Request(
                receiver_enr.into(),
                send_message.clone(),
            ));
            // Force the receiver to handle it
            let receiver = async move {
                loop {
                    if let Some(message) = receiver_handler.recv().await {
                        match message {
                            HandlerResponse::WhoAreYou(wru_ref) => {
                                let _ = recv_send
                                .send(HandlerRequest::WhoAreYou(wru_ref, Some(sender_enr.clone())));
                            }
                            HandlerResponse::Request(_, request) => {
                                assert_eq!(request, send_message);
                                return;
                            }
                            _ => {}
                        }
                    }
                }
            };

            // Ensure messages were received and processed within timeout.
            async {
                select! {
                    _ = receiver => {}
                    _ = delay_for(Duration::from_millis(100)) => {
                        panic!("Test timed out");
                    }
                }
            };
        }
        _ => {}
    }
}
