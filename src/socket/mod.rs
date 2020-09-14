use crate::packet::*;
use crate::Executor;
use parking_lot::RwLock;
use recv::*;
use send::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

mod filter;
mod recv;
mod send;

pub use filter::{FilterConfig, FilterConfigBuilder};
pub use recv::InboundPacket;
pub(crate) use recv::MAX_PACKET_SIZE;
pub use send::OutboundPacket;
/// Convenience objects for setting up the recv handler.
pub struct SocketConfig {
    /// The executor to spawn the tasks.
    pub executor: Box<dyn Executor + Send + Sync>,
    /// The listening socket.
    pub socket_addr: SocketAddr,
    /// Configuration details for the packet filter.
    pub filter_config: FilterConfig,
    pub expected_responses: Arc<RwLock<HashMap<SocketAddr, usize>>>,
    /// The WhoAreYou magic packet.
    pub whoareyou_magic: [u8; MAGIC_LENGTH],
}

/// Creates the UDP socket and handles the exit futures for the send/recv UDP handlers.
pub struct Socket {
    pub send: mpsc::Sender<OutboundPacket>,
    pub recv: mpsc::Receiver<InboundPacket>,
    sender_exit: Option<oneshot::Sender<()>>,
    recv_exit: Option<oneshot::Sender<()>>,
}

impl Socket {
    // Creates a std UDP Socket which can be called outside of a tokio execution environment. These
    // verifies the creation of the socket. Once established we create the underlying Recv and Send
    // Handlers with the `new()` function.
    pub(crate) fn new_socket(
        socket_addr: SocketAddr,
    ) -> Result<std::net::UdpSocket, std::io::Error> {
        // set up the UDP socket
        let socket = {
            let domain = match socket_addr {
                SocketAddr::V4(_) => socket2::Domain::ipv4(),

                SocketAddr::V6(_) => socket2::Domain::ipv6(),
            };
            socket2::Socket::new(
                domain,
                socket2::Type::dgram(),
                Some(socket2::Protocol::udp()),
            )?
        };
        socket.reuse_address()?;
        socket.bind(&socket_addr.into())?;
        Ok(socket.into_udp_socket())
    }

    /// Creates a UDP socket, spawns a send/recv task and returns the channels.
    /// If this struct is dropped, the send/recv tasks will shutdown.
    /// This needs to be run inside of a tokio executor.
    pub(crate) fn new(
        socket: std::net::UdpSocket,
        config: SocketConfig,
    ) -> Result<Self, std::io::Error> {
        let socket = tokio::net::UdpSocket::from_std(socket)?;

        // split the UDP socket
        let (recv_udp, send_udp) = socket.split();

        // spawn the recv handler
        let recv_config = RecvHandlerConfig {
            filter_config: config.filter_config,
            executor: config.executor.clone(),
            recv: recv_udp,
            whoareyou_magic: config.whoareyou_magic,
            expected_responses: config.expected_responses,
        };

        let (recv, recv_exit) = RecvHandler::spawn(recv_config);
        // spawn the sender handler
        let (send, sender_exit) = SendHandler::spawn(config.executor.clone(), send_udp);

        Ok(Socket {
            send,
            recv,
            sender_exit: Some(sender_exit),
            recv_exit: Some(recv_exit),
        })
    }
}

impl std::ops::Drop for Socket {
    // close the send/recv handlers
    fn drop(&mut self) {
        self.sender_exit
            .take()
            .expect("Exit always exists")
            .send(())
            .unwrap_or_else(|_| ());
        self.recv_exit
            .take()
            .expect("Exit always exists")
            .send(())
            .unwrap_or_else(|_| ());
    }
}
