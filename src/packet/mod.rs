//! This module defines the raw UDP message packets for Discovery v5.1.
//!
//! The [discv5 wire specification](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md) provides further information on UDP message packets as implemented in this module.
//!
//! A [`Packet`] defines all raw UDP message variants and implements the encoding/decoding
//! logic.
//!
//! Note, that all message encryption/decryption is handled outside of this module.
//!
//! [`Packet`]: enum.Packet.html

use crate::error::PacketError;
use crate::Enr;
use enr::NodeId;
use rand::Rng;
use std::convert::TryInto;

use aes_ctr::stream_cipher::{generic_array::GenericArray, NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes128Ctr;
use zeroize::Zeroize;

/// The packet IV length (u128).
pub const IV_LENGTH: usize = 16;
/// The length of the static header. (6 byte protocol id, 2 bytes version, 1 byte kind, 12 byte
/// message nonce and a 2 byte authdata-size).
pub const STATIC_HEADER_LENGTH: usize = 23;
/// The message nonce length (in bytes).
pub const MESSAGE_NONCE_LENGTH: usize = 12;
/// The Id nonce legnth (in bytes).
pub const ID_NONCE_LENGTH: usize = 32;

/// Protocol ID sent with each message.
const PROTOCOL_ID: &str = "discv5  ";
/// The version sent with each handshake.
const VERSION: u16 = 0x0001;

/// Message Nonce (12 bytes).
pub type MessageNonce = [u8; MESSAGE_NONCE_LENGTH];
/// The nonce sent in a WHOAREYOU packet.
pub type IdNonce = [u8; ID_NONCE_LENGTH];

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    /// Random data unique to the packet.
    pub iv: u128,
    /// Protocol header.
    pub header: PacketHeader,
    /// The message contents itself.
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PacketHeader {
    /// The source NodeId of the packet.
    pub src_id: NodeId,
    /// The type of packet this is.
    pub kind: PacketKind,
}

impl PacketHeader {
    // Encodes the header to bytes to be included into the `masked-header` of the Packet Encoding.
    pub fn encode(&self) -> Vec<u8> {
        let auth_data = self.kind.encode();
        let mut buf = Vec::with_capacity(auth_data.len() + 8 + 32 + 1 + 2); // protocol_id size + node_id size + kind + authdata_size
        buf.extend_from_slice(PROTOCOL_ID.as_bytes());
        buf.extend_from_slice(&self.src_id.raw());
        let kind: u8 = (&self.kind).into();
        buf.extend_from_slice(&kind.to_be_bytes());
        buf.extend_from_slice(&(auth_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&auth_data);

        buf
    }

    // If the packet is not a challenge, the authenticated data is the encoded header.
    pub fn authenticated_data(&self) -> Vec<u8> {
        if let PacketKind::WhoAreYou { .. } = self.kind {
            return Vec::new();
        }

        // all else requires the encoded header
        self.encode()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PacketKind {
    /// An ordinary message.
    Message(MessageNonce),
    /// A WHOAREYOU packet.
    WhoAreYou {
        /// The request nonce the WHOAREYOU references.
        request_nonce: MessageNonce,
        /// The ID Nonce to be verified.
        id_nonce: IdNonce,
        /// The local node's current ENR sequence number.
        enr_seq: u64,
    },
    /// A handshake message.
    Handshake {
        /// The nonce of the message.
        message_nonce: MessageNonce,
        /// Id-nonce signature that matches the WHOAREYOU request.
        id_nonce_sig: Vec<u8>,
        /// The ephemeral public key of the handshake.
        ephem_pubkey: Vec<u8>,
        /// The ENR record of the node if the WHOAREYOU request is out-dated.
        enr_record: Option<Enr>,
    },
}

impl Into<u8> for &PacketKind {
    fn into(self) -> u8 {
        match self {
            PacketKind::Message(_) => 0,
            PacketKind::WhoAreYou { .. } => 1,
            PacketKind::Handshake { .. } => 2,
        }
    }
}

impl PacketKind {
    /// Encodes the packet type into its corresponding auth_data.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PacketKind::Message(message_nonce) => message_nonce.to_vec(),
            PacketKind::WhoAreYou {
                request_nonce,
                id_nonce,
                enr_seq,
            } => {
                let mut auth_data = Vec::with_capacity(52);
                auth_data.extend_from_slice(request_nonce);
                auth_data.extend_from_slice(id_nonce);
                auth_data.extend_from_slice(&enr_seq.to_be_bytes());
                debug_assert_eq!(auth_data.len(), 52);
                auth_data
            }
            PacketKind::Handshake {
                message_nonce,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            } => {
                let sig_size = id_nonce_sig.len();
                let pubkey_size = ephem_pubkey.len();
                let node_record = enr_record.as_ref().map(|enr| rlp::encode(enr));
                let expected_len = 15
                    + sig_size
                    + pubkey_size
                    + node_record.as_ref().map(|x| x.len()).unwrap_or_default();

                let mut auth_data = Vec::with_capacity(expected_len);
                auth_data.extend_from_slice(&VERSION.to_be_bytes());
                auth_data.extend_from_slice(message_nonce);
                auth_data.extend_from_slice(&(sig_size as u8).to_be_bytes());
                auth_data.extend_from_slice(&(pubkey_size as u8).to_be_bytes());
                auth_data.extend_from_slice(id_nonce_sig);
                auth_data.extend_from_slice(ephem_pubkey);
                if let Some(node_record) = node_record {
                    auth_data.extend_from_slice(&node_record);
                }

                debug_assert_eq!(auth_data.len(), expected_len);

                auth_data
            }
        }
    }

    pub fn is_whoareyou(&self) -> bool {
        match self {
            PacketKind::WhoAreYou { .. } => true,
            _ => false,
        }
    }

    /// Decodes auth data, given the kind byte.
    pub fn decode(kind: u8, auth_data: &[u8]) -> Result<Self, PacketError> {
        match kind {
            0 => {
                // Decoding a message packet
                // This should only contain a 12 byte nonce.
                if auth_data.len() != MESSAGE_NONCE_LENGTH {
                    return Err(PacketError::InvalidAuthDataSize);
                }
                Ok(PacketKind::Message(
                    auth_data.try_into().expect("Must have the correct length"),
                ))
            }
            1 => {
                // Decoding a WHOAREYOU packet
                // This must be 52 bytes long.
                if auth_data.len() != 52 {
                    return Err(PacketError::InvalidAuthDataSize);
                }
                let request_nonce: MessageNonce = auth_data[..MESSAGE_NONCE_LENGTH]
                    .try_into()
                    .expect("MESSAGE_NONCE_LENGTH is the correct size");
                let id_nonce: IdNonce = auth_data
                    [MESSAGE_NONCE_LENGTH..MESSAGE_NONCE_LENGTH + ID_NONCE_LENGTH]
                    .try_into()
                    .expect("ID_NONCE_LENGTH must be the correct size");
                let enr_seq = u64::from_be_bytes(
                    auth_data[MESSAGE_NONCE_LENGTH + ID_NONCE_LENGTH..]
                        .try_into()
                        .expect("The length of the authdata must be 52 bytes"),
                );

                Ok(PacketKind::WhoAreYou {
                    request_nonce,
                    id_nonce,
                    enr_seq,
                })
            }
            2 => {
                // Decoding a Handshake packet
                // Start by decoding the header
                if auth_data.len() < 3 + MESSAGE_NONCE_LENGTH {
                    // The auth_data header is too short
                    return Err(PacketError::InvalidAuthDataSize);
                }

                // verify the version
                if auth_data[0] != VERSION {
                    return Err(PacketError::InvalidVersion(auth_data[0]));
                }

                // decode the lengths
                let message_nonce: MessageNonce = auth_data[1..MESSAGE_NONCE_LENGTH + 1]
                    .try_into()
                    .expect("MESSAGE_NONCE_LENGTH is the correct size");
                let sig_size = auth_data[MESSAGE_NONCE_LENGTH + 1];
                let eph_key_size = auth_data[MESSAGE_NONCE_LENGTH + 2];

                let sig_key_size = (sig_size + eph_key_size) as usize;
                // verify the auth data length
                if auth_data.len() < 3 + MESSAGE_NONCE_LENGTH + sig_key_size {
                    return Err(PacketError::InvalidAuthDataSize);
                }

                let remaining_data = &auth_data[MESSAGE_NONCE_LENGTH + 3..];

                let id_nonce_sig = remaining_data[0..sig_size as usize].to_vec();
                let ephem_pubkey = remaining_data[sig_size as usize..sig_key_size].to_vec();

                let enr_record = if remaining_data.len() > sig_key_size {
                    Some(
                        rlp::decode::<Enr>(&remaining_data[sig_key_size..])
                            .map_err(PacketError::InvalidEnr)?,
                    )
                } else {
                    None
                };

                Ok(PacketKind::Handshake {
                    message_nonce,
                    id_nonce_sig,
                    ephem_pubkey,
                    enr_record,
                })
            }
            _ => Err(PacketError::UnknownPacket),
        }
    }
}

/// The implementation of creating, encoding and decoding raw packets in the discv5.1 system.
//
// NOTE: We perform the encryption and decryption when we are encoding/decoding as this is
// performed in its own task in practice. The Handler can create the messages without the overhead
// of encryption/decryption and send them off to the send/recv tasks to perform the
// encryption/decryption.
impl Packet {
    /// Creates an ordinary message packet.
    pub fn new_message(src_id: NodeId, nonce: MessageNonce, ciphertext: Vec<u8>) -> Self {
        let iv: u128 = rand::random();

        let header = PacketHeader {
            src_id,
            kind: PacketKind::Message(nonce),
        };

        Packet {
            iv,
            header,
            message: ciphertext,
        }
    }

    pub fn new_whoareyou(
        src_id: NodeId,
        request_nonce: MessageNonce,
        id_nonce: IdNonce,
        enr_seq: u64,
    ) -> Self {
        let iv: u128 = rand::random();

        let header = PacketHeader {
            src_id,
            kind: PacketKind::WhoAreYou {
                request_nonce,
                id_nonce,
                enr_seq,
            },
        };

        Packet {
            iv,
            header,
            message: Vec::new(),
        }
    }

    pub fn new_authheader(
        src_id: NodeId,
        message_nonce: MessageNonce,
        id_nonce_sig: Vec<u8>,
        ephem_pubkey: Vec<u8>,
        enr_record: Option<Enr>,
    ) -> Self {
        let iv: u128 = rand::random();

        let header = PacketHeader {
            src_id,
            kind: PacketKind::Handshake {
                message_nonce,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            },
        };

        Packet {
            iv,
            header,
            message: Vec::new(),
        }
    }

    /// Generates a Packet::Random given a `tag`.
    pub fn new_random(src_id: &NodeId) -> Result<Self, &'static str> {
        let mut ciphertext = [0u8; 44];
        rand::thread_rng()
            .try_fill(&mut ciphertext[..])
            .map_err(|_| "PRNG failed")?;

        let message_nonce: MessageNonce = rand::random();

        Ok(Self::new_message(
            *src_id,
            message_nonce,
            ciphertext.to_vec(),
        ))
    }

    /// Returns true if the packet is a WHOAREYOU packet.
    pub fn is_whoareyou(&self) -> bool {
        match &self.header.kind {
            PacketKind::WhoAreYou { .. } => true,
            PacketKind::Message(_) | PacketKind::Handshake { .. } => false,
        }
    }

    /// Returns the message nonce if one exists.
    pub fn message_nonce(&self) -> Option<&MessageNonce> {
        match &self.header.kind {
            PacketKind::Message(message_nonce) => Some(message_nonce),
            PacketKind::WhoAreYou { .. } => None,
            PacketKind::Handshake { message_nonce, .. } => Some(message_nonce),
        }
    }

    /// Encodes a packet to bytes and performs the AES-CTR encryption.
    pub fn encode(self, dst_id: &NodeId) -> Vec<u8> {
        let header = self.generate_header(dst_id);
        let mut buf = Vec::with_capacity(IV_LENGTH + header.len() + self.message.len());
        buf.extend_from_slice(&self.iv.to_be_bytes());
        buf.extend_from_slice(&header);
        buf.extend_from_slice(&self.message);
        buf
    }

    /// Decodes a packet (data) given our local source id (src_key).
    pub fn decode(src_id: &NodeId, data: &[u8]) -> Result<Self, PacketError> {
        // The smallest packet must be at least this large
        // The 24 is the smallest auth_data that can be sent (it is by a WHOAREYOU packet)
        if data.len() < IV_LENGTH + STATIC_HEADER_LENGTH + 24 {
            return Err(PacketError::TooSmall);
        }

        // attempt to decrypt the static header
        let iv = data[..IV_LENGTH].to_vec();

        /* Decryption is done inline
         *
         * This was split into its own library, but brought back to allow re-use of the cipher when
         * performing the decryption
         */
        let key = GenericArray::clone_from_slice(&src_id.raw()[..16]);
        let nonce = GenericArray::clone_from_slice(&iv);
        let mut cipher = Aes128Ctr::new(&key, &nonce);

        // Take the static header content
        let mut static_header = data[IV_LENGTH..IV_LENGTH + STATIC_HEADER_LENGTH].to_vec();
        cipher.apply_keystream(&mut static_header);

        // double check the size
        if static_header.len() != STATIC_HEADER_LENGTH {
            return Err(PacketError::HeaderLengthInvalid(static_header.len()));
        }

        // Check the protocol id
        if &static_header[..8] != PROTOCOL_ID.as_bytes() {
            return Err(PacketError::HeaderDecryptionFailed);
        }

        // The decryption was successful, decrypt the remaining header
        let auth_data_size = u16::from_be_bytes(
            static_header[STATIC_HEADER_LENGTH - 2..]
                .try_into()
                .expect("Can only be 2 bytes in size"),
        );

        let remaining_data = data[STATIC_HEADER_LENGTH..].to_vec();
        if auth_data_size as usize > remaining_data.len() {
            return Err(PacketError::InvalidAuthDataSize);
        }

        let mut auth_data = data[IV_LENGTH + STATIC_HEADER_LENGTH
            ..IV_LENGTH + STATIC_HEADER_LENGTH + auth_data_size as usize]
            .to_vec();
        cipher.apply_keystream(&mut auth_data);

        let kind = PacketKind::decode(static_header[40], &auth_data)?;
        let src_id = NodeId::parse(&static_header[8..40]).expect("This is exactly 32 bytes");

        let header = PacketHeader { src_id, kind };

        // Any remaining bytes are message data
        let message = data[IV_LENGTH + STATIC_HEADER_LENGTH + auth_data_size as usize..].to_vec();

        if !message.is_empty() && header.kind.is_whoareyou() {
            // do not allow extra bytes being sent in WHOAREYOU messages
            return Err(PacketError::UnknownPacket);
        }

        Ok(Packet {
            iv: u128::from_be_bytes(iv[..].try_into().expect("IV_LENGTH must be 16 bytes")),
            header,
            message,
        })
    }

    /// Creates the masked header of a packet performing the required AES-CTR encryption.
    fn generate_header(&self, dst_id: &NodeId) -> Vec<u8> {
        let mut header_bytes = self.header.encode();

        /* Encryption is done inline
         *
         * This was split into its own library, but brought back to allow re-use of the cipher when
         * performing decryption
         */
        let mut key = GenericArray::clone_from_slice(&dst_id.raw()[..16]);
        let mut nonce = GenericArray::clone_from_slice(&self.iv.to_be_bytes());

        let mut cipher = Aes128Ctr::new(&key, &nonce);
        cipher.apply_keystream(&mut header_bytes);
        key.zeroize();
        nonce.zeroize();
        header_bytes
    }
}

impl std::fmt::Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Packet {{ iv: {}, header: {}, message {} }}",
            hex::encode(self.iv.to_be_bytes()),
            self.header.to_string(),
            hex::encode(&self.message)
        )
    }
}

impl std::fmt::Display for PacketHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PacketHeader {{ src_id: {}, kind: {} }}",
            hex::encode(self.src_id.raw()),
            self.kind.to_string()
        )
    }
}

impl std::fmt::Display for PacketKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketKind::Message(nonce) => write!(f, "Message ( {} )", hex::encode(nonce)),
            PacketKind::WhoAreYou {
                request_nonce,
                id_nonce,
                enr_seq,
            } => write!(
                f,
                "WhoAreYou {{ request_nonce: {} , id_nonce: {}, enr_seq: {} }}",
                hex::encode(request_nonce),
                hex::encode(id_nonce),
                enr_seq
            ),
            PacketKind::Handshake {
                message_nonce,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            } => write!(
                f,
                "Handshake {{ message_nonce: {}, id_nonce_sig: {}, ephem_pubkey: {}, enr_record {:?}",
                hex::encode(message_nonce),
                hex::encode(id_nonce_sig),
                hex::encode(ephem_pubkey),
                enr_record
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enr::{CombinedKey, EnrKey};
    use rand;

    fn init_log() {
        let _ = simple_logger::SimpleLogger::new()
            .with_level(log::LevelFilter::Debug)
            .init();
    }

    fn hex_decode(x: &'static str) -> Vec<u8> {
        hex::decode(x).unwrap()
    }

    fn node_key_1() -> CombinedKey {
        CombinedKey::secp256k1_from_bytes(&mut hex_decode(
            "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f",
        ))
        .unwrap()
    }

    fn node_key_2() -> CombinedKey {
        CombinedKey::secp256k1_from_bytes(&mut hex_decode(
            "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628",
        ))
        .unwrap()
    }

    #[test]
    fn packet_encode_random() {
        init_log();
        let node_id_a: NodeId = node_key_1().public().into();
        let node_id_b: NodeId = node_key_2().public().into();

        let expected_result = hex::decode("0000000000000000000000000000000b4f3ab1857252d94edf25b8bda34d42d8260ec07cfbb0b826e8067831b5af17ad5566dc48f0d48d73b9942b9bb5d5d5c9e08a3585038c4d010101010101010101010101").unwrap();
        let iv = 11u128;
        let header = PacketHeader {
            src_id: node_id_a,
            kind: PacketKind::Message([12u8; MESSAGE_NONCE_LENGTH]),
        };
        let message = [1u8; 12].to_vec();
        let packet = Packet {
            iv,
            header,
            message,
        };

        let encoded = packet.encode(&node_id_b);
        assert_eq!(expected_result, encoded);
    }

    #[test]
    fn packet_ref_test_encode_whoareyou() {
        init_log();
        // reference input
        let src_id: NodeId = node_key_1().public().into();
        let dst_id: NodeId = node_key_2().public().into();
        let request_nonce: MessageNonce = hex_decode("0102030405060708090a0b0c")[..]
            .try_into()
            .unwrap();
        let id_nonce: IdNonce =
            hex_decode("0102030405060708090a0b0c0d0e0f1000000000000000000000000000000000")[..]
                .try_into()
                .unwrap();
        let enr_seq = 0u64;
        let iv = 0u128;

        // expected hex output
        let expected_output = hex::decode("00000000000000000000000000000000088b3d4342776668980a4adf72a8fcaa963f24b27a2f6bb44c7ed5ca10e87de130f94d2390b9853c3ecb9ad5e368892ec562137bf19c6d0a9191a5651c4f415117bdfa0c7ab86af62b7a9784eceb28008d03ede83bd1369631f9f3d8da0b45").unwrap();

        let header = PacketHeader {
            src_id,
            kind: PacketKind::WhoAreYou {
                request_nonce,
                id_nonce,
                enr_seq,
            },
        };

        let packet = Packet {
            iv,
            header,
            message: Vec::new(),
        };

        assert_eq!(packet.encode(&dst_id), expected_output);
    }

    #[test]
    fn packet_encode_handshake() {
        init_log();
        // reference input
        let src_id = NodeId::parse(&vec![3; 32]).unwrap();
        let dst_id = NodeId::parse(&vec![4; 32]).unwrap();
        let message_nonce: MessageNonce = [52u8; MESSAGE_NONCE_LENGTH];
        let id_nonce_sig = vec![5u8; 64];
        let ephem_pubkey = vec![6u8; 33];
        let enr_record = None;
        let iv = 0u128;

        let expected_output = hex::decode("0000000000000000000000000000000035a14bcdb8448e04f25747c7493c12d052da4583e19f19d5fe5a8d438a4b5b518dfead9d80200875c33d42d29bed582c1d561390390af686d994770f24d8da18605ff3f5b60b090c61515093a88ef4c02186f7d1b5c9a88fdb8cfae239f13e451758751561b439d8044e27cecdf646f2aa1c9ecbd5faf37eb6794f6337f4b2a885391e631f72deb808c63bf0b0faed23d7117f7a2e1f98c28bd017").unwrap();

        let header = PacketHeader {
            src_id,
            kind: PacketKind::Handshake {
                message_nonce,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            },
        };

        let packet = Packet {
            iv,
            header,
            message: Vec::new(),
        };
        let encoded = packet.encode(&dst_id);
        assert_eq!(encoded, expected_output);
    }

    #[test]
    fn packet_encode_handshake_enr() {
        // reference input
        let node_key_1 = node_key_1();
        let src_id: NodeId = node_key_1.public().into();
        let dst_id = NodeId::parse(&vec![4; 32]).unwrap();
        let message_nonce: MessageNonce = [52u8; MESSAGE_NONCE_LENGTH];
        let id_nonce_sig = vec![5u8; 64];
        let ephem_pubkey = vec![6u8; 33];
        let enr_record = Some(
            enr::EnrBuilder::new("v4")
                .ip("127.0.0.1".parse().unwrap())
                .tcp(9000)
                .build(&node_key_1)
                .unwrap(),
        );
        let iv = 0u128;

        let expected_output = hex::decode("0000000000000000000000000000000035a14bcdb8448e045bfec0dda3cb8cd3d28f5dc8cae1ef446ec303591d35d45c767284d6d58594cdc33dc4d29bed582c1d561390390af686d994770f24d8da18605ff3f5b60b090c61515093a88ef4c02186f7d1b5c9a88fdb8cfae239f13e451758751561b439d8044e27cecdf646f2aa1c9ecbd5faf37eb6794f6337f4b2a885391e631f72deb808c63bf0b0faed23d7117f7a2e1f98c28bd01774f273648aacc15fec7016235dfb3ace8f8ffd6f63ea1958d5cbe6ca51c9ec78d8bf1b4f326b4dfd90fec9ea5a4aed319818bb4ec872986bd559d8b56cf4589d22e0fe1cbd6f63358ab38c7637d3e45a233ed56dadb635603abd38cfb1ad7ad358bda590c9544ee00782b475477e47f5e0b986988b76101b4da99b018e80c76c0d0de15cabfe").unwrap();

        let header = PacketHeader {
            src_id,
            kind: PacketKind::Handshake {
                message_nonce,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            },
        };

        let packet = Packet {
            iv,
            header,
            message: Vec::new(),
        };
        let encoded = packet.encode(&dst_id);
        // println!("{}", hex::encode(&encoded));
        assert_eq!(encoded, expected_output);
    }

    #[test]
    fn packet_ref_test_encode_message() {
        // reference input
        let src_id: NodeId = node_key_1().public().into();
        let dst_id: NodeId = node_key_2().public().into();
        let iv = 0u128;

        let message_nonce: MessageNonce = [52u8; MESSAGE_NONCE_LENGTH];
        let header = PacketHeader {
            src_id,
            kind: PacketKind::Message(message_nonce),
        };
        let ciphertext = vec![23; 12];

        let expected_output = hex::decode("00000000000000000000000000000000088b3d4342776668980a4adf72a8fcaa963f24b27a2f6bb44c7ed5ca10e87de130f94d2390b9853c3fcba2e0d55fb91ff7512f46cfa355171717171717171717171717").unwrap();

        let packet = Packet {
            iv,
            header,
            message: ciphertext,
        };
        let encoded = packet.encode(&dst_id);
        //println!("{}", hex::encode(&encoded));
        assert_eq!(encoded, expected_output);
    }

    /* This section provides functionality testing of the packets */
    #[test]
    fn packet_encode_decode_random() {
        let src_id: NodeId = node_key_1().public().into();
        let dst_id: NodeId = node_key_2().public().into();

        let packet = Packet::new_random(&src_id).unwrap();

        let encoded_packet = packet.clone().encode(&dst_id);
        let decoded_packet = Packet::decode(&dst_id, &encoded_packet).unwrap();

        assert_eq!(decoded_packet, packet);
    }

    #[test]
    fn packet_encode_decode_whoareyou() {
        let src_id: NodeId = node_key_1().public().into();
        let dst_id: NodeId = node_key_2().public().into();

        let message_nonce: MessageNonce = rand::random();
        let id_nonce: IdNonce = rand::random();
        let enr_seq: u64 = rand::random();

        let packet = Packet::new_whoareyou(src_id, message_nonce, id_nonce, enr_seq);

        let encoded_packet = packet.clone().encode(&dst_id);
        let decoded_packet = Packet::decode(&dst_id, &encoded_packet).unwrap();

        assert_eq!(decoded_packet, packet);
    }

    #[test]
    fn encode_decode_auth_packet() {
        let src_id: NodeId = node_key_1().public().into();
        let dst_id: NodeId = node_key_2().public().into();

        let message_nonce: MessageNonce = rand::random();
        let id_nonce_sig = vec![13; 64];
        let pubkey = vec![11; 33];
        let enr_record = None;

        let packet =
            Packet::new_authheader(src_id, message_nonce, id_nonce_sig, pubkey, enr_record);

        let encoded_packet = packet.clone().encode(&dst_id);
        let decoded_packet = Packet::decode(&dst_id, &encoded_packet).unwrap();

        assert_eq!(decoded_packet, packet);
    }

    #[test]
    fn packet_decode_ref_ping() {
        let src_id: NodeId = node_key_1().public().into();
        let dst_id: NodeId = node_key_2().public().into();
        let message_nonce: MessageNonce = hex_decode("ffffffffffffffffffffffff")[..]
            .try_into()
            .unwrap();
        let iv = 0u128;

        let header = PacketHeader {
            src_id,
            kind: PacketKind::Message(message_nonce),
        };
        let ciphertext = hex_decode("b84102ed931f66d180cbb4219f369a24f4e6b24d7bdc2a04");
        let expected_packet = Packet {
            iv,
            header,
            message: ciphertext,
        };

        let decoded_ref_packet = hex::decode("00000000000000000000000000000000088b3d4342776668980a4adf72a8fcaa963f24b27a2f6bb44c7ed5ca10e87de130f94d2390b9853c3fcba22b1e9472d43c9ae48d04689eb84102ed931f66d180cbb4219f369a24f4e6b24d7bdc2a04").unwrap();

        let packet = Packet::decode(&dst_id, &decoded_ref_packet).unwrap();
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn packet_decode_ref_ping_handshake() {
        let src_id: NodeId = node_key_1().public().into();
        let dst_id: NodeId = node_key_2().public().into();
        let message_nonce: MessageNonce = hex_decode("ffffffffffffffffffffffff")[..]
            .try_into()
            .unwrap();
        let id_nonce_sig = hex_decode("c14a44c1e56c122877e65606ad2ce92d1ad6e13e946d4ce0673b90e237bdd05c2181fc714c008686a08eb4df52faab7614a469576e9ab1363377a7de100aedc2");
        let ephem_pubkey = hex_decode("9a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a50f497889e4a9c74f48321875f8601ec65650fa0922fda04d69089b79af7f5533");
        let enr_record = None;
        let iv = 0u128;

        let header = PacketHeader {
            src_id,
            kind: PacketKind::Handshake {
                message_nonce,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            },
        };

        let message = hex_decode("7fccc3d4569a69fdf04f31230ae4be20404467d9ea9ab3cd");
        let expected_packet = Packet {
            iv,
            header,
            message,
        };

        let decoded_ref_packet = hex::decode("00000000000000000000000000000000088b3d4342776668980a4adf72a8fcaa963f24b27a2f6bb44c7ed5ca10e87de130f94d2390b9853c3dcb21d51e9472d43c9ae48d04689ef4d3d2602a5e89ac340f9e81e722b1d7dac2578d520dd5bc6dc1e38ad3ab33012be1a5d259267a0947bf242219834c5702d1c694c0ceb4a6a27b5d68bd2c2e32e6cb9696706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef52417d9c40a31564e8d5f31a7f08c38045ff5e30d9661838b1eabee9f1e561120bc7fccc3d4569a69fdf04f31230ae4be20404467d9ea9ab3cd").unwrap();

        let packet = Packet::decode(&dst_id, &decoded_ref_packet).unwrap();
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn packet_decode_ref_ping_handshake_enr() {
        let src_id: NodeId = node_key_1().public().into();
        let dst_id: NodeId = node_key_2().public().into();
        let message_nonce: MessageNonce = hex_decode("ffffffffffffffffffffffff")[..]
            .try_into()
            .unwrap();
        let id_nonce_sig = hex_decode("c14a44c1e56c122877e65606ad2ce92d1ad6e13e946d4ce0673b90e237bdd05c2181fc714c008686a08eb4df52faab7614a469576e9ab1363377a7de100aedc2");
        let ephem_pubkey = hex_decode("9a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a50f497889e4a9c74f48321875f8601ec65650fa0922fda04d69089b79af7f5533");
        let enr_record = Some("enr:-H24QBfhsHORjaMtZAZCx2LA4ngWmOSXH4qzmnd0atrYPwHnb_yHTFkkgIu-fFCJCILCuKASh6CwgxLR1ToX1Rf16ycBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMT0UIR4Ch7I2GhYViQqbUhIIBUbQoleuTP-Wz1NJksuQ".parse::<Enr>().unwrap());
        let iv = 0u128;

        let header = PacketHeader {
            src_id,
            kind: PacketKind::Handshake {
                message_nonce,
                id_nonce_sig,
                ephem_pubkey,
                enr_record,
            },
        };

        let message = hex_decode("7fccc3d4569a69fd8aca026be87afab8e8e645d1ee888992");
        let expected_packet = Packet {
            iv,
            header,
            message,
        };

        let decoded_ref_packet = hex::decode("00000000000000000000000000000000088b3d4342776668980a4adf72a8fcaa963f24b27a2f6bb44c7ed5ca10e87de130f94d2390b9853c3dcaa0d51e9472d43c9ae48d04689ef4d3d2602a5e89ac340f9e81e722b1d7dac2578d520dd5bc6dc1e38ad3ab33012be1a5d259267a0947bf242219834c5702d1c694c0ceb4a6a27b5d68bd2c2e32e6cb9696706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef52417d9c40a31564e8d5f31a7f08c38045ff5e30d9661838b1eabee9f1e561120bcc4d9f2f9c839152b4ab970e029b2395b97e8c3aa8d3b497ee98a15e865bcd34effa8b83eb6396bca60ad8f0bff1e047e278454bc2b3d6404c12106a9d0b6107fc2383976fc05fbda2c954d402c28c8fb53a2b3a4b111c286ba2ac4ff880168323c6e97b01dbcbeef4f234e5849f75ab007217c919820aaa1c8a7926d3625917fccc3d4569a69fd8aca026be87afab8e8e645d1ee888992").unwrap();

        let packet = Packet::decode(&dst_id, &decoded_ref_packet).unwrap();
        assert_eq!(packet, expected_packet);
    }
}
