//! Ethernet Layer (Layer 2)
//!
//! This module handles Ethernet frame parsing, building, and
//! EtherType demultiplexing.

use crate::net::skb::SkBuff;

/// Ethernet address length
pub const ETH_ALEN: usize = 6;

/// Ethernet header length
pub const ETH_HLEN: usize = 14;

/// Minimum Ethernet frame size (without FCS)
pub const ETH_ZLEN: usize = 60;

/// Maximum Ethernet payload (standard MTU)
pub const ETH_DATA_LEN: usize = 1500;

/// Maximum Ethernet frame size (without FCS)
pub const ETH_FRAME_LEN: usize = 1514;

/// Broadcast MAC address
pub const ETH_BROADCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

/// EtherType values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    /// IPv4 (0x0800)
    Ipv4,
    /// ARP (0x0806)
    Arp,
    /// IPv6 (0x86DD)
    Ipv6,
    /// VLAN tagged (0x8100)
    Vlan,
    /// Unknown protocol
    Unknown(u16),
}

impl EtherType {
    /// Convert from network byte order u16
    pub fn from_be(value: u16) -> Self {
        match value {
            0x0800 => EtherType::Ipv4,
            0x0806 => EtherType::Arp,
            0x86DD => EtherType::Ipv6,
            0x8100 => EtherType::Vlan,
            v => EtherType::Unknown(v),
        }
    }

    /// Convert to network byte order u16
    pub fn to_be(self) -> u16 {
        match self {
            EtherType::Ipv4 => 0x0800,
            EtherType::Arp => 0x0806,
            EtherType::Ipv6 => 0x86DD,
            EtherType::Vlan => 0x8100,
            EtherType::Unknown(v) => v,
        }
    }
}

impl Default for EtherType {
    fn default() -> Self {
        EtherType::Unknown(0)
    }
}

/// Ethernet header structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    /// Destination MAC address
    pub h_dest: [u8; ETH_ALEN],
    /// Source MAC address
    pub h_source: [u8; ETH_ALEN],
    /// Protocol type (big-endian)
    pub h_proto: [u8; 2],
}

impl EthHdr {
    /// Get the EtherType
    pub fn protocol(&self) -> EtherType {
        let proto = u16::from_be_bytes(self.h_proto);
        EtherType::from_be(proto)
    }

    /// Set the EtherType
    pub fn set_protocol(&mut self, proto: EtherType) {
        self.h_proto = proto.to_be().to_be_bytes();
    }

    /// Check if destination is broadcast
    pub fn is_broadcast(&self) -> bool {
        self.h_dest == ETH_BROADCAST
    }

    /// Check if destination is multicast
    pub fn is_multicast(&self) -> bool {
        self.h_dest[0] & 0x01 != 0
    }
}

/// Determine protocol type and strip Ethernet header
///
/// This is called by drivers after receiving a packet. It:
/// 1. Parses the Ethernet header
/// 2. Sets skb.protocol
/// 3. Advances data pointer past Ethernet header
///
/// Returns the EtherType for dispatch.
pub fn eth_type_trans(skb: &SkBuff) -> EtherType {
    if skb.len() < ETH_HLEN {
        return EtherType::Unknown(0);
    }

    // Parse Ethernet header
    let data = skb.data();
    let proto_bytes = [data[12], data[13]];
    let proto = u16::from_be_bytes(proto_bytes);

    EtherType::from_be(proto)
}

/// Build an Ethernet header
///
/// Prepends an Ethernet header to the skb.
pub fn eth_header(
    skb: &mut SkBuff,
    dest: &[u8; ETH_ALEN],
    source: &[u8; ETH_ALEN],
    proto: EtherType,
) -> Option<()> {
    let hdr = skb.push(ETH_HLEN)?;

    // Destination MAC
    hdr[0..6].copy_from_slice(dest);
    // Source MAC
    hdr[6..12].copy_from_slice(source);
    // EtherType
    let proto_bytes = proto.to_be().to_be_bytes();
    hdr[12..14].copy_from_slice(&proto_bytes);

    Some(())
}

/// Parse Ethernet header from skb
///
/// Returns header reference and advances data pointer.
pub fn eth_hdr(skb: &SkBuff) -> Option<&EthHdr> {
    if skb.len() < ETH_HLEN {
        return None;
    }

    let data = skb.data();
    // Safety: we verified length and EthHdr is packed
    let hdr = unsafe { &*(data.as_ptr() as *const EthHdr) };
    Some(hdr)
}

/// Format a MAC address as string
pub fn format_mac(mac: &[u8; 6]) -> [u8; 17] {
    let hex = b"0123456789abcdef";
    let mut buf = [0u8; 17];

    for (i, &byte) in mac.iter().enumerate() {
        let pos = i * 3;
        buf[pos] = hex[(byte >> 4) as usize];
        buf[pos + 1] = hex[(byte & 0x0f) as usize];
        if i < 5 {
            buf[pos + 2] = b':';
        }
    }

    buf
}
