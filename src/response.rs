use std::sync::Arc;

use afpacket::tokio::RawPacketStream;
use pnet::packet::arp::{Arp, ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::{FromPacket, Packet};
use tokio::io::AsyncReadExt;

use crate::caching::ArpCache;
use crate::constants::ETH_PACK_LEN;
use crate::error::{Error, Result};

pub(super) struct Listener {
    stream: RawPacketStream,
    cache: Arc<ArpCache>,
}

impl Listener {
    pub(super) fn new(stream: RawPacketStream, cache: Arc<ArpCache>) -> Self {
        Self { stream, cache }
    }

    pub(super) async fn listen(&mut self) -> Result<()> {
        let mut buf = [0; ETH_PACK_LEN];
        while let Ok(read_bytes) = self.stream.read(&mut buf).await {
            if let Ok(arp) = parse_arp_packet(&buf[..read_bytes]) {
                if arp.operation == ArpOperations::Reply {
                    self.cache.cache(arp).await;
                }
            }
        }
        Err(Error::Opaque(
            "error while reading the interface traffic".into(),
        ))
    }
}

pub(super) fn parse_arp_packet(bytes: &[u8]) -> Result<Arp> {
    let ethernet_packet =
        EthernetPacket::new(bytes).ok_or(Error::Opaque("failed to parse Ethernet frame".into()))?;
    if ethernet_packet.get_ethertype() == EtherTypes::Arp {
        Ok(ArpPacket::new(ethernet_packet.payload())
            .ok_or(Error::Opaque("failed to parse ARP packet".into()))?
            .from_packet())
    } else {
        Err(Error::Opaque("not an ARP packet".into()))
    }
}
