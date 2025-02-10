use afpacket::tokio::RawPacketStream;
use log::debug;
use pnet::packet::FromPacket;
use pnet::{
    packet::{
        arp::{Arp, ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        Packet,
    },
    util::MacAddr,
};
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::Duration};
use thiserror::Error as ThisError;
use timedmap::TimedMap;
use tokio::task::JoinHandle;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, Notify},
};

use tokio_util::sync::CancellationToken;

pub type OpaqueError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Response timeout")]
    ResponseTimeout,
    #[error("{0}")]
    Opaque(#[from] OpaqueError),
}
pub type Result<T> = std::result::Result<T, Error>;

struct ArpConstants;
impl ArpConstants {
    const PACK_LEN: usize = 28;
    const AS_ETH_PACK_LEN: usize = 42;
    const MAC_ADDR_LEN: u8 = 6;
    const IP_V4_LEN: u8 = 4;
}

#[allow(clippy::enum_variant_names)]
#[derive(ThisError, Debug)]
#[non_exhaustive]
pub enum InputBuildError {
    #[error("sender MAC address is required")]
    MissingSenderMac,
    #[error("sender IP address is required")]
    MissingSenderIp,
    #[error("target MAC address is required")]
    MissingTargetMac,
    #[error("target IP address is required")]
    MissingTargetIp,
}

#[derive(Debug, PartialEq)]
pub enum ProbeOutcome {
    Free,
    Occupied,
}

pub struct ArpRequestInput {
    sender_ip: Ipv4Addr,
    sender_mac: MacAddr,
    target_ip: Ipv4Addr,
    target_mac: MacAddr,
}

pub struct ArpRequestInputBuilder {
    sender_ip: Option<Ipv4Addr>,
    sender_mac: Option<MacAddr>,
    target_ip: Option<Ipv4Addr>,
    target_mac: Option<MacAddr>,
}

impl Default for ArpRequestInputBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpRequestInputBuilder {
    pub fn new() -> Self {
        Self {
            sender_ip: None,
            sender_mac: None,
            target_ip: None,
            target_mac: None,
        }
    }

    pub fn with_sender_mac(mut self, sender_mac: MacAddr) -> Self {
        self.sender_mac = Some(sender_mac);
        self
    }

    pub fn with_sender_ip(mut self, sender_ip: Ipv4Addr) -> Self {
        self.sender_ip = Some(sender_ip);
        self
    }

    pub fn with_target_mac(mut self, target_mac: MacAddr) -> Self {
        self.target_mac = Some(target_mac);
        self
    }

    pub fn with_target_ip(mut self, target_ip: Ipv4Addr) -> Self {
        self.target_ip = Some(target_ip);
        self
    }

    pub fn build(&self) -> std::result::Result<ArpRequestInput, InputBuildError> {
        Ok(ArpRequestInput {
            target_mac: self.target_mac.ok_or(InputBuildError::MissingTargetMac)?,
            target_ip: self.target_ip.ok_or(InputBuildError::MissingTargetIp)?,
            sender_mac: self.sender_mac.ok_or(InputBuildError::MissingSenderMac)?,
            sender_ip: self.sender_ip.ok_or(InputBuildError::MissingSenderIp)?,
        })
    }
}

pub struct ArpProbeInput {
    sender_mac: MacAddr,
    target_ip: Ipv4Addr,
}

pub struct ArpProbeInputBuilder {
    sender_mac: Option<MacAddr>,
    target_ip: Option<Ipv4Addr>,
}

impl Default for ArpProbeInputBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpProbeInputBuilder {
    pub fn new() -> Self {
        Self {
            target_ip: None,
            sender_mac: None,
        }
    }

    pub fn with_sender_mac(mut self, sender_mac: MacAddr) -> Self {
        self.sender_mac = Some(sender_mac);
        self
    }

    pub fn with_target_ip(mut self, target_ip: Ipv4Addr) -> Self {
        self.target_ip = Some(target_ip);
        self
    }

    pub fn build(&self) -> std::result::Result<ArpProbeInput, InputBuildError> {
        Ok(ArpProbeInput {
            target_ip: self.target_ip.ok_or(InputBuildError::MissingTargetIp)?,
            sender_mac: self.sender_mac.ok_or(InputBuildError::MissingSenderMac)?,
        })
    }
}

//@todo: Check if Streams can be reused in both client and listener
pub struct Client {
    response_timeout: Duration,
    stream: Mutex<RawPacketStream>,
    cache: Arc<ArpCache>,
    notification_handler: Arc<NotificationHandler>,
    _task_spawner: BackgroundTaskSpawner,
}

impl Client {
    pub fn new(
        interface_name: &str,
        response_timeout: Duration,
        cache_timeout: Duration,
    ) -> Result<Self> {
        let mut stream = RawPacketStream::new().map_err(|err| {
            Error::Opaque(format!("failed to create packet stream, reason: {}", err).into())
        })?;
        stream.bind(interface_name).map_err(|err| {
            Error::Opaque(format!("failed to bind interface to stream, reason {}", err).into())
        })?;

        let notification_handler = Arc::new(NotificationHandler::new());
        let cache = Arc::new(ArpCache::new(
            cache_timeout,
            Arc::clone(&notification_handler),
        ));

        let mut task_spawner = BackgroundTaskSpawner::new();
        task_spawner.spawn(ResponseListener::new(interface_name, Arc::clone(&cache))?);

        Ok(Self {
            response_timeout,
            stream: Mutex::new(stream),
            cache,
            notification_handler,
            _task_spawner: task_spawner,
        })
    }

    pub async fn probe(&self, input: &ArpProbeInput) -> Result<ProbeOutcome> {
        let input = ArpRequestInput {
            sender_ip: Ipv4Addr::UNSPECIFIED,
            sender_mac: input.sender_mac,
            target_ip: input.target_ip,
            target_mac: MacAddr::zero(),
        };

        match self.request(&input).await {
            Ok(_) => Ok(ProbeOutcome::Occupied),
            Err(Error::ResponseTimeout) => Ok(ProbeOutcome::Free),
            Err(err) => Err(err),
        }
    }

    pub async fn request(&self, input: &ArpRequestInput) -> Result<Arp> {
        if let Some(cached) = self.cache.get(&input.target_ip) {
            return Ok(cached);
        }
        let mut eth_buf = [0; ArpConstants::AS_ETH_PACK_LEN];
        Self::fill_packet_buf(&mut eth_buf, input);
        let notifier = self
            .notification_handler
            .register_notifier(input.target_ip)
            .await;
        self.stream
            .lock()
            .await
            .write_all(&eth_buf)
            .await
            .map_err(|err| {
                Error::Opaque(format!("failed to send request, reason: {}", err).into())
            })?;

        let response = tokio::time::timeout(
            self.response_timeout,
            self.await_response(notifier, &input.target_ip),
        )
        .await
        .map_err(|_| Error::ResponseTimeout)?;
        Ok(response)
    }

    fn fill_packet_buf(eth_buf: &mut [u8], input: &ArpRequestInput) {
        let mut eth_packet = MutableEthernetPacket::new(eth_buf).unwrap();
        eth_packet.set_destination(MacAddr::broadcast());
        eth_packet.set_source(input.sender_mac);
        eth_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buf = [0; ArpConstants::PACK_LEN];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buf).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(ArpConstants::MAC_ADDR_LEN);
        arp_packet.set_proto_addr_len(ArpConstants::IP_V4_LEN);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(input.sender_mac);
        arp_packet.set_sender_proto_addr(input.sender_ip);
        arp_packet.set_target_hw_addr(input.target_mac);
        arp_packet.set_target_proto_addr(input.target_ip);

        eth_packet.set_payload(arp_packet.packet());
    }

    async fn await_response(&self, notifier: Arc<Notify>, target_ip: &Ipv4Addr) -> Arp {
        loop {
            notifier.notified().await;
            {
                if let Some(packet) = self.cache.get(target_ip) {
                    return packet;
                }
            }
        }
    }
}

struct BackgroundTaskSpawner {
    token: CancellationToken,
    handle: Option<JoinHandle<()>>,
}

impl BackgroundTaskSpawner {
    fn new() -> Self {
        Self {
            token: CancellationToken::new(),
            handle: None,
        }
    }

    fn spawn(&mut self, mut listener: ResponseListener) {
        let token = self.token.clone();
        let handle = tokio::task::spawn(async move {
            debug!("starting background task");
            tokio::select! {
                _ = listener.listen() => {

                },
                _ = token.cancelled() => {
                    debug!("Background task has been cancellation");
                }
            }
            debug!("Finished background task")
        });
        self.handle = Some(handle);
    }
}

impl Drop for BackgroundTaskSpawner {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.token.cancel();
        }
    }
}

struct ArpCache {
    timeout: Duration,
    responses: TimedMap<Ipv4Addr, Arp>,
    notification_handler: Arc<NotificationHandler>,
}

impl ArpCache {
    fn new(timeout: Duration, notification_handler: Arc<NotificationHandler>) -> Self {
        Self {
            timeout,
            responses: TimedMap::new(),
            notification_handler,
        }
    }

    async fn cache(&self, response: Arp) {
        let ip = response.sender_proto_addr;
        self.responses.insert(ip, response, self.timeout);
        self.notification_handler.notify(&ip).await;
    }

    fn get(&self, ip: &Ipv4Addr) -> Option<Arp> {
        self.responses.get(ip)
    }
}

struct NotificationHandler {
    notifiers: Mutex<HashMap<Ipv4Addr, Arc<Notify>>>,
}

impl NotificationHandler {
    fn new() -> Self {
        Self {
            notifiers: Mutex::new(HashMap::new()),
        }
    }

    async fn register_notifier(&self, src_ip: Ipv4Addr) -> Arc<Notify> {
        let mut notifiers = self.notifiers.lock().await;
        let notifier = Arc::new(Notify::new());
        notifiers.insert(src_ip, notifier.clone());
        notifier
    }

    async fn notify(&self, ip: &Ipv4Addr) {
        if let Some(notifier) = self.notifiers.lock().await.remove(ip) {
            notifier.notify_one();
        }
    }
}

struct ResponseListener {
    stream: RawPacketStream,
    cache: Arc<ArpCache>,
}

impl ResponseListener {
    fn new(interface_name: &str, cache: Arc<ArpCache>) -> Result<Self> {
        let mut stream = RawPacketStream::new().map_err(|err| {
            Error::Opaque(format!("failed to create packet stream, reason: {}", err).into())
        })?;
        stream.bind(interface_name).map_err(|err| {
            Error::Opaque(format!("failed to bind interface to stream, reason {}", err).into())
        })?;

        Ok(Self { stream, cache })
    }

    async fn listen(&mut self) -> Result<()> {
        let mut buf = [0; ArpConstants::AS_ETH_PACK_LEN];
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

fn parse_arp_packet(bytes: &[u8]) -> Result<Arp> {
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

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        path::PathBuf,
        process::Command,
        sync::{Arc, Once},
        time::Duration,
    };

    use crate::arp::{parse_arp_packet, ArpProbeInputBuilder, Client, ProbeOutcome};
    use afpacket::tokio::RawPacketStream;
    use ipnet::Ipv4Net;
    use pnet::{
        datalink,
        packet::{
            arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket},
            ethernet::{EtherTypes, MutableEthernetPacket},
            Packet,
        },
        util::MacAddr,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::ArpConstants;

    type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
    type Result<T> = std::result::Result<T, Error>;

    struct Server {
        mac: MacAddr,
        stream: RawPacketStream,
        net: Ipv4Net,
    }

    impl Server {
        fn new(interface_name: &str, net: Ipv4Net) -> Result<Self> {
            let interfaces = datalink::interfaces();
            let interface = interfaces
                .into_iter()
                .find(|iface| iface.name == interface_name)
                .ok_or_else(|| format!("Interface {} not found", interface_name))?;
            let mut stream = RawPacketStream::new()?;
            stream.bind(interface_name)?;
            Ok(Self {
                mac: interface.mac.unwrap(),
                stream,
                net,
            })
        }

        async fn serve(&mut self) -> Result<()> {
            let mut request_buf = [0; ArpConstants::AS_ETH_PACK_LEN];
            let mut arp_buf = [0; ArpConstants::PACK_LEN];
            let mut response_buf = [0; ArpConstants::AS_ETH_PACK_LEN];
            while let Ok(read_bytes) = self.stream.read(&mut request_buf).await {
                if let Ok(request) = parse_arp_packet(&request_buf[..read_bytes]) {
                    if self.net.contains(&request.target_proto_addr) {
                        let mut arp_response = MutableArpPacket::new(&mut arp_buf).unwrap();
                        arp_response.set_hardware_type(ArpHardwareTypes::Ethernet);
                        arp_response.set_protocol_type(EtherTypes::Ipv4);
                        arp_response.set_hw_addr_len(ArpConstants::MAC_ADDR_LEN);
                        arp_response.set_proto_addr_len(ArpConstants::IP_V4_LEN);
                        arp_response.set_operation(ArpOperations::Reply);

                        arp_response.set_sender_proto_addr(request.target_proto_addr);
                        arp_response.set_sender_hw_addr(self.mac);
                        arp_response.set_target_proto_addr(request.sender_proto_addr);
                        arp_response.set_target_hw_addr(request.sender_hw_addr);

                        let mut eth_response = MutableEthernetPacket::new(&mut response_buf)
                            .ok_or("failed to parse Ethernet frame")?;
                        eth_response.set_ethertype(EtherTypes::Arp);
                        eth_response.set_destination(request.sender_hw_addr);
                        eth_response.set_source(self.mac);
                        eth_response.set_payload(arp_response.packet());

                        self.stream.write_all(eth_response.packet()).await?;
                    }
                }
            }
            Ok(())
        }
    }

    static INIT: Once = Once::new();

    fn init_dummy_interface() {
        const SCRIPT_PATH: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/setup_dummy_interface.sh"
        );
        Command::new("sudo")
            .arg(SCRIPT_PATH)
            .status()
            .expect("Failed to setup dummy test interface");
    }

    fn set_cap_net_raw_capabilities(test_binary: PathBuf) {
        Command::new("sudo")
            .arg("setcap")
            .arg("cap_net_raw=eip")
            .arg(test_binary)
            .status()
            .expect("Failed to set net raw capabilities");
    }

    #[tokio::test]
    async fn test_detection() {
        INIT.call_once(init_dummy_interface);
        // not ideal, capabilities are not affected during first test run
        let test_bin_path = std::env::current_exe().expect("Failed to get test executable");
        set_cap_net_raw_capabilities(test_bin_path);

        let interface_name = "dummy0";

        tokio::spawn(async move {
            let net = Ipv4Net::new(Ipv4Addr::new(10, 1, 1, 0), 25).unwrap();
            let mut server = Server::new(interface_name, net).unwrap();
            server.serve().await.unwrap();
        });
        {
            let client = Arc::new(
                Client::new(
                    interface_name,
                    Duration::from_secs(1),
                    Duration::from_secs(60),
                )
                .unwrap(),
            );

            let source_mac = datalink::interfaces()
                .into_iter()
                .find(|iface| iface.name == interface_name)
                .ok_or_else(|| format!("Interface {} not found", interface_name))
                .unwrap()
                .mac
                .ok_or("interface does not have mac address")
                .unwrap();

            let futures: Vec<_> = (0..128)
                .map(|ip_d| {
                    let client_clone = client.clone();
                    async move {
                        let builder = ArpProbeInputBuilder::new()
                            .with_sender_mac(source_mac)
                            .with_target_ip(Ipv4Addr::new(10, 1, 1, ip_d as u8));
                        client_clone.probe(&builder.build().unwrap()).await.unwrap()
                    }
                })
                .collect();

            let results = futures::future::join_all(futures).await;
            for detection_state in results {
                assert_eq!(detection_state, ProbeOutcome::Occupied);
            }

            let futures: Vec<_> = (128..=255)
                .map(|ip_d| {
                    let client_clone = client.clone();
                    async move {
                        let builder = ArpProbeInputBuilder::new()
                            .with_sender_mac(source_mac)
                            .with_target_ip(Ipv4Addr::new(10, 1, 1, ip_d as u8));
                        client_clone.probe(&builder.build().unwrap()).await.unwrap()
                    }
                })
                .collect();

            let results = futures::future::join_all(futures).await;
            for detection_state in results {
                assert_eq!(detection_state, ProbeOutcome::Free);
            }
        }
    }
}
