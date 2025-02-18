use afpacket::tokio::RawPacketStream;
use pnet::{
    packet::{
        arp::{Arp, ArpHardwareTypes, ArpOperations, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
        Packet,
    },
    util::MacAddr,
};

use std::{future::Future, net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::task::JoinHandle;
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex, Notify},
};

use tokio_util::sync::CancellationToken;

use crate::{
    caching::ArpCache, error::ResponseTimeout, probe::ProbeInput, request::RequestOutcome,
};
use crate::{constants::IP_V4_LEN, notification::NotificationHandler};
use crate::{
    constants::{ARP_PACK_LEN, ETH_PACK_LEN, MAC_ADDR_LEN},
    request::RequestInput,
};
use crate::{
    error::{Error, Result},
    probe::ProbeOutcome,
};
use crate::{probe::ProbeStatus, response::Listener};

/// A struct responsible for performing batch requests and probes with retry logic.
///
/// This struct abstracts the client and provides methods to perform multiple
/// probes or requests with retry capabilities. The number of retries can be
/// configured during initialization.
#[derive(Debug)]
pub struct ClientSpinner {
    client: Client,
    n_retries: usize,
}

impl ClientSpinner {
    /// Creates a new instance of `ClientSpinner` with the given `Client`.
    ///
    /// This constructor initializes a `ClientSpinner` with a client and sets the
    /// number of retries to `0` (no retries).
    pub fn new(client: Client) -> Self {
        Self {
            client,
            n_retries: 0,
        }
    }

    /// Sets the number of retries for subsequent probes and requests.
    pub fn with_retries(mut self, n_retires: usize) -> Self {
        self.n_retries = n_retires;
        self
    }

    /// Performs a batch of probes asynchronously with retries.
    ///
    /// This method takes an array of `ProbeInput` and attempts to probe each one.
    /// If a probe fails, it will retry up to `n_retries` times before returning the
    /// results.
    pub async fn probe_batch(&self, inputs: &[ProbeInput]) -> Result<Vec<ProbeOutcome>> {
        let futures_producer = || {
            inputs
                .iter()
                .map(|input| async { self.client.probe(*input).await })
        };
        Self::handle_retries(self.n_retries, futures_producer).await
    }

    /// Performs a batch of requests asynchronously with retries.
    ///
    /// This method takes an array of `RequestInput` and attempts to request each one.
    /// If a request fails, it will retry up to `n_retries` times before returning the
    /// results.
    pub async fn request_batch(&self, inputs: &[RequestInput]) -> Result<Vec<RequestOutcome>> {
        let futures_producer = || {
            inputs
                .iter()
                .map(|input| async { self.client.request(*input).await })
        };
        Self::handle_retries(self.n_retries, futures_producer).await
    }

    async fn handle_retries<F, I, Fut, T>(n_retries: usize, futures_producer: F) -> Result<Vec<T>>
    where
        F: Fn() -> I,
        Fut: Future<Output = Result<T>>,
        I: Iterator<Item = Fut>,
    {
        for _ in 0..n_retries {
            futures::future::try_join_all(futures_producer()).await?;
        }
        futures::future::try_join_all(futures_producer()).await
    }
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub interface_name: String,
    pub response_timeout: Duration,
    pub cache_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct ClientConfigBuilder {
    interface_name: String,
    response_timeout: Option<Duration>,
    cache_timeout: Option<Duration>,
}

impl ClientConfigBuilder {
    pub fn new(interface_name: &str) -> Self {
        Self {
            interface_name: interface_name.into(),
            response_timeout: Some(Duration::from_secs(1)),
            cache_timeout: Some(Duration::from_secs(60)),
        }
    }

    pub fn with_response_timeout(mut self, timeout: Duration) -> Self {
        self.response_timeout = Some(timeout);
        self
    }

    pub fn with_cache_timeout(mut self, timeout: Duration) -> Self {
        self.cache_timeout = Some(timeout);
        self
    }

    pub fn build(self) -> ClientConfig {
        ClientConfig {
            interface_name: self.interface_name,
            cache_timeout: self.cache_timeout.unwrap(),
            response_timeout: self.response_timeout.unwrap(),
        }
    }
}

/// A client for handling ARP (Address Resolution Protocol) requests and probes.
///
/// The `Client` is responsible for sending ARP requests, caching responses,
/// and handling notifications. It uses a raw packet stream for network communication.
///
/// # Example
/// ```no_run
/// use async_arp::{Client, ClientConfig};
/// use std::time::Duration;
///
/// let config = ClientConfig {
///     interface_name: "eth0".to_string(),
///     response_timeout: Duration::from_secs(2),
///     cache_timeout: Duration::from_secs(60),
/// };
///
/// let client = Client::new(config).expect("Failed to create ARP client");
/// ```
#[derive(Debug)]
pub struct Client {
    response_timeout: Duration,
    stream: Mutex<RawPacketStream>,
    cache: Arc<ArpCache>,

    notification_handler: Arc<NotificationHandler>,
    _task_spawner: BackgroundTaskSpawner,
}

impl Client {
    /// Creates a new `Client` with the given configuration.
    ///
    /// This function initializes a raw packet stream, binds it to the specified
    /// network interface, and sets up caching and background tasks for listening
    /// to ARP responses.
    ///
    /// # Errors
    /// Returns an error if the packet stream cannot be created or if binding to
    /// the specified network interface fails.
    pub fn new(config: ClientConfig) -> Result<Self> {
        let mut stream = RawPacketStream::new().map_err(|err| {
            Error::Opaque(format!("failed to create packet stream, reason: {}", err).into())
        })?;
        stream.bind(&config.interface_name).map_err(|err| {
            Error::Opaque(format!("failed to bind interface to stream, reason {}", err).into())
        })?;

        let notification_handler = Arc::new(NotificationHandler::new());
        let cache = Arc::new(ArpCache::new(
            config.cache_timeout,
            Arc::clone(&notification_handler),
        ));

        let mut task_spawner = BackgroundTaskSpawner::new();
        task_spawner.spawn(Listener::new(stream.clone(), Arc::clone(&cache)));

        Ok(Self {
            response_timeout: config.response_timeout,
            stream: Mutex::new(stream),
            cache,
            notification_handler,
            _task_spawner: task_spawner,
        })
    }

    /// Probes for the presence of a device at the given IP address.
    ///
    /// This function sends an ARP request to determine whether an IP address
    /// is occupied. It returns a `ProbeOutcome`, indicating whether the address
    /// is in use.
    ///
    /// # Example
    /// ```no_run
    /// use async_arp::{Client, ClientConfigBuilder, ProbeStatus, ProbeInputBuilder};
    /// use pnet::util::MacAddr;
    /// use std::net::Ipv4Addr;
    ///
    /// let probe_input = ProbeInputBuilder::new()
    ///     .with_sender_mac(MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E))
    ///     .with_target_ip(Ipv4Addr::new(192, 168, 1, 1))
    ///     .build()
    ///     .expect("Failed to build probe input");
    /// tokio_test::block_on(async {
    ///     let client = Client::new(ClientConfigBuilder::new("eth0").build()).unwrap();
    ///     let outcome = client.probe(probe_input).await.unwrap();
    ///     match outcome.status {
    ///         ProbeStatus::Occupied => println!("IP is in use"),
    ///         ProbeStatus::Free => println!("IP is available"),
    /// }
    /// })
    /// ```
    ///
    /// # Errors
    /// Returns an error if sending the ARP request fails.
    pub async fn probe(&self, input: ProbeInput) -> Result<ProbeOutcome> {
        let input = RequestInput {
            sender_ip: Ipv4Addr::UNSPECIFIED,
            sender_mac: input.sender_mac,
            target_ip: input.target_ip,
            target_mac: MacAddr::zero(),
        };

        match self.request(input).await {
            Ok(response) => {
                let status = match response.response_result {
                    Ok(_) => ProbeStatus::Occupied,
                    Err(_) => ProbeStatus::Free,
                };
                Ok(ProbeOutcome::new(status, input.target_ip))
            }
            Err(err) => Err(err),
        }
    }

    /// Sends an ARP request and waits for a response.
    ///
    /// If the requested IP is already cached, the cached response is returned immediately.
    /// Otherwise, a new ARP request is sent, and the client waits for a response within
    /// the configured timeout period.
    ///
    /// # Example
    /// ```no_run
    /// use pnet::util::MacAddr;
    /// use std::net::Ipv4Addr;
    /// use async_arp::{Client, ClientConfigBuilder, RequestInputBuilder};
    ///
    /// let request_input = RequestInputBuilder::new()
    ///     .with_sender_ip(Ipv4Addr::new(192, 168, 1, 100))
    ///     .with_sender_mac(MacAddr::new(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E))
    ///     .with_target_ip(Ipv4Addr::new(192, 168, 1, 1))
    ///     .with_target_mac(MacAddr::zero())
    ///     .build()
    ///     .expect("Failed to build request input");
    /// tokio_test::block_on(async {
    ///     let client = Client::new(ClientConfigBuilder::new("eth0").build()).unwrap();
    ///     let outcome = client.request(request_input).await.unwrap();
    ///
    ///     println!("Received response: {:?}", outcome);
    /// })
    /// ```
    ///
    /// # Errors
    /// Returns an error if sending the request fails or if no response is received
    /// within the timeout period.
    pub async fn request(&self, input: RequestInput) -> Result<RequestOutcome> {
        if let Some(cached) = self.cache.get(&input.target_ip) {
            return Ok(RequestOutcome::new(input, Ok(cached)));
        }
        let mut eth_buf = [0; ETH_PACK_LEN];
        Self::fill_packet_buf(&mut eth_buf, &input);
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

        let response_result = tokio::time::timeout(
            self.response_timeout,
            self.await_response(notifier, &input.target_ip),
        )
        .await
        .map_err(|_| ResponseTimeout {});
        Ok(RequestOutcome::new(input, response_result))
    }

    fn fill_packet_buf(eth_buf: &mut [u8], input: &RequestInput) {
        let mut eth_packet = MutableEthernetPacket::new(eth_buf).unwrap();
        eth_packet.set_destination(MacAddr::broadcast());
        eth_packet.set_source(input.sender_mac);
        eth_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buf = [0; ARP_PACK_LEN];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buf).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(MAC_ADDR_LEN);
        arp_packet.set_proto_addr_len(IP_V4_LEN);
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

#[derive(Debug)]
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

    fn spawn(&mut self, mut listener: Listener) {
        let token = self.token.clone();
        let handle = tokio::task::spawn(async move {
            tokio::select! {
                _ = listener.listen() => {

                },
                _ = token.cancelled() => {
                }
            }
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

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::Arc};

    use crate::{
        client::{Client, ClientConfigBuilder, ProbeStatus},
        constants::{ARP_PACK_LEN, ETH_PACK_LEN, IP_V4_LEN, MAC_ADDR_LEN},
        probe::ProbeInputBuilder,
        response::parse_arp_packet,
        ClientSpinner,
    };
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
                .ok_or_else(|| format!("interface {} not found", interface_name))?;
            let mut stream = RawPacketStream::new()?;
            stream.bind(interface_name)?;
            Ok(Self {
                mac: interface.mac.unwrap(),
                stream,
                net,
            })
        }

        async fn serve(&mut self) -> Result<()> {
            let mut request_buf = [0; ETH_PACK_LEN];
            let mut arp_buf = [0; ARP_PACK_LEN];
            let mut response_buf = [0; ETH_PACK_LEN];
            while let Ok(read_bytes) = self.stream.read(&mut request_buf).await {
                if let Ok(request) = parse_arp_packet(&request_buf[..read_bytes]) {
                    if self.net.contains(&request.target_proto_addr) {
                        let mut arp_response = MutableArpPacket::new(&mut arp_buf).unwrap();
                        arp_response.set_hardware_type(ArpHardwareTypes::Ethernet);
                        arp_response.set_protocol_type(EtherTypes::Ipv4);
                        arp_response.set_hw_addr_len(MAC_ADDR_LEN);
                        arp_response.set_proto_addr_len(IP_V4_LEN);
                        arp_response.set_operation(ArpOperations::Reply);

                        arp_response.set_sender_proto_addr(request.target_proto_addr);
                        arp_response.set_sender_hw_addr(self.mac);
                        arp_response.set_target_proto_addr(request.sender_proto_addr);
                        arp_response.set_target_hw_addr(request.sender_hw_addr);

                        let mut eth_response = MutableEthernetPacket::new(&mut response_buf)
                            .ok_or("failed to create Ethernet frame")?;
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

    #[tokio::test]
    async fn test_spinner_down_interface() {
        const INTERFACE_NAME: &str = "down_dummy";
        let client = Client::new(ClientConfigBuilder::new(INTERFACE_NAME).build()).unwrap();
        let spinner = ClientSpinner::new(client);
        let result = spinner
            .probe_batch(&[ProbeInputBuilder::new()
                .with_sender_mac(MacAddr::broadcast())
                .with_target_ip(Ipv4Addr::new(10, 1, 1, 1))
                .build()
                .unwrap()])
            .await;
        assert!(result.is_err())
    }

    // Even though no async functions called directly, tokio runtime must be running to rely on AsyncFd (which is used by dependency)
    #[tokio::test]
    async fn test_invalid_interface() {
        const INTERFACE_NAME: &str = "invalid_dummy";
        assert!(Client::new(ClientConfigBuilder::new(INTERFACE_NAME).build()).is_err());
    }

    #[tokio::test]
    async fn test_client_detection() {
        const INTERFACE_NAME: &str = "dummy0";
        tokio::spawn(async move {
            let net = Ipv4Net::new(Ipv4Addr::new(10, 1, 1, 0), 25).unwrap();
            let mut server = Server::new(INTERFACE_NAME, net).unwrap();
            server.serve().await.unwrap();
        });
        {
            let client =
                Arc::new(Client::new(ClientConfigBuilder::new(INTERFACE_NAME).build()).unwrap());

            let sender_mac = datalink::interfaces()
                .into_iter()
                .find(|iface| iface.name == INTERFACE_NAME)
                .ok_or_else(|| format!("interface {} not found", INTERFACE_NAME))
                .unwrap()
                .mac
                .ok_or("interface does not have mac address")
                .unwrap();

            let future_probes: Vec<_> = (0..128)
                .map(|ip_d| {
                    let client_clone = client.clone();
                    async move {
                        let builder = ProbeInputBuilder::new()
                            .with_sender_mac(sender_mac)
                            .with_target_ip(Ipv4Addr::new(10, 1, 1, ip_d as u8));
                        client_clone.probe(builder.build().unwrap()).await.unwrap()
                    }
                })
                .collect();

            let outcomes = futures::future::join_all(future_probes).await;
            for outcome in outcomes {
                assert_eq!(outcome.status, ProbeStatus::Occupied);
            }

            let future_probes: Vec<_> = (128..=255)
                .map(|ip_d| {
                    let client_clone = client.clone();
                    async move {
                        let builder = ProbeInputBuilder::new()
                            .with_sender_mac(sender_mac)
                            .with_target_ip(Ipv4Addr::new(10, 1, 1, ip_d as u8));
                        client_clone.probe(builder.build().unwrap()).await.unwrap()
                    }
                })
                .collect();

            let outcomes = futures::future::join_all(future_probes).await;
            for outcome in outcomes {
                assert_eq!(outcome.status, ProbeStatus::Free);
            }
        }
    }
}
