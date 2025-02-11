use async_arp::{
    client::{Client, ClientConfigBuilder},
    probe::{ProbeInputBuilder, ProbeStatus},
};
use ipnet::Ipv4Net;
use pnet::datalink::{self};
use std::sync::Arc;
use std::{io::Write, net::IpAddr};

use clap::Parser;

/// Simple example to show ARP probing capabilities
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Network interface name to send and receive ARP messages
    #[arg(short, long)]
    iface: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == args.iface)
        .ok_or_else(|| format!("interface {} not found", args.iface))
        .unwrap();
    let net = interface
        .ips
        .iter()
        .filter(|net| net.is_ipv4())
        .take(1)
        .next()
        .unwrap();

    let net = if let IpAddr::V4(ipv4) = net.ip() {
        Some(Ipv4Net::new(ipv4, net.prefix()).unwrap())
    } else {
        None
    }
    .unwrap();

    let client = Arc::new(Client::new(ClientConfigBuilder::new(&args.iface).build()).unwrap());
    let future_probes: Vec<_> = net
        .hosts()
        .map(|target_ip| {
            let client_clone = client.clone();
            async move {
                let sender_mac = interface
                    .mac
                    .ok_or("interface does not have mac address")
                    .unwrap();
                let builder = ProbeInputBuilder::new()
                    .with_sender_mac(sender_mac)
                    .with_target_ip(target_ip);
                client_clone.probe(builder.build().unwrap()).await.unwrap()
            }
        })
        .collect();

    let outcomes = futures::future::join_all(future_probes).await;
    let occupied = outcomes
        .into_iter()
        .filter(|outcome| outcome.status == ProbeStatus::Occupied);

    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "Found hosts:").unwrap();
        for outcome in occupied {
            writeln!(stdout, "{:?}", outcome).unwrap();
        }
    }
}
