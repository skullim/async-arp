use async_arp::{Client, ClientConfigBuilder, ProbeStatus};
use clap::Parser;
use std::io::Write;
use std::time::{Duration, Instant};

mod common;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = common::Args::parse();
    let interface = common::interface_from(&args.iface);
    let net = common::net_from(&interface).unwrap();

    let client = Client::new(
        ClientConfigBuilder::new(&args.iface)
            .with_response_timeout(Duration::from_millis(500))
            .build(),
    )
    .unwrap();
    let inputs = common::generate_probe_inputs(net, interface);

    let start = Instant::now();
    let futures = inputs.into_iter().map(|input| client.probe(input));
    let outcomes = futures::future::join_all(futures).await;
    let scan_duration = start.elapsed();

    let occupied = outcomes
        .into_iter()
        .filter_map(|outcome| outcome.ok())
        .filter(|outcome| outcome.status == ProbeStatus::Occupied);

    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "Found hosts:").unwrap();
        for outcome in occupied {
            writeln!(stdout, "{:?}", outcome).unwrap();
        }
        writeln!(stdout, "Scan took {:?}", scan_duration).unwrap();
    }
}
