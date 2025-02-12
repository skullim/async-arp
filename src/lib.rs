//! ## Example
//! Following example demonstrates probing all hosts in a given network range (e.g., an IPv4 subnet).
//! To run this example locally, make sure to specify the network interface (e.g., `eth0` or `wlan0`) as a parameter.
//! ```no_run
#![doc = include_str!("../examples/probe.rs")]
//! ```
//! In a similar fashion, more advanced ARP requests (e.g., for diagnostic purposes) can be sent using [`client::Client::request`].

mod client;
mod error;
mod probe;
mod request;

pub use client::{Client, ClientConfig, ClientConfigBuilder};
pub use error::{Error, InputBuildError, OpaqueError, Result};
pub use probe::{ProbeInput, ProbeInputBuilder, ProbeOutcome, ProbeStatus};
pub use request::{RequestInput, RequestInputBuilder, RequestOutcome};

pub(crate) mod caching;
pub(crate) mod constants;
pub(crate) mod notification;
pub(crate) mod response;
