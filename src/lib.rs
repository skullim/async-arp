//! ## Example: Probing Hosts in a Network Range with Retry Capabilities
//!
//! This example demonstrates probing all hosts in a given network range (e.g., an IPv4 subnet) with retry capabilities,
//! using [`ClientSpinner`] to batch the probes. This approach allows for retrying failed probes across the entire network range.
//! To run this example locally, make sure to specify the network interface (e.g., `eth0` or `wlan0`) as a parameter.
//!
//! ```ignore
//! use common;
#![doc = include_str!("../examples/probe-spinner.rs")]
//! ```
//!
//! ## Example 2: Using [`Client`] for Single Probe Requests
//!
//! When more granular control over the execution order is needed, or if only a single probe or request is desired,
//! you can use [`Client`] instead of [`ClientSpinner`]. This approach is useful for cases when you want to handle
//! each probe individually or when finer control is needed over how the futures are driven to completion.
//!
//! ```ignore
//! use common;
#![doc = include_str!("../examples/probe-client.rs")]
//! ```
//!
//! ## Advanced ARP Requests (Diagnostic Purposes)
//!
//! In a similar fashion, more advanced ARP requests (e.g., for diagnostic purposes) can be sent using either
//! [`ClientSpinner::request_batch`] or [`Client::request`]. The former allows for batching multiple ARP requests,
//! while the latter provides more control over individual requests. Both approaches enable sending specific ARP requests tailored
//! to your network diagnostic needs.
//!
mod client;
mod error;
mod probe;
mod request;

pub use client::{Client, ClientConfig, ClientConfigBuilder, ClientSpinner};
pub use error::{Error, InputBuildError, OpaqueError, Result};
pub use probe::{ProbeInput, ProbeInputBuilder, ProbeOutcome, ProbeStatus};
pub use request::{RequestInput, RequestInputBuilder, RequestOutcome};

pub(crate) mod caching;
pub(crate) mod constants;
pub(crate) mod notification;
pub(crate) mod response;
