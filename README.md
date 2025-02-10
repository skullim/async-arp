# async-arp

`async-arp` is an asynchronous Rust crate that provides a high-level client for interacting with the Address Resolution Protocol (ARP). It can be used to probe the presence of hosts in a network or send advanced, custom ARP requests. This crate is ideal for network diagnostics, monitoring, or any application requiring interaction with ARP.

## Features
- **Async**: Uses the Tokio runtime for efficient asynchronous networking.
- **Host Probing**: Quickly probe for active devices in the network using ARP requests.
- **Advanced Requests**: Send custom ARP requests and interact with devices in more complex ways.
- **Unix-only**: This crate is designed for Unix-based systems (Linux, macOS, BSD).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
  at your option.