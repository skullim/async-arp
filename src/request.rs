use crate::error::{InputBuildError, ResponseTimeout};
use pnet::{packet::arp::Arp, util::MacAddr};
use std::net::Ipv4Addr;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct RequestInput {
    pub sender_ip: Ipv4Addr,
    pub sender_mac: MacAddr,
    pub target_ip: Ipv4Addr,
    pub target_mac: MacAddr,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct RequestInputBuilder {
    sender_ip: Option<Ipv4Addr>,
    sender_mac: Option<MacAddr>,
    target_ip: Option<Ipv4Addr>,
    target_mac: Option<MacAddr>,
}

impl RequestInputBuilder {
    pub fn new() -> Self {
        Self::default()
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

    pub fn build(&self) -> Result<RequestInput, InputBuildError> {
        Ok(RequestInput {
            target_mac: self.target_mac.ok_or(InputBuildError::MissingTargetMac)?,
            target_ip: self.target_ip.ok_or(InputBuildError::MissingTargetIp)?,
            sender_mac: self.sender_mac.ok_or(InputBuildError::MissingSenderMac)?,
            sender_ip: self.sender_ip.ok_or(InputBuildError::MissingSenderIp)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RequestOutcome {
    pub input: RequestInput,
    pub response_result: Result<Arp, ResponseTimeout>,
}

impl RequestOutcome {
    pub fn new(input: RequestInput, response_result: Result<Arp, ResponseTimeout>) -> Self {
        Self {
            input,
            response_result,
        }
    }
}
