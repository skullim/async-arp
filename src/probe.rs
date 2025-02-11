use crate::error::InputBuildError;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ProbeInput {
    pub sender_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default)]
pub struct ProbeInputBuilder {
    sender_mac: Option<MacAddr>,
    target_ip: Option<Ipv4Addr>,
}

impl ProbeInputBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_sender_mac(mut self, sender_mac: MacAddr) -> Self {
        self.sender_mac = Some(sender_mac);
        self
    }

    pub fn with_target_ip(mut self, target_ip: Ipv4Addr) -> Self {
        self.target_ip = Some(target_ip);
        self
    }

    pub fn build(&self) -> std::result::Result<ProbeInput, InputBuildError> {
        Ok(ProbeInput {
            target_ip: self.target_ip.ok_or(InputBuildError::MissingTargetIp)?,
            sender_mac: self.sender_mac.ok_or(InputBuildError::MissingSenderMac)?,
        })
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum ProbeStatus {
    Free,
    Occupied,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ProbeOutcome {
    pub status: ProbeStatus,
    pub target_ip: Ipv4Addr,
}

impl ProbeOutcome {
    pub fn new(status: ProbeStatus, target_ip: Ipv4Addr) -> Self {
        Self { status, target_ip }
    }
}
