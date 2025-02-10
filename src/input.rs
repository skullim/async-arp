use std::net::Ipv4Addr;
use thiserror::Error as ThisError;

use pnet::util::MacAddr;

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

pub struct ArpRequestInput {
    pub sender_ip: Ipv4Addr,
    pub sender_mac: MacAddr,
    pub target_ip: Ipv4Addr,
    pub target_mac: MacAddr,
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
    pub sender_mac: MacAddr,
    pub target_ip: Ipv4Addr,
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
