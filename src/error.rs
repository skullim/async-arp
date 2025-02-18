use thiserror::Error as ThisError;

pub type OpaqueError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("{0}")]
    Opaque(#[from] OpaqueError),
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(ThisError, Debug, Clone, Copy)]
#[error("Response timeout")]
pub struct ResponseTimeout;

#[allow(clippy::enum_variant_names)]
#[derive(ThisError, Debug, Clone, Copy)]
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
