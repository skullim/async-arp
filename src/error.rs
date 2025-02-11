use thiserror::Error as ThisError;

pub type OpaqueError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Response timeout")]
    ResponseTimeout,
    #[error("{0}")]
    Opaque(#[from] OpaqueError),
}
pub type Result<T> = std::result::Result<T, Error>;

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
