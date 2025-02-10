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
