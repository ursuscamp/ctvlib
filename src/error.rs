use bitcoin::script::PushBytesError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unknown error: {0}")]
    UnknownError(String),

    #[error("Missing sequence")]
    MissingSequence,

    #[error("{0}")]
    BitcoinStackItemSize(#[from] PushBytesError),

    #[error("{0}")]
    BitcoinAddress(#[from] bitcoin::address::Error),

    #[error("{0}")]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    TaprootBuilderError(#[from] bitcoin::taproot::TaprootBuilderError),
}
