mod ctv;
mod error;
/// Utility functions for generating segwit addresses and scripts.
pub mod segwit;
mod tmplhash;

pub use ctv::{Ctv, Output};
pub use error::Error;
pub use tmplhash::TemplateHash;
