pub mod attachments;
pub mod cache;
pub mod document;
pub mod metrics;
pub mod resolver;
pub mod scanner;
pub mod worker;

pub fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}
