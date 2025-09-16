// Node module - contains all the node types for radix trees

pub mod base;
pub mod dns;
pub mod ip;

// Re-export the main types for easy access
pub use crate::utils::hash_u64;
pub use base::BaseNode;
pub use dns::DnsNode;
pub use ip::IPNode;
