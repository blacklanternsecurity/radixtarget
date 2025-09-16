// Node module - contains all the node types for radix trees

pub mod base;
pub mod ip;
pub mod dns;

// Re-export the main types for easy access
pub use base::BaseNode;
pub use ip::IPNode;
pub use dns::DnsNode;
pub use crate::utils::hash_u64;
