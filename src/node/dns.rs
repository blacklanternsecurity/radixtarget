use super::base::BaseNode;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DnsNode {
    pub children: HashMap<u64, Box<DnsNode>>,
    pub host: Option<String>, // canonicalized (punycode) hostname
}

impl Default for DnsNode {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsNode {
    pub fn new() -> Self {
        DnsNode {
            children: HashMap::new(),
            host: None,
        }
    }
}

impl BaseNode for DnsNode {
    fn is_dead(&self) -> bool {
        self.host.is_none() && self.children.is_empty()
    }
    fn children_mut(&mut self) -> &mut HashMap<u64, Box<DnsNode>> {
        &mut self.children
    }
    fn children(&self) -> &HashMap<u64, Box<DnsNode>> {
        &self.children
    }
    fn host_string(&self) -> Option<String> {
        self.host.clone()
    }
}
