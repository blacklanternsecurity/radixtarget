// Fast tree-bitmap implementation for IP prefix lookups
// Based on the Tree-bitmap algorithm by W. Eatherton, Z. Dittia, G. Varghes
// Provides O(log n) operations with efficient memory usage

use ipnet::IpNet;
use std::cmp;

// Tree-bitmap core modules
mod allocator;
mod node;

use allocator::{Allocator, AllocatorHandle};
use node::{MatchResult, Node};

/// Convert IpNet to nibbles (4-bit chunks) for tree-bitmap traversal
fn ipnet_to_nibbles(network: &IpNet) -> (Vec<u8>, u32) {
    match network {
        IpNet::V4(net) => {
            let addr = net.addr();
            let octets = addr.octets();
            let mut nibbles = Vec::with_capacity(8);
            for byte in octets {
                nibbles.push(byte >> 4);
                nibbles.push(byte & 0xf);
            }
            (nibbles, net.prefix_len().into())
        }
        IpNet::V6(net) => {
            let addr = net.addr();
            let octets = addr.octets();
            let mut nibbles = Vec::with_capacity(32);
            for byte in octets {
                nibbles.push(byte >> 4);
                nibbles.push(byte & 0xf);
            }
            (nibbles, net.prefix_len().into())
        }
    }
}


/// Fast tree-bitmap implementation for IP prefix lookups
#[derive(Debug)]
pub struct FastTreeBitmap {
    tree: TreeBitmap<IpNet>,
}

/// Core TreeBitmap structure - copied from working implementation
#[derive(Debug)]
struct TreeBitmap<T: Sized> {
    trienodes: Allocator<Node>,
    results: Allocator<T>,
    len: usize,
    should_drop: bool,
}

impl<T: Sized> TreeBitmap<T> {
    /// Returns TreeBitmap with 0 start capacity.
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Returns TreeBitmap with pre-allocated buffers of size n.
    pub fn with_capacity(n: usize) -> Self {
        let mut trieallocator: Allocator<Node> = Allocator::with_capacity(n);
        let mut root_hdl = trieallocator.alloc(0);
        trieallocator.insert(&mut root_hdl, 0, Node::new());

        TreeBitmap {
            trienodes: trieallocator,
            results: Allocator::with_capacity(n),
            len: 0,
            should_drop: true,
        }
    }

    /// Returns handle to root node.
    fn root_handle(&self) -> AllocatorHandle {
        AllocatorHandle::generate(1, 0)
    }

    /// Push down results encoded in the last 16 bits into child trie nodes.
    /// Makes ```node``` into a normal node.
    fn push_down(&mut self, node: &mut Node) {
        debug_assert!(node.is_endnode(), "push_down: not an endnode");
        debug_assert!(node.child_ptr == 0);
        // count number of internal nodes in the first 15 bits (those that will
        // remain in place).
        let internal_node_count = (node.internal() & 0xffff_0000).count_ones();
        let remove_at = internal_node_count;
        // count how many nodes to push down
        let nodes_to_pushdown = (node.internal() & 0x0000_ffff).count_ones();
        if nodes_to_pushdown > 0 {
            let mut result_hdl = node.result_handle();
            let mut child_node_hdl = self.trienodes.alloc(0);

            for _ in 0..nodes_to_pushdown {
                // allocate space for child result value
                let mut child_result_hdl = self.results.alloc(0);
                // put result value in freshly allocated bucket
                let result_value = self.results.remove(&mut result_hdl, remove_at);
                self.results.insert(&mut child_result_hdl, 0, result_value);
                // create and save child node
                let mut child_node = Node::new();
                child_node.set_internal(1 << 31);
                child_node.result_ptr = child_result_hdl.offset;
                // append trienode to collection
                let insert_node_at = child_node_hdl.len;
                self.trienodes
                    .insert(&mut child_node_hdl, insert_node_at, child_node);
            }
            // the result data may have moved to a smaller bucket, update the
            // result pointer
            node.result_ptr = result_hdl.offset;
            node.child_ptr = child_node_hdl.offset;
            // no results from this node remain, free the result slot
            if internal_node_count == 0 && nodes_to_pushdown > 0 {
                self.results.free(&mut result_hdl);
                node.result_ptr = 0;
            }
        }
        node.make_normalnode();
        // note: we do not need to touch the external bits
    }

    /// longest match lookup of ```nibbles```. Returns bits matched as u32, and reference to T.
    pub fn longest_match(&self, nibbles: &[u8]) -> Option<(u32, &T)> {
        let mut cur_hdl = self.root_handle();
        let mut cur_index = 0;
        let mut bits_matched = 0;
        let mut bits_searched = 0;
        let mut best_match: Option<(AllocatorHandle, u32)> = None; // result handle + index

        for nibble in nibbles {
            let cur_node = *self.trienodes.get(&cur_hdl, cur_index);
            let match_mask = node::MATCH_MASKS[*nibble as usize];

            if let MatchResult::Match(result_hdl, result_index, matching_bit_index) =
                cur_node.match_internal(match_mask)
            {
                bits_matched = bits_searched;
                bits_matched += node::BIT_MATCH[matching_bit_index as usize];
                best_match = Some((result_hdl, result_index));
            }

            if cur_node.is_endnode() {
                break;
            }
            match cur_node.match_external(match_mask) {
                MatchResult::Chase(child_hdl, child_index) => {
                    bits_searched += 4;
                    cur_hdl = child_hdl;
                    cur_index = child_index;
                    continue;
                }
                MatchResult::None => {
                    break;
                }
                _ => unreachable!(),
            }
        }

        match best_match {
            Some((result_hdl, result_index)) => {
                Some((bits_matched, self.results.get(&result_hdl, result_index)))
            }
            None => None,
        }
    }

    pub fn insert(&mut self, nibbles: &[u8], masklen: u32, value: T) -> Option<T> {
        let mut cur_hdl = self.root_handle();
        let mut cur_index = 0;
        let mut bits_left = masklen;
        let mut ret = None;

        let mut loop_count = 0;
        loop {
            let nibble = if loop_count < nibbles.len() {
                nibbles[loop_count]
            } else {
                0
            };
            loop_count += 1;

            let mut cur_node = *self.trienodes.get(&cur_hdl, cur_index);
            let match_result = cur_node.match_segment(nibble);

            if let MatchResult::Chase(child_hdl, index) = match_result
                && bits_left >= 4 {
                    // follow existing branch
                    bits_left -= 4;
                    cur_hdl = child_hdl;
                    cur_index = index;
                    continue;
                }

            let bitmap = node::gen_bitmap(nibble, cmp::min(4, bits_left));

            if (cur_node.is_endnode() && bits_left <= 4) || bits_left <= 3 {
                // final node reached, insert results
                let mut result_hdl = match cur_node.result_count() {
                    0 => self.results.alloc(0),
                    _ => cur_node.result_handle(),
                };
                let result_index = (cur_node.internal()
                    >> (bitmap & node::END_BIT_MASK).trailing_zeros())
                .count_ones();

                if cur_node.internal() & (bitmap & node::END_BIT_MASK) > 0 {
                    // key already exists!
                    ret = Some(self.results.replace(&result_hdl, result_index - 1, value));
                } else {
                    cur_node.set_internal(bitmap & node::END_BIT_MASK);
                    self.results.insert(&mut result_hdl, result_index, value); // add result
                    self.len += 1;
                }
                cur_node.result_ptr = result_hdl.offset;
                self.trienodes.set(&cur_hdl, cur_index, cur_node); // save trie node
                return ret;
            }
            // add a branch

            if cur_node.is_endnode() {
                // move any result pointers out of the way, so we can add branch
                self.push_down(&mut cur_node);
            }
            let mut child_hdl = match cur_node.child_count() {
                0 => self.trienodes.alloc(0),
                _ => cur_node.child_handle(),
            };

            let child_index = (cur_node.external() >> bitmap.trailing_zeros()).count_ones();

            if cur_node.external() & (bitmap & node::END_BIT_MASK) == 0 {
                // no existing branch; create it
                cur_node.set_external(bitmap & node::END_BIT_MASK);
            } else {
                // follow existing branch
                if let MatchResult::Chase(child_hdl, index) = cur_node.match_segment(nibble) {
                    self.trienodes.set(&cur_hdl, cur_index, cur_node); // save trie node
                    bits_left -= 4;
                    cur_hdl = child_hdl;
                    cur_index = index;
                    continue;
                }
                unreachable!()
            }

            // prepare a child node
            let mut child_node = Node::new();
            child_node.make_endnode();
            self.trienodes
                .insert(&mut child_hdl, child_index, child_node); // save child
            cur_node.child_ptr = child_hdl.offset;
            self.trienodes.set(&cur_hdl, cur_index, cur_node); // save trie node

            bits_left -= 4;
            cur_hdl = child_hdl;
            cur_index = child_index;
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn exact_match(&self, nibbles: &[u8], masklen: u32) -> Option<&T> {
        let mut cur_hdl = self.root_handle();
        let mut cur_index = 0;
        let mut bits_left = masklen;

        for nibble in nibbles {
            let cur_node = self.trienodes.get(&cur_hdl, cur_index);
            let bitmap = node::gen_bitmap(*nibble, cmp::min(bits_left, 4)) & node::END_BIT_MASK;
            let reached_final_node = bits_left < 4 || (cur_node.is_endnode() && bits_left == 4);

            if reached_final_node {
                match cur_node.match_internal(bitmap) {
                    MatchResult::Match(result_hdl, result_index, _) => {
                        return Some(self.results.get(&result_hdl, result_index));
                    }
                    _ => return None,
                }
            }

            match cur_node.match_external(bitmap) {
                MatchResult::Chase(child_hdl, child_index) => {
                    cur_hdl = child_hdl;
                    cur_index = child_index;
                    bits_left -= 4;
                }
                _ => return None,
            }
        }
        None
    }

    /// Remove prefix. Returns existing value if the prefix previously existed.
    pub fn remove(&mut self, nibbles: &[u8], masklen: u32) -> Option<T> {
        debug_assert!(nibbles.len() >= (masklen / 4) as usize);
        let root_hdl = self.root_handle();
        let mut root_node = *self.trienodes.get(&root_hdl, 0);
        let ret = self.remove_child(&mut root_node, nibbles, masklen);
        self.trienodes.set(&root_hdl, 0, root_node);
        ret
    }

    // remove child and result from node
    fn remove_child(&mut self, node: &mut Node, nibbles: &[u8], masklen: u32) -> Option<T> {
        let nibble = nibbles[0];
        let bitmap = node::gen_bitmap(nibble, cmp::min(masklen, 4)) & node::END_BIT_MASK;
        let reached_final_node = masklen < 4 || (node.is_endnode() && masklen == 4);

        if reached_final_node {
            match node.match_internal(bitmap) {
                MatchResult::Match(mut result_hdl, result_index, _) => {
                    node.unset_internal(bitmap);
                    let ret = self.results.remove(&mut result_hdl, result_index);
                    if node.result_count() == 0 {
                        self.results.free(&mut result_hdl);
                    }
                    node.result_ptr = result_hdl.offset;
                    self.len -= 1;
                    return Some(ret);
                }
                _ => return None,
            }
        }

        if let MatchResult::Chase(mut child_node_hdl, index) = node.match_external(bitmap) {
            let mut child_node = *self.trienodes.get(&child_node_hdl, index);
            let ret = self.remove_child(&mut child_node, &nibbles[1..], masklen - 4);

            if child_node.child_count() == 0 && !child_node.is_endnode() {
                child_node.make_endnode();
            }
            if child_node.is_empty() {
                self.trienodes.remove(&mut child_node_hdl, index);
                node.unset_external(bitmap);
                if child_node_hdl.len == 0 {
                    // no child nodes
                    self.trienodes.free(&mut child_node_hdl);
                }
                node.child_ptr = child_node_hdl.offset;
            } else {
                node.child_ptr = child_node_hdl.offset;
                self.trienodes.set(&child_node_hdl, index, child_node);
            }
            ret
        } else {
            None
        }
    }

    pub fn iter(&self) -> TreeBitmapIter<'_, T> {
        let root_hdl = self.root_handle();
        let root_node = *self.trienodes.get(&root_hdl, 0);
        TreeBitmapIter {
            inner: self,
            path: vec![PathElem {
                node: root_node,
                pos: 0,
            }],
            nibbles: vec![0],
        }
    }
}

#[derive(Debug)]
struct PathElem {
    node: Node,
    pos: usize,
}

pub struct TreeBitmapIter<'a, T: 'a> {
    inner: &'a TreeBitmap<T>,
    path: Vec<PathElem>,
    nibbles: Vec<u8>,
}

#[rustfmt::skip]
static PREFIX_OF_BIT: [u8; 32] = [// 0       1       2      3        4       5       6       7
                                  0b0000, 0b0000, 0b1000, 0b0000, 0b0100, 0b1000, 0b1100, 0b0000,
                                  // 8       9      10      11      12      13      14      15
                                  0b0010, 0b0100, 0b0110, 0b1000, 0b1010, 0b1100, 0b1110,      0,
                                  // 16      17      18      19      20      21      22      23
                                  0b0000, 0b0001, 0b0010, 0b0011, 0b0100, 0b0101, 0b0110, 0b0111,
                                  // 24      25      26      27      28      29      30      31
                                  0b1000, 0b1001, 0b1010, 0b1011, 0b1100, 0b1101, 0b1110, 0b1111];

fn tree_next<T: Sized>(
    trie: &TreeBitmap<T>,
    path: &mut Vec<PathElem>,
    nibbles: &mut Vec<u8>,
) -> Option<(Vec<u8>, u32, AllocatorHandle, u32)> {
    loop {
        let mut path_elem = path.pop()?;
        let cur_node = path_elem.node;
        let mut cur_pos = path_elem.pos;
        nibbles.pop();
        // optim:
        if cur_pos == 0 && cur_node.result_count() == 0 {
            path_elem.pos = 16;
            cur_pos = 16;
        }
        if path_elem.pos == 32 {
            continue;
        }
        let nibble = PREFIX_OF_BIT[path_elem.pos];
        let bitmap = 1 << (31 - path_elem.pos);

        path_elem.pos += 1;
        nibbles.push(nibble);
        path.push(path_elem);
        // match internal
        if cur_pos < 16 || cur_node.is_endnode() {
            let match_result = cur_node.match_internal(bitmap);
            if let MatchResult::Match(result_hdl, result_index, matching_bit) = match_result {
                let bits_matched =
                    ((path.len() as u32) - 1) * 4 + node::BIT_MATCH[matching_bit as usize];
                return Some((nibbles.clone(), bits_matched, result_hdl, result_index));
            }
        } else if let MatchResult::Chase(child_hdl, child_index) = cur_node.match_external(bitmap) {
            let child_node = trie.trienodes.get(&child_hdl, child_index);
            nibbles.push(0);
            path.push(PathElem {
                node: *child_node,
                pos: 0,
            });
        }
    }
}

impl<'a, T: 'a> Iterator for TreeBitmapIter<'a, T> {
    type Item = (Vec<u8>, u32, &'a T); //(nibbles, masklen, &T)

    fn next(&mut self) -> Option<Self::Item> {
        match tree_next(self.inner, &mut self.path, &mut self.nibbles) {
            Some((path, bits_matched, hdl, index)) => {
                let value = self.inner.results.get(&hdl, index);
                Some((path, bits_matched, value))
            }
            None => None,
        }
    }
}

impl<T> Drop for TreeBitmap<T> {
    fn drop(&mut self) {
        if self.should_drop {
            for (_, _, item) in self.iter() {
                unsafe {
                    std::ptr::read(item);
                }
            }
        }
    }
}

impl FastTreeBitmap {
    pub fn new() -> Self {
        Self {
            tree: TreeBitmap::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            tree: TreeBitmap::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.tree.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tree.len() == 0
    }

    /// Get all stored networks
    pub fn all_networks(&self) -> Vec<IpNet> {
        let mut networks = Vec::new();
        for (_nibbles, _masklen, network) in self.tree.iter() {
            networks.push(*network);
        }
        networks
    }

    pub fn insert(&mut self, network: IpNet) -> Option<IpNet> {
        let canonical = crate::utils::canonicalize_ipnet(&network);
        let (nibbles, masklen) = ipnet_to_nibbles(&canonical);
        self.tree.insert(&nibbles, masklen, canonical)
    }

    pub fn longest_match(&self, network: &IpNet) -> Option<&IpNet> {
        let canonical = crate::utils::canonicalize_ipnet(network);
        let (nibbles, _) = ipnet_to_nibbles(&canonical);

        match self.tree.longest_match(&nibbles) {
            Some((_, result)) => Some(result),
            None => None,
        }
    }

    pub fn exact_match(&self, network: &IpNet) -> Option<&IpNet> {
        let canonical = crate::utils::canonicalize_ipnet(network);
        let (nibbles, masklen) = ipnet_to_nibbles(&canonical);
        self.tree.exact_match(&nibbles, masklen)
    }

    pub fn remove(&mut self, network: &IpNet) -> Option<IpNet> {
        let canonical = crate::utils::canonicalize_ipnet(network);
        let (nibbles, masklen) = ipnet_to_nibbles(&canonical);
        self.tree.remove(&nibbles, masklen)
    }
}

impl Default for FastTreeBitmap {
    fn default() -> Self {
        Self::new()
    }
}
