// Copyright 2016 Hroi Sigurdsson
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::cmp;
use std::fmt;
use std::mem;

/// A vector that contains `len / spacing` buckets and each bucket contains `spacing` elements.
/// Buckets are store contiguously in the vector.
/// So slots are multiples of `spacing`.
///
/// Every access goes through a slice of exactly one bucket, so an out-of-range
/// index panics instead of touching a neighbouring bucket.
pub struct BucketVec<T> {
    buf: Vec<T>,
    freelist: Vec<u32>,
    len: u32,
    spacing: u32,
}

impl<T: fmt::Debug> fmt::Debug for BucketVec<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("BucketVec")
            .field("spacing", &self.spacing)
            .field("freelist", &self.freelist)
            .field("len", &self.len)
            .field("cap", &self.buf.capacity())
            .field("buf", &format!("Vec<T> len={}", self.len))
            .finish()
    }
}

impl<T: Copy + Default> BucketVec<T> {
    pub fn with_capacity(spacing: u32, capacity: usize) -> BucketVec<T> {
        BucketVec {
            buf: Vec::with_capacity(capacity),
            freelist: Vec::with_capacity(32),
            len: 0,
            spacing,
        }
    }

    #[allow(dead_code)]
    pub fn new(spacing: u32) -> BucketVec<T> {
        Self::with_capacity(spacing, 0)
    }

    #[inline]
    fn bucket(&self, slot: u32) -> &[T] {
        debug_assert!(slot.is_multiple_of(self.spacing));
        &self.buf[slot as usize..(slot + self.spacing) as usize]
    }

    #[inline]
    fn bucket_mut(&mut self, slot: u32) -> &mut [T] {
        debug_assert!(slot.is_multiple_of(self.spacing));
        &mut self.buf[slot as usize..(slot + self.spacing) as usize]
    }

    /// Allocate a bucket slot.
    pub fn alloc_slot(&mut self) -> u32 {
        match self.freelist.pop() {
            Some(n) => n,
            None => {
                let slot = self.len;
                self.len += self.spacing;
                self.buf.resize(self.len as usize, T::default());
                slot
            }
        }
    }

    /// Free a bucket slot.
    pub fn free_slot(&mut self, slot: u32) {
        self.freelist.push(slot)
    }

    #[inline]
    pub fn get_slot_entry(&self, slot: u32, index: u32) -> &T {
        &self.bucket(slot)[index as usize]
    }

    pub fn set_slot_entry(&mut self, slot: u32, index: u32, value: T) {
        self.bucket_mut(slot)[index as usize] = value;
    }

    pub fn replace_slot_entry(&mut self, slot: u32, index: u32, value: T) -> T {
        mem::replace(&mut self.bucket_mut(slot)[index as usize], value)
    }

    /// Insert ```value``` into ```slot``` at ```index```. Values to the right
    /// of ```index``` will be moved.
    /// If all values have been set the last value will be lost.
    pub fn insert_slot_entry(&mut self, slot: u32, index: u32, value: T) {
        let bucket = self.bucket_mut(slot);
        let index = index as usize;
        let last = bucket.len() - 1;
        bucket.copy_within(index..last, index + 1);
        bucket[index] = value;
    }

    pub fn remove_slot_entry(&mut self, slot: u32, index: u32) -> T {
        let bucket = self.bucket_mut(slot);
        let index = index as usize;
        let ret = bucket[index];
        bucket.copy_within(index + 1.., index);
        let last = bucket.len() - 1;
        bucket[last] = T::default();
        ret
    }

    /// Move contents from one bucket to another.
    /// Returns the offset of the new location.
    fn move_slot(&mut self, slot: u32, dst: &mut BucketVec<T>) -> u32 {
        let nitems = cmp::min(self.spacing, dst.spacing) as usize;

        debug_assert!(slot < self.len);
        debug_assert!(nitems > 0);

        let dst_slot = dst.alloc_slot();
        dst.bucket_mut(dst_slot)[..nitems].copy_from_slice(&self.bucket(slot)[..nitems]);
        self.bucket_mut(slot).fill(T::default());

        self.free_slot(slot);

        dst_slot
    }
}

static LEN2BUCKET: [u32; 33] = [
    0, 0, 1, 2, 2, 3, 3, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8,
    8,
];

#[inline]
pub fn choose_bucket(len: u32) -> u32 {
    LEN2BUCKET[len as usize]
}

/// ```Allocator``` stores items in exponentially sized buckets (using
/// ```BucketVec```s for backing).
///
/// All interaction is done with an ```AllocatorHandle```used for tracking the
/// collection size and location.
/// The location of data is computed based on the collection size and base
/// pointer (stored in handle).
/// When a bucket becomes full, the contents are moved to a larger bucket. In
/// this case the allocator will update the caller's pointer.
#[derive(Debug)]
pub struct Allocator<T: Sized> {
    buckets: [BucketVec<T>; 9],
}

/// Tracks the size and location of the referenced collection.
#[derive(Debug)]
pub struct AllocatorHandle {
    /// The current length of the collection
    pub len: u32,
    /// Basepointer
    pub offset: u32,
}

impl AllocatorHandle {
    #[inline]
    pub fn generate(len: u32, offset: u32) -> AllocatorHandle {
        AllocatorHandle { len, offset }
    }
}

impl<T: Copy + Default> Allocator<T> {
    /// Initialize a new allocator with default capacity.
    #[allow(dead_code)]
    pub fn new() -> Allocator<T> {
        Allocator {
            buckets: [
                BucketVec::new(1),
                BucketVec::new(2),
                BucketVec::new(4),
                BucketVec::new(6),
                BucketVec::new(8),
                BucketVec::new(12),
                BucketVec::new(16),
                BucketVec::new(24),
                BucketVec::new(32),
            ],
        }
    }

    /// Initialize a new ```Allocator``` with specified capacity.
    pub fn with_capacity(cap: usize) -> Allocator<T> {
        Allocator {
            buckets: [
                BucketVec::with_capacity(1, cap),
                BucketVec::with_capacity(2, cap),
                BucketVec::with_capacity(4, cap),
                BucketVec::with_capacity(6, cap),
                BucketVec::with_capacity(8, cap),
                BucketVec::with_capacity(12, cap),
                BucketVec::with_capacity(16, cap),
                BucketVec::with_capacity(24, cap),
                BucketVec::with_capacity(32, cap),
            ],
        }
    }

    pub fn alloc(&mut self, count: u32) -> AllocatorHandle {
        let bucket_index = choose_bucket(count) as usize;
        let slot = self.buckets[bucket_index].alloc_slot();
        AllocatorHandle {
            len: count,
            offset: slot,
        }
    }

    pub fn free(&mut self, hdl: &mut AllocatorHandle) {
        debug_assert!(hdl.len == 0, "tried to free non-empty collection");
        let bucket_index = choose_bucket(hdl.len) as usize;
        self.buckets[bucket_index].free_slot(hdl.offset);
        hdl.offset = 0;
    }

    pub fn set(&mut self, hdl: &AllocatorHandle, index: u32, value: T) {
        let bucket_index = choose_bucket(hdl.len) as usize;
        self.buckets[bucket_index].set_slot_entry(hdl.offset, index, value)
    }

    pub fn replace(&mut self, hdl: &AllocatorHandle, index: u32, value: T) -> T {
        let bucket_index = choose_bucket(hdl.len) as usize;
        self.buckets[bucket_index].replace_slot_entry(hdl.offset, index, value)
    }

    #[inline]
    pub fn get(&self, hdl: &AllocatorHandle, index: u32) -> &T {
        let bucket_index = choose_bucket(hdl.len) as usize;
        self.buckets[bucket_index].get_slot_entry(hdl.offset, index)
    }

    pub fn insert(&mut self, hdl: &mut AllocatorHandle, index: u32, value: T) {
        let mut bucket_index = choose_bucket(hdl.len) as usize;
        let next_bucket_index = choose_bucket(hdl.len + 1) as usize;
        let mut slot = hdl.offset;

        debug_assert!(self.buckets[bucket_index].len >= hdl.offset);

        if bucket_index != next_bucket_index {
            // move to bigger bucket
            debug_assert!(next_bucket_index > bucket_index);
            let (left, right) = self.buckets.split_at_mut(bucket_index + 1);
            slot = left[bucket_index]
                .move_slot(slot, &mut right[next_bucket_index - bucket_index - 1]);
            bucket_index = next_bucket_index;
        }

        hdl.offset = slot;
        hdl.len += 1;

        self.buckets[bucket_index].insert_slot_entry(slot, index, value)
    }

    pub fn remove(&mut self, hdl: &mut AllocatorHandle, index: u32) -> T {
        let bucket_index = choose_bucket(hdl.len) as usize;
        let next_bucket_index = choose_bucket(hdl.len - 1) as usize;
        let mut slot = hdl.offset;

        let ret = self.buckets[bucket_index].remove_slot_entry(slot, index);

        if bucket_index != next_bucket_index {
            // move to smaller bucket
            debug_assert!(next_bucket_index < bucket_index);
            let (left, right) = self.buckets.split_at_mut(bucket_index);
            slot = right[0].move_slot(slot, &mut left[next_bucket_index]);
        }

        hdl.offset = slot;
        hdl.len -= 1;
        ret
    }
}
