use crate::{
    c,
    endian::{self, BigEndian},
    polyfill,
};
use core::num::Wrapping;

mod sha2 {
    use crate::c;

    pub(super) const CHAINING_WORDS: usize = 8;

    #[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64"))]
    extern "C" {
        pub(super) fn GFp_sha256_block_data_order(
            state: &mut super::State,
            data: *const u8,
            num: c::size_t,
        );
    }
}

pub struct MyAlgorithm {
    #[allow(unused)]
    block_data_order: unsafe extern "C" fn(state: &mut State, data: *const u8, num: c::size_t),
}

pub static MYSHA256: MyAlgorithm = MyAlgorithm {
    block_data_order: sha2::GFp_sha256_block_data_order,
};

#[derive(Clone)]
pub(crate) struct BlockContext {
    state: State,

    // Note that SHA-512 has a 128-bit input bit counter, but this
    // implementation only supports up to 2^64-1 input bits for all algorithms,
    // so a 64-bit counter is more than sufficient.
    completed_data_blocks: u64,

    /// The context's algorithm.
    algorithm: &'static Algorithm,
}

impl BlockContext {
    pub(crate) fn new(algorithm: &'static Algorithm) -> Self {
        Self {
            state: algorithm.initial_state,
            completed_data_blocks: 0,
            algorithm,
        }
    }

    #[inline]
    pub(crate) fn update(&mut self, input: &[u8]) {
        let num_blocks = input.len() / self.algorithm.block_len;
        assert_eq!(num_blocks * self.algorithm.block_len, input.len());
        if num_blocks > 0 {
            unsafe {
                (self.algorithm.block_data_order)(&mut self.state, input.as_ptr(), num_blocks);
            }
            self.completed_data_blocks = self
                .completed_data_blocks
                .checked_add(polyfill::u64_from_usize(num_blocks))
                .unwrap();
        }
    }

    pub(crate) fn finish(mut self, pending: &mut [u8], num_pending: usize) -> Digest {
        let block_len = self.algorithm.block_len;
        assert_eq!(pending.len(), block_len);
        assert!(num_pending <= pending.len());

        let mut padding_pos = num_pending;
        pending[padding_pos] = 0x80;
        padding_pos += 1;

        if padding_pos > block_len - self.algorithm.len_len {
            polyfill::slice::fill(&mut pending[padding_pos..block_len], 0);
            unsafe {
                (self.algorithm.block_data_order)(&mut self.state, pending.as_ptr(), 1);
            }
            // We don't increase |self.completed_data_blocks| because the
            // padding isn't data, and so it isn't included in the data length.
            padding_pos = 0;
        }

        polyfill::slice::fill(&mut pending[padding_pos..(block_len - 8)], 0);

        // Output the length, in bits, in big endian order.
        let completed_data_bits = self
            .completed_data_blocks
            .checked_mul(polyfill::u64_from_usize(block_len))
            .unwrap()
            .checked_add(polyfill::u64_from_usize(num_pending))
            .unwrap()
            .checked_mul(8)
            .unwrap();
        pending[(block_len - 8)..block_len].copy_from_slice(&u64::to_be_bytes(completed_data_bits));

        unsafe {
            (self.algorithm.block_data_order)(&mut self.state, pending.as_ptr(), 1);
        }

        Digest {
            algorithm: self.algorithm,
            value: (self.algorithm.format_output)(self.state),
        }
    }
}

#[derive(Clone)]
pub struct Context {
    block: BlockContext,
    // TODO: More explicitly force 64-bit alignment for |pending|.
    pending: [u8; MAX_BLOCK_LEN],
    num_pending: usize,
}

impl Context {
    fn new(algorithm: &'static Algorithm) -> Self {
        Self {
            block: BlockContext::new(algorithm),
            pending: [0u8; MAX_BLOCK_LEN],
            num_pending: 0,
        }
    }

    fn clone_from(block: &BlockContext) -> Self {
        Self {
            block: block.clone(),
            pending: [0u8; MAX_BLOCK_LEN],
            num_pending: 0,
        }
    }

    /// Updates the digest with all the data in `data`. `update` may be called
    /// zero or more times until `finish` is called. It must not be called
    /// after `finish` has been called.
    fn update(&mut self, data: &[u8]) {
        let block_len = self.block.algorithm.block_len;
        if data.len() < block_len - self.num_pending {
            self.pending[self.num_pending..(self.num_pending + data.len())].copy_from_slice(data);
            self.num_pending += data.len();
            return;
        }

        let mut remaining = data;
        if self.num_pending > 0 {
            let to_copy = block_len - self.num_pending;
            self.pending[self.num_pending..block_len].copy_from_slice(&data[..to_copy]);
            self.block.update(&self.pending[..block_len]);
            remaining = &remaining[to_copy..];
            self.num_pending = 0;
        }

        let num_blocks = remaining.len() / block_len;
        let num_to_save_for_later = remaining.len() % block_len;
        self.block.update(&remaining[..(num_blocks * block_len)]);
        if num_to_save_for_later > 0 {
            self.pending[..num_to_save_for_later]
                .copy_from_slice(&remaining[(remaining.len() - num_to_save_for_later)..]);
            self.num_pending = num_to_save_for_later;
        }
    }

    /// Finalizes the digest calculation and returns the digest value. `finish`
    /// consumes the context so it cannot be (mis-)used after `finish` has been
    /// called.
    fn finish(mut self) -> Digest {
        let block_len = self.block.algorithm.block_len;
        self.block
            .finish(&mut self.pending[..block_len], self.num_pending)
    }

    /// The algorithm that this context is using.
    #[inline(always)]
    fn algorithm(&self) -> &'static Algorithm {
        self.block.algorithm
    }
}

/// A calculated digest value.
///
/// Use `as_ref` to get the value as a `&[u8]`.
#[derive(Clone, Copy)]
pub struct Digest {
    value: Output,
    algorithm: &'static Algorithm,
}

impl AsRef<[u8]> for Digest {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        let as64 = unsafe { &self.value.as64 };
        &endian::as_byte_slice(as64)[..self.algorithm.output_len]
    }
}

/// A digest algorithm.
pub struct Algorithm {
    /// The length of a finalized digest.
    output_len: usize,

    /// The size of the chaining value of the digest function, in bytes. For
    /// non-truncated algorithms (SHA-1, SHA-256, SHA-512), this is equal to
    /// `output_len`. For truncated algorithms (e.g. SHA-384, SHA-512/256),
    /// this is equal to the length before truncation. This is mostly helpful
    /// for determining the size of an HMAC key that is appropriate for the
    /// digest algorithm.
    chaining_len: usize,

    /// The internal block length.
    block_len: usize,

    /// The length of the length in the padding.
    len_len: usize,

    block_data_order: unsafe extern "C" fn(state: &mut State, data: *const u8, num: c::size_t),
    format_output: fn(input: State) -> Output,

    initial_state: State,
}

impl PartialEq for Algorithm {
    fn eq(&self, other: &Self) -> bool {
        true
    }
}

impl Eq for Algorithm {}

#[derive(Clone, Copy)] // XXX: Why do we need to be `Copy`?
#[repr(C)]
union State {
    as64: [Wrapping<u64>; sha2::CHAINING_WORDS],
    as32: [Wrapping<u32>; sha2::CHAINING_WORDS],
}

#[derive(Clone, Copy)]
#[repr(C)]
union Output {
    as64: [BigEndian<u64>; 512 / 8 / core::mem::size_of::<BigEndian<u64>>()],
    as32: [BigEndian<u32>; 256 / 8 / core::mem::size_of::<BigEndian<u32>>()],
}

/// The maximum block length (`Algorithm::block_len`) of all the algorithms in
/// this module.
const MAX_BLOCK_LEN: usize = 1024 / 8;

/// The maximum output length (`Algorithm::output_len`) of all the algorithms
/// in this module.
const MAX_OUTPUT_LEN: usize = 512 / 8;
