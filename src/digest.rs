use crate::{
    c,
    endian::{self, BigEndian},
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


#[derive(Clone)]
pub struct Context {
    block: BlockContext,
    // TODO: More explicitly force 64-bit alignment for |pending|.
    pending: [u8; MAX_BLOCK_LEN],
    num_pending: usize,
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
