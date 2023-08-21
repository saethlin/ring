use crate::{c, error};

#[cfg(feature = "alloc")]
use crate::bits;

#[cfg(feature = "alloc")]
use core::num::Wrapping;

// XXX: Not correct for x32 ABIs.
#[cfg(target_pointer_width = "64")]
pub type Limb = u64;
#[cfg(target_pointer_width = "32")]
pub type Limb = u32;
#[cfg(target_pointer_width = "64")]
pub const LIMB_BITS: usize = 64;
#[cfg(target_pointer_width = "32")]
pub const LIMB_BITS: usize = 32;

#[cfg(target_pointer_width = "64")]
#[derive(Debug, PartialEq)]
#[repr(u64)]
pub enum LimbMask {
    True = 0xffff_ffff_ffff_ffff,
    False = 0,
}

#[cfg(target_pointer_width = "32")]
#[derive(Debug, PartialEq)]
#[repr(u32)]
pub enum LimbMask {
    True = 0xffff_ffff,
    False = 0,
}

pub const LIMB_BYTES: usize = (LIMB_BITS + 7) / 8;

#[inline]
pub fn limbs_equal_limbs_consttime(a: &[Limb], b: &[Limb]) -> LimbMask {
    extern "C" {
        fn LIMBS_equal(a: *const Limb, b: *const Limb, num_limbs: c::size_t) -> LimbMask;
    }

    assert_eq!(a.len(), b.len());
    unsafe { LIMBS_equal(a.as_ptr(), b.as_ptr(), a.len()) }
}

#[inline]
pub fn limbs_less_than_limbs_consttime(a: &[Limb], b: &[Limb]) -> LimbMask {
    assert_eq!(a.len(), b.len());
    unsafe { LIMBS_less_than(a.as_ptr(), b.as_ptr(), b.len()) }
}

#[inline]
pub fn limbs_less_than_limbs_vartime(a: &[Limb], b: &[Limb]) -> bool {
    limbs_less_than_limbs_consttime(a, b) == LimbMask::True
}

#[inline]
#[cfg(feature = "alloc")]
pub fn limbs_less_than_limb_constant_time(a: &[Limb], b: Limb) -> LimbMask {
    unsafe { LIMBS_less_than_limb(a.as_ptr(), b, a.len()) }
}

#[inline]
pub fn limbs_are_zero_constant_time(limbs: &[Limb]) -> LimbMask {
    unsafe { LIMBS_are_zero(limbs.as_ptr(), limbs.len()) }
}

#[cfg(feature = "alloc")]
#[inline]
pub fn limbs_are_even_constant_time(limbs: &[Limb]) -> LimbMask {
    unsafe { LIMBS_are_even(limbs.as_ptr(), limbs.len()) }
}

#[cfg(feature = "alloc")]
#[inline]
pub fn limbs_equal_limb_constant_time(a: &[Limb], b: Limb) -> LimbMask {
    unsafe { LIMBS_equal_limb(a.as_ptr(), b, a.len()) }
}

/// Returns the number of bits in `a`.
//
// This strives to be constant-time with respect to the values of all bits
// except the most significant bit. This does not attempt to be constant-time
// with respect to `a.len()` or the value of the result or the value of the
// most significant bit (It's 1, unless the input is zero, in which case it's
// zero.)
#[cfg(feature = "alloc")]
pub fn limbs_minimal_bits(a: &[Limb]) -> bits::BitLength {
    for num_limbs in (1..=a.len()).rev() {
        let high_limb = a[num_limbs - 1];

        // Find the number of set bits in |high_limb| by a linear scan from the
        // most significant bit to the least significant bit. This works great
        // for the most common inputs because usually the most significant bit
        // it set.
        for high_limb_num_bits in (1..=LIMB_BITS).rev() {
            let shifted = unsafe { LIMB_shr(high_limb, high_limb_num_bits - 1) };
            if shifted != 0 {
                return bits::BitLength::from_usize_bits(
                    ((num_limbs - 1) * LIMB_BITS) + high_limb_num_bits,
                );
            }
        }
    }

    // No bits were set.
    bits::BitLength::from_usize_bits(0)
}

#[inline]
pub fn limbs_reduce_once_constant_time(r: &mut [Limb], m: &[Limb]) {
    assert_eq!(r.len(), m.len());
    unsafe { LIMBS_reduce_once(r.as_mut_ptr(), m.as_ptr(), m.len()) };
}

/// Parses `input` into `result`, padding `result` with zeros to its length.
/// This attempts to be constant-time with respect to the value but not with
/// respect to the length; it is assumed that the length is public knowledge.
pub fn parse_big_endian_and_pad_consttime(
    input: untrusted::Input,
    result: &mut [Limb],
) -> Result<(), error::Unspecified> {
    if input.is_empty() {
        return Err(error::Unspecified);
    }

    // `bytes_in_current_limb` is the number of bytes in the current limb.
    // It will be `LIMB_BYTES` for all limbs except maybe the highest-order
    // limb.
    let mut bytes_in_current_limb = input.len() % LIMB_BYTES;
    if bytes_in_current_limb == 0 {
        bytes_in_current_limb = LIMB_BYTES;
    }

    let num_encoded_limbs = (input.len() / LIMB_BYTES)
        + (if bytes_in_current_limb == LIMB_BYTES {
            0
        } else {
            1
        });
    if num_encoded_limbs > result.len() {
        return Err(error::Unspecified);
    }

    for r in &mut result[..] {
        *r = 0;
    }

    // XXX: Questionable as far as constant-timedness is concerned.
    // TODO: Improve this.
    input.read_all(error::Unspecified, |input| {
        for i in 0..num_encoded_limbs {
            let mut limb: Limb = 0;
            for _ in 0..bytes_in_current_limb {
                let b: Limb = input.read_byte()?.into();
                limb = (limb << 8) | b;
            }
            result[num_encoded_limbs - i - 1] = limb;
            bytes_in_current_limb = LIMB_BYTES;
        }
        Ok(())
    })
}

pub fn big_endian_from_limbs(limbs: &[Limb], out: &mut [u8]) {
    let num_limbs = limbs.len();
    let out_len = out.len();
    assert_eq!(out_len, num_limbs * LIMB_BYTES);
    for i in 0..num_limbs {
        let mut limb = limbs[i];
        for j in 0..LIMB_BYTES {
            out[((num_limbs - i - 1) * LIMB_BYTES) + (LIMB_BYTES - j - 1)] = (limb & 0xff) as u8;
            limb >>= 8;
        }
    }
}

#[cfg(feature = "alloc")]
pub type Window = Limb;

/// Processes `limbs` as a sequence of 5-bit windows, folding the windows from
/// most significant to least significant and returning the accumulated result.
/// The first window will be mapped by `init` to produce the initial value for
/// the accumulator. Then `f` will be called to fold the accumulator and the
/// next window until all windows are processed. When the input's bit length
/// isn't divisible by 5, the window passed to `init` will be partial; all
/// windows passed to `fold` will be full.
///
/// This is designed to avoid leaking the contents of `limbs` through side
/// channels as long as `init` and `fold` are side-channel free.
///
/// Panics if `limbs` is empty.
#[cfg(feature = "alloc")]
pub fn fold_5_bit_windows<R, I: FnOnce(Window) -> R, F: Fn(R, Window) -> R>(
    limbs: &[Limb],
    init: I,
    fold: F,
) -> R {
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    struct BitIndex(Wrapping<c::size_t>);

    const WINDOW_BITS: Wrapping<c::size_t> = Wrapping(5);

    extern "C" {
        fn LIMBS_window5_split_window(
            lower_limb: Limb,
            higher_limb: Limb,
            index_within_word: BitIndex,
        ) -> Window;
        fn LIMBS_window5_unsplit_window(limb: Limb, index_within_word: BitIndex) -> Window;
    }

    let num_limbs = limbs.len();
    let mut window_low_bit = {
        let num_whole_windows = (num_limbs * LIMB_BITS) / 5;
        let mut leading_bits = (num_limbs * LIMB_BITS) - (num_whole_windows * 5);
        if leading_bits == 0 {
            leading_bits = WINDOW_BITS.0;
        }
        BitIndex(Wrapping(LIMB_BITS - leading_bits))
    };

    let initial_value = {
        let leading_partial_window =
            unsafe { LIMBS_window5_split_window(*limbs.last().unwrap(), 0, window_low_bit) };
        window_low_bit.0 -= WINDOW_BITS;
        init(leading_partial_window)
    };

    let mut low_limb = 0;
    limbs
        .iter()
        .rev()
        .fold(initial_value, |mut acc, current_limb| {
            let higher_limb = low_limb;
            low_limb = *current_limb;

            if window_low_bit.0 > Wrapping(LIMB_BITS) - WINDOW_BITS {
                let window =
                    unsafe { LIMBS_window5_split_window(low_limb, higher_limb, window_low_bit) };
                window_low_bit.0 -= WINDOW_BITS;
                acc = fold(acc, window);
            };
            while window_low_bit.0 < Wrapping(LIMB_BITS) {
                let window = unsafe { LIMBS_window5_unsplit_window(low_limb, window_low_bit) };
                // The loop exits when this subtraction underflows, causing `window_low_bit` to
                // wrap around to a very large value.
                window_low_bit.0 -= WINDOW_BITS;
                acc = fold(acc, window);
            }
            window_low_bit.0 += Wrapping(LIMB_BITS); // "Fix" the underflow.

            acc
        })
}

extern "C" {
    #[cfg(feature = "alloc")]
    fn LIMB_shr(a: Limb, shift: c::size_t) -> Limb;

    #[cfg(feature = "alloc")]
    fn LIMBS_are_even(a: *const Limb, num_limbs: c::size_t) -> LimbMask;
    fn LIMBS_are_zero(a: *const Limb, num_limbs: c::size_t) -> LimbMask;
    #[cfg(feature = "alloc")]
    fn LIMBS_equal_limb(a: *const Limb, b: Limb, num_limbs: c::size_t) -> LimbMask;
    fn LIMBS_less_than(a: *const Limb, b: *const Limb, num_limbs: c::size_t) -> LimbMask;
    #[cfg(feature = "alloc")]
    fn LIMBS_less_than_limb(a: *const Limb, b: Limb, num_limbs: c::size_t) -> LimbMask;
    fn LIMBS_reduce_once(r: *mut Limb, m: *const Limb, num_limbs: c::size_t);
}
