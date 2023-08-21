use crate::error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd)]
pub struct BitLength(usize);

impl BitLength {
    #[inline]
    pub fn as_usize_bits(&self) -> usize {
        self.0
    }

    #[cfg(feature = "alloc")]
    #[inline]
    pub fn as_usize_bytes_rounded_up(&self) -> usize {
        // Equivalent to (self.0 + 7) / 8, except with no potential for
        // overflow and without branches.

        // Branchless round_up = if self.0 & 0b111 != 0 { 1 } else { 0 };
        let round_up = ((self.0 >> 2) | (self.0 >> 1) | self.0) & 1;

        (self.0 / 8) + round_up
    }

    #[cfg(feature = "alloc")]
    #[inline]
    pub fn try_sub_1(self) -> Result<BitLength, error::Unspecified> {
        let sum = self.0.checked_sub(1).ok_or(error::Unspecified)?;
        Ok(BitLength(sum))
    }
}
