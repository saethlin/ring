use crate::{c, error};

pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), error::Unspecified> {
    if a.len() != b.len() {
        return Err(error::Unspecified);
    }
    let result = unsafe { GFp_memcmp(a.as_ptr(), b.as_ptr(), a.len()) };
    match result {
        0 => Ok(()),
        _ => Err(error::Unspecified),
    }
}

extern "C" {
    fn GFp_memcmp(a: *const u8, b: *const u8, len: c::size_t) -> c::int;
}
