#[inline(always)]
pub const fn u64_from_usize(x: usize) -> u64 {
    x as u64
}

pub mod slice {
    // https://github.com/rust-lang/rust/issues/27750
    // https://internals.rust-lang.org/t/stabilizing-basic-functions-on-arrays-and-slices/2868
    #[inline(always)]
    pub fn fill<T>(dest: &mut [T], value: T)
    where
        T: Copy,
    {
        for d in dest {
            *d = value;
        }
    }
}
