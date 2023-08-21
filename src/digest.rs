mod sha2 {
    pub(super) const CHAINING_WORDS: usize = 8;

    #[cfg(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86_64"))]
    extern "C" {
        pub(super) fn GFp_sha256_block_data_order(
            state: &mut super::State,
            data: *const u8,
            num: usize,
        );
    }
}

pub struct MyAlgorithm {
    #[allow(unused)]
    block_data_order: unsafe extern "C" fn(state: &mut State, data: *const u8, num: usize),
}

pub static MYSHA256: MyAlgorithm = MyAlgorithm {
    block_data_order: sha2::GFp_sha256_block_data_order,
};

#[repr(C)]
union State {
    as64: [u64; sha2::CHAINING_WORDS],
    as32: [u32; sha2::CHAINING_WORDS],
}
