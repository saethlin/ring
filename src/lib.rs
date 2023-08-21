pub struct MyAlgorithm {
    block_data_order: unsafe extern "C" fn(state: &mut State, data: *const u8, num: usize),
}

#[repr(C)]
union State {
    as64: [u64; 8],
    as32: [u32; 8],
}

extern "C" {
    fn GFp_sha256_block_data_order(state: &mut State, data: *const u8, num: usize);
}

mod digest {
    pub static MYSHA256: super::MyAlgorithm = super::MyAlgorithm {
        block_data_order: super::GFp_sha256_block_data_order,
    };
}

pub static MYALGORITHM: &'static MyAlgorithm = &digest::MYSHA256;

#[no_mangle]
static mut GFp_armcap_P: u32 = 0;
