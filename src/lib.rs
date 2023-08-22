extern "C" {
    fn GFp_sha256_block_data_order();
}

mod digest {
    pub static WRAPPER: unsafe extern "C" fn() = super::GFp_sha256_block_data_order;
}

pub static WRAPPER_REF: &'static unsafe extern "C" fn() = &digest::WRAPPER;

#[no_mangle]
static mut GFp_armcap_P: u32 = 0;
