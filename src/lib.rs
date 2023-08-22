pub struct FnWrapper {
    inner: unsafe extern "C" fn(),
}

extern "C" {
    fn GFp_sha256_block_data_order();
}

mod digest {
    pub static WRAPPER: super::FnWrapper = super::FnWrapper {
        inner: super::GFp_sha256_block_data_order,
    };
}

pub static WRAPPER_REF: &'static FnWrapper = &digest::WRAPPER;

#[no_mangle]
static mut GFp_armcap_P: u32 = 0;
