mod cpu;
mod digest;
mod endian;

pub static MYALGORITHM: &'static digest::MyAlgorithm = &digest::MYSHA256;

/*
extern "C" {
    fn MyExampleFunction(state: &mut crate::digest::State, data: *const u8, num: crate::c::size_t);
}

pub struct MyAlgorithm {
    inner: unsafe extern "C" fn(state: &mut crate::digest::State, data: *const u8, num: crate::c::size_t),
}

pub static MYSHA256: MyAlgorithm = MyAlgorithm {
    inner: MyExampleFunction,
};

pub static DEMO: &'static inner::MyAlgorithm = &inner::MYSHA256;
*/

#[no_mangle]
static mut GFp_armcap_P: u32 = 0;
