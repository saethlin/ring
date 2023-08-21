mod c {
	pub(crate) type size_t = usize;
}

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

mod sealed {
    /// Traits that are designed to only be implemented internally in *ring*.
    //
    // Usage:
    // ```
    // use crate::sealed;
    //
    // pub trait MyType: sealed::Sealed {
    //     // [...]
    // }
    //
    // impl sealed::Sealed for MyType {}
    // ```
    pub trait Sealed {}
}
