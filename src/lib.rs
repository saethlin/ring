// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Safe, fast, small crypto using Rust with BoringSSL's cryptography
//! primitives.
//!
//! # Feature Flags
//!
//! <table>
//! <tr><th>Feature
//!     <th>Description
//! <tr><td><code>alloc (default)</code>
//!     <td>Enable features that require use of the heap, RSA in particular.
//! <tr><td><code>dev_urandom_fallback (default)</code>
//!     <td>This is only applicable to Linux. On Linux, by default,
//!         <code>ring::rand::SystemRandom</code> will fall back to reading
//!         from <code>/dev/urandom</code> if the <code>getrandom()</code>
//!         syscall isn't supported at runtime. When the
//!         <code>dev_urandom_fallback</code> feature is disabled, such
//!         fallbacks will not occur. See the documentation for
//!         <code>rand::SystemRandom</code> for more details.
//! <tr><td><code>std</code>
//!     <td>Enable features that use libstd, in particular
//!         <code>std::error::Error</code> integration. Implies `alloc`.
//! <tr><td><code>wasm32_c</code>
//!     <td>Enables features that require a C compiler on wasm32 targets, such as
//!        the <code>constant_time</code> module, HMAC verification, and PBKDF2
//!        verification. Without this feature, only a subset of functionality
//!        is provided to wasm32 targets so that a C compiler isn't needed. A
//!        typical invocation would be:
//!        <code>TARGET_CC=clang-10 TARGET_AR=llvm-ar-10 cargo test --target=wasm32-unknown-unknown --features=wasm32_c</code>
//!        with <code>llvm-ar-10</code> and <code>clang-10</code> in <code>$PATH</code>.
//!        (Going forward more functionality should be enabled by default, without
//!        requiring these hacks, and without requiring a C compiler.)
//! </table>

#![doc(html_root_url = "https://briansmith.org/rustdoc/")]
#![allow(
    clippy::collapsible_if,
    clippy::identity_op,
    clippy::len_without_is_empty,
    clippy::len_zero,
    clippy::let_unit_value,
    clippy::many_single_char_names,
    clippy::needless_range_loop,
    clippy::new_without_default,
    clippy::neg_cmp_op_on_partial_ord,
    clippy::range_plus_one,
    clippy::too_many_arguments,
    clippy::trivially_copy_pass_by_ref,
    clippy::type_complexity,
    clippy::unreadable_literal,
    missing_copy_implementations,
    missing_debug_implementations,
    non_camel_case_types,
    non_snake_case,
    unsafe_code
)]
#![forbid(unused_results)]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod c {
	pub(crate) type size_t = usize;
}

mod cpu;
mod digest;
mod endian;
mod error;
mod hmac;
mod polyfill;
mod rand;

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
