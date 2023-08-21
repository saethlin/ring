use crate::{digest, error};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Algorithm(&'static digest::Algorithm);

impl Algorithm {
    #[inline]
    pub fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.0
    }
}

#[derive(Clone, Copy)]
pub struct Tag(digest::Digest);

impl AsRef<[u8]> for Tag {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A key to use for HMAC signing.
#[derive(Clone)]
pub struct Key {
    inner: digest::BlockContext,
    outer: digest::BlockContext,
}

/// A context for multi-step (Init-Update-Finish) HMAC signing.
///
/// Use `sign` for single-step HMAC signing.
#[derive(Clone)]
pub struct Context {
    inner: digest::Context,
    outer: digest::BlockContext,
}
