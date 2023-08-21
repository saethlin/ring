use crate::{digest, error, hkdf};

/// An HMAC algorithm.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Algorithm(&'static digest::Algorithm);

impl Algorithm {
    /// The digest algorithm this HMAC algorithm is based on.
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

impl Key {
    fn construct<F>(algorithm: Algorithm, fill: F) -> Result<Self, error::Unspecified>
    where
        F: FnOnce(&mut [u8]) -> Result<(), error::Unspecified>,
    {
        let mut key_bytes = [0; digest::MAX_OUTPUT_LEN];
        let key_bytes = &mut key_bytes[..algorithm.0.output_len];
        fill(key_bytes)?;
        Ok(Self::new(algorithm, key_bytes))
    }

    /// Construct an HMAC signing key using the given digest algorithm and key
    /// value.
    ///
    /// `key_value` should be a value generated using a secure random number
    /// generator (e.g. the `key_value` output by
    /// `SealingKey::generate_serializable()`) or derived from a random key by
    /// a key derivation function (e.g. `ring::hkdf`). In particular,
    /// `key_value` shouldn't be a password.
    ///
    /// As specified in RFC 2104, if `key_value` is shorter than the digest
    /// algorithm's block length (as returned by `digest::Algorithm::block_len`,
    /// not the digest length returned by `digest::Algorithm::output_len`) then
    /// it will be padded with zeros. Similarly, if it is longer than the block
    /// length then it will be compressed using the digest algorithm.
    ///
    /// You should not use keys larger than the `digest_alg.block_len` because
    /// the truncation described above reduces their strength to only
    /// `digest_alg.output_len * 8` bits. Support for such keys is likely to be
    /// removed in a future version of *ring*.
    pub fn new(algorithm: Algorithm, key_value: &[u8]) -> Self {
        let digest_alg = algorithm.0;
        let mut key = Self {
            inner: digest::BlockContext::new(digest_alg),
            outer: digest::BlockContext::new(digest_alg),
        };

        let key_hash;
        let key_value = if key_value.len() <= digest_alg.block_len {
            key_value
        } else {
            key_hash = digest::digest(digest_alg, key_value);
            key_hash.as_ref()
        };

        const IPAD: u8 = 0x36;

        let mut padded_key = [IPAD; digest::MAX_BLOCK_LEN];
        let padded_key = &mut padded_key[..digest_alg.block_len];

        // If the key is shorter than one block then we're supposed to act like
        // it is padded with zero bytes up to the block length. `x ^ 0 == x` so
        // we can just leave the trailing bytes of `padded_key` untouched.
        for (padded_key, key_value) in padded_key.iter_mut().zip(key_value.iter()) {
            *padded_key ^= *key_value;
        }
        key.inner.update(&padded_key);

        const OPAD: u8 = 0x5C;

        // Remove the `IPAD` masking, leaving the unmasked padded key, then
        // mask with `OPAD`, all in one step.
        for b in padded_key.iter_mut() {
            *b ^= IPAD ^ OPAD;
        }
        key.outer.update(&padded_key);

        key
    }

    /// The digest algorithm for the key.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm(self.inner.algorithm)
    }
}

impl hkdf::KeyType for Algorithm {
    fn len(&self) -> usize {
        self.digest_algorithm().output_len
    }
}

impl From<hkdf::Okm<'_, Algorithm>> for Key {
    fn from(okm: hkdf::Okm<Algorithm>) -> Self {
        Key::construct(*okm.len(), |buf| okm.fill(buf)).unwrap()
    }
}

/// A context for multi-step (Init-Update-Finish) HMAC signing.
///
/// Use `sign` for single-step HMAC signing.
#[derive(Clone)]
pub struct Context {
    inner: digest::Context,
    outer: digest::BlockContext,
}

impl Context {
    /// Constructs a new HMAC signing context using the given digest algorithm
    /// and key.
    pub fn with_key(signing_key: &Key) -> Self {
        Self {
            inner: digest::Context::clone_from(&signing_key.inner),
            outer: signing_key.outer.clone(),
        }
    }

    /// Updates the HMAC with all the data in `data`. `update` may be called
    /// zero or more times until `finish` is called.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes the HMAC calculation and returns the HMAC value. `sign`
    /// consumes the context so it cannot be (mis-)used after `sign` has been
    /// called.
    ///
    /// It is generally not safe to implement HMAC verification by comparing
    /// the return value of `sign` to a tag. Use `verify` for verification
    /// instead.
    pub fn sign(self) -> Tag {
        let algorithm = self.inner.algorithm();
        let mut pending = [0u8; digest::MAX_BLOCK_LEN];
        let pending = &mut pending[..algorithm.block_len];
        let num_pending = algorithm.output_len;
        pending[..num_pending].copy_from_slice(self.inner.finish().as_ref());
        Tag(self.outer.finish(pending, num_pending))
    }
}
