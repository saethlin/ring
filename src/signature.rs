use crate::{cpu, ec, error, sealed};

#[cfg(feature = "alloc")]
pub use crate::rsa::{
    signing::RsaKeyPair,
    signing::RsaSubjectPublicKey,

    verification::{
        RsaPublicKeyComponents, RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
        RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_3072_8192_SHA384,
        RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512,
    },

    RsaEncoding,
    RsaParameters,

    // `RSA_PKCS1_SHA1` is intentionally not exposed. At a minimum, we'd need
    // to create test vectors for signing with it, which we don't currently
    // have. But, it's a bad idea to use SHA-1 anyway, so perhaps we just won't
    // ever expose it.
    RSA_PKCS1_SHA256,
    RSA_PKCS1_SHA384,
    RSA_PKCS1_SHA512,

    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
};

/// A public key signature returned from a signing operation.
#[derive(Clone, Copy)]
pub struct Signature {
    value: [u8; MAX_LEN],
    len: usize,
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.value[..self.len]
    }
}

/// Key pairs for signing messages (private key and public key).
pub trait KeyPair: core::fmt::Debug + Send + Sized + Sync {
    /// The type of the public key.
    type PublicKey: AsRef<[u8]> + core::fmt::Debug + Clone + Send + Sized + Sync;

    /// The public key for the key pair.
    fn public_key(&self) -> &Self::PublicKey;
}

/// The longest signature is an ASN.1 P-384 signature where *r* and *s* are of
/// maximum length with the leading high bit set on each. Then each component
/// will have a tag, a one-byte length, and a one-byte “I'm not negative”
/// prefix, and the outer sequence will have a two-byte length.
pub(crate) const MAX_LEN: usize = 1/*tag:SEQUENCE*/ + 2/*len*/ +
    (2 * (1/*tag:INTEGER*/ + 1/*len*/ + 1/*zero*/ + ec::SCALAR_MAX_BYTES));

/// A signature verification algorithm.
pub trait VerificationAlgorithm: core::fmt::Debug + Sync + sealed::Sealed {
    /// Verify the signature `signature` of message `msg` with the public key
    /// `public_key`.
    fn verify(
        &self,
        public_key: untrusted::Input,
        msg: untrusted::Input,
        signature: untrusted::Input,
    ) -> Result<(), error::Unspecified>;
}

/// An unparsed, possibly malformed, public key for signature verification.
pub struct UnparsedPublicKey<B: AsRef<[u8]>> {
    algorithm: &'static dyn VerificationAlgorithm,
    bytes: B,
}

impl<B: Copy> Copy for UnparsedPublicKey<B> where B: AsRef<[u8]> {}

impl<B: Clone> Clone for UnparsedPublicKey<B>
where
    B: AsRef<[u8]>,
{
    fn clone(&self) -> Self {
        Self {
            algorithm: self.algorithm,
            bytes: self.bytes.clone(),
        }
    }
}

impl<B: AsRef<[u8]>> UnparsedPublicKey<B> {
    /// Construct a new `UnparsedPublicKey`.
    ///
    /// No validation of `bytes` is done until `verify()` is called.
    #[inline]
    pub fn new(algorithm: &'static dyn VerificationAlgorithm, bytes: B) -> Self {
        Self { algorithm, bytes }
    }

    /// Parses the public key and verifies `signature` is a valid signature of
    /// `message` using it.
    ///
    /// See the [crate::signature] module-level documentation for examples.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), error::Unspecified> {
        let _ = cpu::features();
        self.algorithm.verify(
            untrusted::Input::from(self.bytes.as_ref()),
            untrusted::Input::from(message),
            untrusted::Input::from(signature),
        )
    }
}
