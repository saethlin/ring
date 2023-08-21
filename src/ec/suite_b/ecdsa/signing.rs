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

//! ECDSA Signatures using the P-256 and P-384 curves.

use crate::{
    arithmetic::montgomery::*,
    digest,
    ec::{
        self,
        suite_b::{ops::*},
    },
    error,
    io::der,
    limb, pkcs8, rand, sealed, signature,
};
/// An ECDSA signing algorithm.
pub struct EcdsaSigningAlgorithm {
    curve: &'static ec::Curve,
    private_scalar_ops: &'static PrivateScalarOps,
    private_key_ops: &'static PrivateKeyOps,
    digest_alg: &'static digest::Algorithm,
    pkcs8_template: &'static pkcs8::Template,
    format_rs: fn(ops: &'static ScalarOps, r: &Scalar, s: &Scalar, out: &mut [u8]) -> usize,
    id: AlgorithmID,
}

#[derive(Debug, Eq, PartialEq)]
enum AlgorithmID {
    ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
    ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING,
}

derive_debug_via_id!(EcdsaSigningAlgorithm);

impl PartialEq for EcdsaSigningAlgorithm {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for EcdsaSigningAlgorithm {}

impl sealed::Sealed for EcdsaSigningAlgorithm {}

/// An ECDSA key pair, used for signing.
pub struct EcdsaKeyPair {
    d: Scalar<R>,
    nonce_key: NonceRandomKey,
    alg: &'static EcdsaSigningAlgorithm,
    public_key: PublicKey,
}

derive_debug_via_field!(EcdsaKeyPair, stringify!(EcdsaKeyPair), public_key);

/// Generates an ECDSA nonce in a way that attempts to protect against a faulty
/// `SecureRandom`.
struct NonceRandom<'a> {
    key: &'a NonceRandomKey,
    message_digest: &'a digest::Digest,
    rng: &'a dyn rand::SecureRandom,
}

impl core::fmt::Debug for NonceRandom<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NonceRandom").finish()
    }
}

impl rand::sealed::SecureRandom for NonceRandom<'_> {
    fn fill_impl(&self, dest: &mut [u8]) -> Result<(), error::Unspecified> {
        // Use the same digest algorithm that will be used to digest the
        // message. The digest algorithm's output is exactly the right size;
        // this is checked below.
        //
        // XXX(perf): The single iteration will require two digest block
        // operations because the amount of data digested is larger than one
        // block.
        let digest_alg = self.key.0.algorithm();
        let mut ctx = digest::Context::new(digest_alg);

        // Digest the randomized digest of the private key.
        let key = self.key.0.as_ref();
        ctx.update(key);

        // The random value is digested between the key and the message so that
        // the key and the message are not directly digested in the same digest
        // block.
        assert!(key.len() <= digest_alg.block_len / 2);
        {
            let mut rand = [0u8; digest::MAX_BLOCK_LEN];
            let rand = &mut rand[..digest_alg.block_len - key.len()];
            assert!(rand.len() >= dest.len());
            self.rng.fill(rand)?;
            ctx.update(rand);
        }

        ctx.update(self.message_digest.as_ref());

        let nonce = ctx.finish();

        // `copy_from_slice()` panics if the lengths differ, so we don't have
        // to separately assert that the lengths are the same.
        dest.copy_from_slice(nonce.as_ref());

        Ok(())
    }
}

impl<'a> sealed::Sealed for NonceRandom<'a> {}

struct NonceRandomKey(digest::Digest);

impl NonceRandomKey {
    fn new(
        alg: &EcdsaSigningAlgorithm,
        seed: &ec::Seed,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::KeyRejected> {
        let mut rand = [0; digest::MAX_OUTPUT_LEN];
        let rand = &mut rand[0..alg.curve.elem_scalar_seed_len];

        // XXX: `KeyRejected` isn't the right way to model  failure of the RNG,
        // but to fix that we'd need to break the API by changing the result type.
        // TODO: Fix the API in the next breaking release.
        rng.fill(rand)
            .map_err(|error::Unspecified| error::KeyRejected::rng_failed())?;

        let mut ctx = digest::Context::new(alg.digest_alg);
        ctx.update(rand);
        ctx.update(seed.bytes_less_safe());
        Ok(NonceRandomKey(ctx.finish()))
    }
}

impl signature::KeyPair for EcdsaKeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

#[derive(Clone, Copy)]
pub struct PublicKey(ec::PublicKey);

derive_debug_self_as_ref_hex_bytes!(PublicKey);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

fn format_rs_fixed(ops: &'static ScalarOps, r: &Scalar, s: &Scalar, out: &mut [u8]) -> usize {
    let scalar_len = ops.scalar_bytes_len();

    let (r_out, rest) = out.split_at_mut(scalar_len);
    limb::big_endian_from_limbs(&r.limbs[..ops.common.num_limbs], r_out);

    let (s_out, _) = rest.split_at_mut(scalar_len);
    limb::big_endian_from_limbs(&s.limbs[..ops.common.num_limbs], s_out);

    2 * scalar_len
}

fn format_rs_asn1(ops: &'static ScalarOps, r: &Scalar, s: &Scalar, out: &mut [u8]) -> usize {
    // This assumes `a` is not zero since neither `r` or `s` is allowed to be
    // zero.
    fn format_integer_tlv(ops: &ScalarOps, a: &Scalar, out: &mut [u8]) -> usize {
        let mut fixed = [0u8; ec::SCALAR_MAX_BYTES + 1];
        let fixed = &mut fixed[..(ops.scalar_bytes_len() + 1)];
        limb::big_endian_from_limbs(&a.limbs[..ops.common.num_limbs], &mut fixed[1..]);

        // Since `a_fixed_out` is an extra byte long, it is guaranteed to start
        // with a zero.
        debug_assert_eq!(fixed[0], 0);

        // There must be at least one non-zero byte since `a` isn't zero.
        let first_index = fixed.iter().position(|b| *b != 0).unwrap();

        // If the first byte has its high bit set, it needs to be prefixed with 0x00.
        let first_index = if fixed[first_index] & 0x80 != 0 {
            first_index - 1
        } else {
            first_index
        };
        let value = &fixed[first_index..];

        out[0] = der::Tag::Integer as u8;

        // Lengths less than 128 are encoded in one byte.
        assert!(value.len() < 128);
        out[1] = value.len() as u8;

        out[2..][..value.len()].copy_from_slice(&value);

        2 + value.len()
    }

    out[0] = der::Tag::Sequence as u8;
    let r_tlv_len = format_integer_tlv(ops, r, &mut out[2..]);
    let s_tlv_len = format_integer_tlv(ops, s, &mut out[2..][r_tlv_len..]);

    // Lengths less than 128 are encoded in one byte.
    let value_len = r_tlv_len + s_tlv_len;
    assert!(value_len < 128);
    out[1] = value_len as u8;

    2 + value_len
}

static EC_PUBLIC_KEY_P256_PKCS8_V1_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes!("ecPublicKey_p256_pkcs8_v1_template.der"),
    alg_id_range: core::ops::Range { start: 8, end: 27 },
    curve_id_index: 9,
    private_key_index: 0x24,
};

static EC_PUBLIC_KEY_P384_PKCS8_V1_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes!("ecPublicKey_p384_pkcs8_v1_template.der"),
    alg_id_range: core::ops::Range { start: 8, end: 24 },
    curve_id_index: 9,
    private_key_index: 0x23,
};

#[cfg(test)]
mod tests {
    use crate::{signature, test};

    #[test]
    fn signature_ecdsa_sign_fixed_test() {
        test::run(
            test_file!("ecdsa_sign_fixed_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let curve_name = test_case.consume_string("Curve");
                let digest_name = test_case.consume_string("Digest");
                let msg = test_case.consume_bytes("Msg");
                let d = test_case.consume_bytes("d");
                let q = test_case.consume_bytes("Q");
                let k = test_case.consume_bytes("k");

                let expected_result = test_case.consume_bytes("Sig");

                let alg = match (curve_name.as_str(), digest_name.as_str()) {
                    ("P-256", "SHA256") => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    ("P-384", "SHA384") => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                    _ => {
                        panic!("Unsupported curve+digest: {}+{}", curve_name, digest_name);
                    }
                };

                let private_key =
                    signature::EcdsaKeyPair::from_private_key_and_public_key(alg, &d, &q).unwrap();
                let rng = test::rand::FixedSliceRandom { bytes: &k };

                let actual_result = private_key
                    .sign_with_fixed_nonce_during_test(&rng, &msg)
                    .unwrap();

                assert_eq!(actual_result.as_ref(), &expected_result[..]);

                Ok(())
            },
        );
    }

    #[test]
    fn signature_ecdsa_sign_asn1_test() {
        test::run(
            test_file!("ecdsa_sign_asn1_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");

                let curve_name = test_case.consume_string("Curve");
                let digest_name = test_case.consume_string("Digest");
                let msg = test_case.consume_bytes("Msg");
                let d = test_case.consume_bytes("d");
                let q = test_case.consume_bytes("Q");
                let k = test_case.consume_bytes("k");

                let expected_result = test_case.consume_bytes("Sig");

                let alg = match (curve_name.as_str(), digest_name.as_str()) {
                    ("P-256", "SHA256") => &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    ("P-384", "SHA384") => &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    _ => {
                        panic!("Unsupported curve+digest: {}+{}", curve_name, digest_name);
                    }
                };

                let private_key =
                    signature::EcdsaKeyPair::from_private_key_and_public_key(alg, &d, &q).unwrap();
                let rng = test::rand::FixedSliceRandom { bytes: &k };

                let actual_result = private_key
                    .sign_with_fixed_nonce_during_test(&rng, &msg)
                    .unwrap();

                assert_eq!(actual_result.as_ref(), &expected_result[..]);

                Ok(())
            },
        );
    }
}
