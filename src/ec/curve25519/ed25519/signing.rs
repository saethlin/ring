use super::{super::ops::*, ED25519_PUBLIC_KEY_LEN};
use crate::{
    digest, error,
    io::der,
    pkcs8,
    signature::{self},
};

/// An Ed25519 key pair, for signing.
pub struct Ed25519KeyPair {
    // RFC 8032 Section 5.1.6 calls this *s*.
    private_scalar: Scalar,

    // RFC 8032 Section 5.1.6 calls this *prefix*.
    private_prefix: Prefix,

    // RFC 8032 Section 5.1.5 calls this *A*.
    public_key: PublicKey,
}

derive_debug_via_field!(Ed25519KeyPair, stringify!(Ed25519KeyPair), public_key);

impl signature::KeyPair for Ed25519KeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

#[derive(Clone, Copy)]
pub struct PublicKey([u8; ED25519_PUBLIC_KEY_LEN]);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

derive_debug_self_as_ref_hex_bytes!(PublicKey);

extern "C" {
    fn GFp_x25519_ge_scalarmult_base(h: &mut ExtPoint, a: &Scalar);
}

type Prefix = [u8; PREFIX_LEN];
const PREFIX_LEN: usize = digest::SHA512_OUTPUT_LEN - SCALAR_LEN;

const SIGNATURE_LEN: usize = ELEM_LEN + SCALAR_LEN;

type Seed = [u8; SEED_LEN];
const SEED_LEN: usize = 32;

static PKCS8_TEMPLATE: pkcs8::Template = pkcs8::Template {
    bytes: include_bytes!("ed25519_pkcs8_v2_template.der"),
    alg_id_range: core::ops::Range { start: 7, end: 12 },
    curve_id_index: 0,
    private_key_index: 0x10,
};
