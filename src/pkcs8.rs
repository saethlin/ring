// Copyright 2017 Brian Smith.
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

//! PKCS#8 is specified in [RFC 5958].
//!
//! [RFC 5958]: https://tools.ietf.org/html/rfc5958.

use crate::{ec, error, io::der};

pub(crate) enum Version {
    V1Only,
    V1OrV2,
    V2Only,
}

/// A template for constructing PKCS#8 documents.
///
/// Note that this only works for ECC.
pub(crate) struct Template {
    pub bytes: &'static [u8],

    // The range within `bytes` that holds the value (not including the tag and
    // length) for use in the PKCS#8 document's privateKeyAlgorithm field.
    pub alg_id_range: core::ops::Range<usize>,

    // `bytes[alg_id_range][curve_id_index..]` contains the OID identifying the,
    // curve, including the tag and length.
    pub curve_id_index: usize,

    // `bytes` will be split into two parts at `private_key_index`, where the
    // first part is written before the private key and the second part is
    // written after the private key. The public key is written after the second
    // part.
    pub private_key_index: usize,
}

/// Parses an unencrypted PKCS#8 private key, verifies that it is the right type
/// of key, and returns the key value.
///
/// `alg_id` must be the encoded value (not including the outermost `SEQUENCE`
/// tag and length) of the `AlgorithmIdentifier` that identifies the key type.
/// The result will be an encoded `RSAPrivateKey` or `ECPrivateKey` or similar.
///
/// PKCS#8 is specified in [RFC 5958].
///
/// [RFC 5958]: https://tools.ietf.org/html/rfc5958.
pub(crate) fn unwrap_key_<'a>(
    alg_id: untrusted::Input,
    version: Version,
    input: untrusted::Input<'a>,
) -> Result<(untrusted::Input<'a>, Option<untrusted::Input<'a>>), error::KeyRejected> {
    input.read_all(error::KeyRejected::invalid_encoding(), |input| {
        der::nested(
            input,
            der::Tag::Sequence,
            error::KeyRejected::invalid_encoding(),
            |input| unwrap_key__(alg_id, version, input),
        )
    })
}

fn unwrap_key__<'a>(
    alg_id: untrusted::Input,
    version: Version,
    input: &mut untrusted::Reader<'a>,
) -> Result<(untrusted::Input<'a>, Option<untrusted::Input<'a>>), error::KeyRejected> {
    let actual_version = der::small_nonnegative_integer(input)
        .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;

    // Do things in a specific order to return more useful errors:
    // 1. Check for completely unsupported version.
    // 2. Check for algorithm mismatch.
    // 3. Check for algorithm-specific version mismatch.

    if actual_version > 1 {
        return Err(error::KeyRejected::version_not_supported());
    };

    let actual_alg_id = der::expect_tag_and_get_value(input, der::Tag::Sequence)
        .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;
    if actual_alg_id != alg_id {
        return Err(error::KeyRejected::wrong_algorithm());
    }

    let require_public_key = match (actual_version, version) {
        (0, Version::V1Only) => false,
        (0, Version::V1OrV2) => false,
        (1, Version::V1OrV2) | (1, Version::V2Only) => true,
        _ => {
            return Err(error::KeyRejected::version_not_supported());
        }
    };

    let private_key = der::expect_tag_and_get_value(input, der::Tag::OctetString)
        .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;

    // Ignore any attributes that are present.
    if input.peek(der::Tag::ContextSpecificConstructed0 as u8) {
        let _ = der::expect_tag_and_get_value(input, der::Tag::ContextSpecificConstructed0)
            .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;
    }

    let public_key = if require_public_key {
        if input.at_end() {
            return Err(error::KeyRejected::public_key_is_missing());
        }
        let public_key = der::nested(
            input,
            der::Tag::ContextSpecificConstructed1,
            error::Unspecified,
            der::bit_string_with_no_unused_bits,
        )
        .map_err(|error::Unspecified| error::KeyRejected::invalid_encoding())?;
        Some(public_key)
    } else {
        None
    };

    Ok((private_key, public_key))
}

/// A generated PKCS#8 document.
pub struct Document {
    bytes: [u8; ec::PKCS8_DOCUMENT_MAX_LEN],
    len: usize,
}

impl AsRef<[u8]> for Document {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
