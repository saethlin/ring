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

// *R* and *r* in Montgomery math refer to different things, so we always use
// `R` to refer to *R* to avoid confusion, even when that's against the normal
// naming conventions. Also the standard camelCase names are used for `KeyPair`
// components.

/// RSA signatures.
use crate::{arithmetic::bigint, limb};

pub mod padding;

// Maximum RSA modulus size supported for signature verification (in bytes).
const PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN: usize = bigint::MODULUS_MAX_LIMBS * limb::LIMB_BYTES;
