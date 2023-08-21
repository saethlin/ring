const ELEM_MAX_BITS: usize = 384;
const ELEM_MAX_BYTES: usize = (ELEM_MAX_BITS + 7) / 8;

pub const SCALAR_MAX_BYTES: usize = ELEM_MAX_BYTES;

pub const PKCS8_DOCUMENT_MAX_LEN: usize = 40 + SCALAR_MAX_BYTES + PUBLIC_KEY_MAX_LEN;

const PUBLIC_KEY_MAX_LEN: usize = 1 + (2 * ELEM_MAX_BYTES);

