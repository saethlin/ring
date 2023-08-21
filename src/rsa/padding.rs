use crate::{digest};

pub struct PKCS1 {
    pub digest_alg: &'static digest::Algorithm,
    pub digestinfo_prefix: &'static [u8],
}

pub struct PSS {
    digest_alg: &'static digest::Algorithm,
}
