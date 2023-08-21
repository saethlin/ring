use crate::{error, hmac};

#[derive(Clone, Copy, Eq, PartialEq)]
struct Algorithm(hmac::Algorithm);

impl KeyType for Algorithm {
    fn len(&self) -> usize {
        self.0.digest_algorithm().output_len
    }
}

pub trait KeyType {
    fn len(&self) -> usize;
}

struct Prk(hmac::Key);

pub struct Okm<'a, L: KeyType> {
    prk: &'a Prk,
    info: &'a [&'a [u8]],
    len: L,
    len_cached: usize,
}

impl<L: KeyType> Okm<'_, L> {
    #[inline]
    pub fn len(&self) -> &L {
        &self.len
    }

    #[inline]
    pub fn fill(self, out: &mut [u8]) -> Result<(), error::Unspecified> {
        fill_okm(self.prk, self.info, out, self.len_cached)
    }
}

fn fill_okm(
    prk: &Prk,
    info: &[&[u8]],
    out: &mut [u8],
    len: usize,
) -> Result<(), error::Unspecified> {
    if out.len() != len {
        return Err(error::Unspecified);
    }

    let digest_alg = prk.0.algorithm().digest_algorithm();
    assert!(digest_alg.block_len >= digest_alg.output_len);

    let mut ctx = hmac::Context::with_key(&prk.0);

    let mut n = 1u8;
    let mut out = out;
    loop {
        for info in info {
            ctx.update(info);
        }
        ctx.update(&[n]);

        let t = ctx.sign();
        let t = t.as_ref();

        // Append `t` to the output.
        out = if out.len() < digest_alg.output_len {
            let len = out.len();
            out.copy_from_slice(&t[..len]);
            &mut []
        } else {
            let (this_chunk, rest) = out.split_at_mut(digest_alg.output_len);
            this_chunk.copy_from_slice(t);
            rest
        };

        if out.is_empty() {
            return Ok(());
        }

        ctx = hmac::Context::with_key(&prk.0);
        ctx.update(t);
        n = n.checked_add(1).unwrap();
    }
}
