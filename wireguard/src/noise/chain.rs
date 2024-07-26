use core::iter;

use blake2::digest::FixedOutput;
use blake2::Blake2s256;
use hmac::Mac;
use utils::bytes::{self, Cast};

use super::A32;

type Hmac = hmac::SimpleHmac<Blake2s256>;

const CHAIN_INITIAL: [u8; 32] = [
	0x60, 0xe2, 0x6d, 0xae, 0xf3, 0x27, 0xef, 0xc0, 0x2e, 0xc3, 0x35, 0xe2, 0xa0, 0x25, 0xd2, 0xd0, 0x16, 0xeb, 0x42, 0x06, 0xf8, 0x72, 0x77, 0xf5,
	0x2d, 0x38, 0xd1, 0x98, 0x8b, 0x78, 0xcd, 0x36,
];

#[derive(Clone)]
pub struct Chain(A32);

impl Chain {
	#[inline]
	pub fn write(&mut self, input: &impl Cast) {
		let [] = self.kdf(input);
	}

	#[inline]
	pub fn consume(mut self) -> (A32, A32) {
		let [t1] = self.kdf(&());
		(self.0, t1)
	}

	#[inline]
	#[must_use]
	pub fn kdf<const N: usize>(&mut self, input: &impl Cast) -> [A32; N] {
		let mut hasher = Hmac::new_from_slice(&self.0).unwrap();
		hasher.update(bytes::as_slice(input));
		let t0 = hasher.finalize_fixed();

		let mut t = [A32::default(); N];

		iter::once(&mut self.0).chain(t.iter_mut()).zip(1..).fold([].as_slice(), |i, (t, n)| {
			let mut core = Hmac::new_from_slice(&t0).unwrap();

			core.update(i);
			core.update(&[n]);

			core.finalize_into(t);

			t.as_slice()
		});

		t
	}
}

impl Default for Chain {
	fn default() -> Self {
		Self(CHAIN_INITIAL.into())
	}
}
