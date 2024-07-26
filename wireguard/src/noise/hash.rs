use blake2::digest::{FixedOutput, Update};
use blake2::Blake2s256;
use utils::bytes::{self, Cast};

use super::A32;

const INITIAL: [u8; 32] = [
	0x22, 0x11, 0xb3, 0x61, 0x08, 0x1a, 0xc5, 0x66, 0x69, 0x12, 0x43, 0xdb, 0x45, 0x8a, 0xd5, 0x32, 0x2d, 0x9c, 0x6c, 0x66, 0x22, 0x93, 0xe8, 0xb7,
	0x0e, 0xe1, 0x9c, 0x65, 0xba, 0x07, 0x9e, 0xf3,
];

#[derive(Clone)]
pub struct Hash(pub(super) A32);

impl Hash {
	#[inline]
	pub fn update(&mut self, data: &impl Cast) {
		let mut core = Blake2s256::default();
		core.update(&self.0);
		core.update(bytes::as_slice(data));
		core.finalize_into(&mut self.0);
	}
}

impl From<A32> for Hash {
	fn from(hash: A32) -> Self {
		Self(hash)
	}
}

impl Default for Hash {
	#[inline]
	fn default() -> Self {
		A32::from(INITIAL).into()
	}
}
