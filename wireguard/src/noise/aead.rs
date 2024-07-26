use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305 as Aead, KeyInit, Tag};
use log::warn;
use utils::bytes;
use utils::bytes::Cast;
use utils::error::*;

use super::{Hash, A32};

#[derive(Cast)]
#[repr(C)]
pub struct Sealed<T: Cast>(T, Tag);

impl<T: Cast> Sealed<T>
where
	Self: Cast,
{
	#[inline]
	pub fn open<'a>(&'a mut self, key: &A32, hash: &mut Hash) -> Result<&'a T> {
		let aad = hash.0;
		hash.update(self);

		Aead::new(key)
			.decrypt_in_place_detached(&Default::default(), &aad, bytes::as_slice_mut(&mut self.0), &self.1)
			.map_err(|_| warn!("Failed to decrypt packet payload"))?;

		Ok(&self.0)
	}

	#[inline]
	pub fn seal(&mut self, t: T, key: &A32, aad: &mut Hash) {
		self.0 = t;
		self.1 = Aead::new(key)
			.encrypt_in_place_detached(&Default::default(), &aad.0, bytes::as_slice_mut(&mut self.0))
			.expect("Sealing data failed");
		aad.update(self);
	}
}
