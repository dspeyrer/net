use core::mem::{size_of, MaybeUninit};

use super::alloc::Alloc;

#[cfg(target_endian = "little")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Inline {
	tag: u8,
	bytes: [MaybeUninit<u8>; Self::CAPACITY],
}

#[cfg(target_endian = "big")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Inline {
	bytes: [u8; Self::CAPACITY],
	tag: u8,
}

impl Inline {
	const CAPACITY: usize = size_of::<Alloc>() - 1;

	#[inline]
	pub fn tag(&self) -> bool {
		self.tag & 0x1 == 1
	}

	#[inline]
	pub fn len(&self) -> usize {
		(self.tag >> 1) as _
	}

	/// Returns the number of uninitialised bytes remaining.
	#[inline]
	pub fn uninit_capacity(&self) -> usize {
		Inline::CAPACITY - self.len()
	}
}
