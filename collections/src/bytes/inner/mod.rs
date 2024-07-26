use core::mem::ManuallyDrop;

use self::alloc::Alloc;
use self::inline::Inline;

pub mod alloc;
pub mod inline;

pub union Core {
	alloc: ManuallyDrop<Alloc>,
	inline: Inline,
}

impl Core {
	/// Returns whether this `Core` is currently inlined.
	#[inline]
	fn is_inline(&self) -> bool {
		unsafe { self.inline.tag() }
	}

	/// Returns the number of uninitialised bytes remaining.
	#[inline]
	pub fn uninit_capacity(&self) -> usize {
		unsafe {
			if self.is_inline() {
				self.inline.uninit_capacity()
			} else {
				self.alloc.uninit_capacity()
			}
		}
	}
}

impl Drop for Core {
	fn drop(&mut self) {
		if !self.is_inline() {
			unsafe { ManuallyDrop::drop(&mut self.alloc) }
		}
	}
}
