use core::cell::Cell;
use core::ops::{Bound, Deref, DerefMut, RangeBounds};
use core::slice;

use super::{rc, Slice};

#[derive(Clone)]
pub struct Bytes {
	/// A pointer to the allocation
	ptr: rc::Alloc,
	/// The length of the allocation
	len: usize,
}

impl Bytes {
	/// Construct a new `Bytes` with the specified length.
	pub fn new(len: usize) -> Self {
		Self { ptr: rc::Alloc::zeroed(len), len }
	}

	/// Create a reference-counted subslice of the `Bytes` instance.
	pub fn slice(&self, range: impl RangeBounds<usize>) -> Slice {
		let start = match range.start_bound() {
			Bound::Unbounded => 0,
			Bound::Included(&n) => n,
			Bound::Excluded(&n) => n + 1,
		};

		let end = match range.end_bound() {
			Bound::Unbounded => self.len,
			Bound::Included(&n) => n + 1,
			Bound::Excluded(&n) => n,
		};

		let _alloc = self.ptr.clone();
		let base = _alloc.base_ptr();

		unsafe {
			Slice {
				_alloc,
				ptr: Cell::new(base.add(start)),
				len: Cell::new(end - start),
			}
		}
	}
}

impl Deref for Bytes {
	type Target = [u8];

	#[inline]
	fn deref(&self) -> &Self::Target {
		unsafe { slice::from_raw_parts(self.ptr.base_ptr().as_ptr(), self.len) }
	}
}

impl DerefMut for Bytes {
	#[inline]
	fn deref_mut(&mut self) -> &mut Self::Target {
		unsafe { slice::from_raw_parts_mut(self.ptr.base_ptr().as_ptr(), self.len) }
	}
}
