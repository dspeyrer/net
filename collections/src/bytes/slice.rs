use core::cell::Cell;
use core::mem::size_of;
use core::ptr::NonNull;
use core::slice;
use std::ops::{Deref, DerefMut};

use utils::bytes::{self, Cast};

use core::mem::align_of;
use std::alloc::{self, Layout};


/// Get the layout required to represent bytes of the specified length
unsafe fn layout(len: usize) -> Layout {
	Layout::from_size_align(size_of::<Meta>() + len, align_of::<Meta>()).unwrap()
}

struct Meta {
	/// The number of bytes in this allocation after the end of the [Meta] section.
	len: usize,
}


pub struct Slice {
	/// A pointer to the allocation base
	mta: NonNull<Meta>,
	/// A pointer within the allocation
	ptr: Cell<NonNull<u8>>,
	/// The length of the slice
	len: Cell<usize>,
}

impl Slice {
	pub fn new(len: usize) -> Self {
		unsafe {
			// The layout will never be zero-sized, since a `Meta` structure is always appended to the beginning of it.
			let acn = alloc::alloc_zeroed(layout(len));
			// The allocator API should never return a null pointer.
			let acn = NonNull::new_unchecked(acn).cast::<Meta>();
			// Write in the allocation length and initial reference count, which is 1.
			acn.write(Meta { len });
			// Get the base data pointer.
			let ptr = acn.add(1).cast::<u8>();
			// Construct the slice.
			Self { mta: acn, ptr: Cell::new(ptr), len: Cell::new(len) }
		}
	}

	pub fn split_max(&self, mut n: usize) -> &[u8] {
		if n > self.len() {
			n = self.len();
		}

		let ptr = self.ptr.get();

		self.ptr.set(unsafe { ptr.add(n) });
		self.len.set(self.len() - n);

		unsafe { slice::from_raw_parts(ptr.as_ptr(), n) }
	}

	pub fn split_bytes(&self, n: usize) -> &[u8] {
		assert!(n <= self.len());

		let ptr = self.ptr.get();

		self.ptr.set(unsafe { ptr.add(n) });
		self.len.set(self.len() - n);

		unsafe { slice::from_raw_parts(ptr.as_ptr(), n) }
	}

	pub fn rsplit_bytes(&self, n: usize) -> &[u8] {
		let new_len = self.len().checked_sub(n).unwrap();

		self.len.set(new_len);
		let ptr = unsafe { self.ptr.get().add(new_len) };

		unsafe { slice::from_raw_parts(ptr.as_ptr(), n) }
	}

	pub fn split_n<T: Cast>(&self, n: usize) -> &[T] {
		bytes::as_slice(self.split_bytes(n * size_of::<T>()))
	}

	pub fn split<T: Cast>(&self) -> &T {
		bytes::cast(self.split_bytes(size_of::<T>()))
	}

	pub fn rsplit<T: Cast>(&self) -> &T {
		bytes::cast(self.rsplit_bytes(size_of::<T>()))
	}

	pub fn truncate(&self, len: usize) {
		assert!(len <= self.len());
		self.len.set(len);
	}
}

impl Drop for Slice {
	fn drop(&mut self) {
		// Get the length of the allocation
		let Meta { len } = unsafe { self.mta.read() };
		// Deallocate the buffer
		unsafe { std::alloc::dealloc(self.mta.as_ptr() as _, layout(len)) };
	}
}

impl Deref for Slice {
	type Target = [u8];

	#[inline]
	fn deref(&self) -> &Self::Target {
		unsafe { slice::from_raw_parts(self.ptr.get().as_ptr(), self.len.get()) }
	}
}

impl DerefMut for Slice {
	#[inline]
	fn deref_mut(&mut self) -> &mut Self::Target {
		unsafe { slice::from_raw_parts_mut(self.ptr.get().as_ptr(), self.len.get()) }
	}
}
