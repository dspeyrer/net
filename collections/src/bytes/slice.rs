use core::cell::Cell;
use core::mem::size_of;
use core::ptr::NonNull;
use core::slice;
use std::ops::{Deref, DerefMut};

use utils::bytes::{self, Cast};

use super::rc;

#[derive(Clone)]
pub struct Slice {
	/// The reference-counted allocation
	pub(crate) _alloc: rc::Alloc,
	/// A pointer within the allocation
	pub(crate) ptr: Cell<NonNull<u8>>,
	/// The length of the slice
	pub(crate) len: Cell<usize>,
}

impl Slice {
	pub fn new(len: usize) -> Self {
		let _alloc = rc::Alloc::zeroed(len);
		let ptr = _alloc.base_ptr();
		Self { _alloc, ptr: Cell::new(ptr), len: Cell::new(len) }
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
