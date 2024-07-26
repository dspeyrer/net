use core::mem::size_of;
use std::ops::{Deref, DerefMut};

use utils::bytes::{self, Cast};

/// A utility structure for mutating byteslices.
pub struct Cursor<'a> {
	/// The underlying buffer
	slice: &'a mut [u8],
	/// A pointer within `slice`
	pivot: &'a mut usize,
}

impl<'a> Cursor<'a> {
	pub fn vec<X>(vec: &mut Vec<u8>, f: impl FnOnce(Cursor) -> X) -> X {
		let mut ptr = vec.as_ptr() as usize;
		let t = f(Cursor { slice: vec, pivot: &mut ptr });
		vec.truncate(ptr - vec.as_ptr() as usize);
		t
	}

	/// Gets the index of the pivot position within the slice.
	#[inline]
	pub fn pivot(&self) -> usize {
		*self.pivot - self.slice.as_ptr() as usize
	}

	/// Pushes an object to the buffer, advancing the pivot.
	pub fn push<T: Cast + ?Sized>(self, t: &T) -> Self {
		let bytes = bytes::as_slice(t);

		let (l, r) = self.slice.split_at_mut(bytes.len());
		*self.pivot = r.as_ptr() as usize;

		l.copy_from_slice(bytes);

		Self { slice: r, pivot: self.pivot }
	}

	/// Byte-casts the buffer into a reference to a type, advancing pivot to the end of the new type reference.
	#[inline]
	pub fn cast<T: Cast>(self) -> &'a mut T {
		*self.pivot = self.slice.as_ptr() as usize + size_of::<T>();
		bytes::cast_mut(self.slice)
	}

	/// Splits off a reference to a type, returning the rest, and advancing the pivot to the start of the new buffer.
	#[inline]
	pub fn split<T: Cast>(self) -> (&'a mut T, Self) {
		let (l, r) = self.slice.split_at_mut(size_of::<T>());
		*self.pivot = r.as_ptr() as usize;
		(bytes::cast_mut(l), Self { slice: r, pivot: self.pivot })
	}

	/// Splits off an instance of a type after the pivot point, returning the preceding buffer, and advancing the pivot to the end of the current buffer.
	#[inline]
	pub fn rsplit<T: Cast>(self) -> (Self, &'a mut T) {
		let (l, r) = self.slice.split_at_mut(self.pivot());
		*self.pivot = r.as_ptr() as usize + size_of::<T>();
		(Cursor { slice: l, pivot: self.pivot }, bytes::cast_mut(r))
	}

	/// Returns a new `Buffer` limited to `len` bytes.
	#[inline]
	pub fn lim(&mut self, len: usize) -> Cursor {
		Cursor { slice: &mut self.slice[..len], pivot: self.pivot }
	}

	/// Returns a new `Buffer` limited to `len` bytes less than the total buffer size.
	#[inline]
	pub fn rlim(&mut self, len: usize) -> Cursor {
		let idx = self.slice.len() - len;
		Cursor { slice: &mut self.slice[..idx], pivot: self.pivot }
	}

	/// Pads from `pivot` to the nearest offset of `n` from the start of the buffer with 0s, advancing the pivot.
	#[inline]
	pub fn pad_to(&mut self, n: usize) {
		let pivot = self.pivot();

		let rem = (n - pivot % n) % n;

		self.slice[pivot..][..rem].fill(0);
		*self.pivot += rem;
	}

	/// Returns a reference to a new buffer which shares a pivot point.
	#[inline]
	pub fn fork(&mut self) -> Cursor {
		Cursor { slice: self.slice, pivot: self.pivot }
	}
}

impl<'a> Deref for Cursor<'a> {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		self.slice
	}
}

impl<'a> DerefMut for Cursor<'a> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		self.slice
	}
}
