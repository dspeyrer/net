use core::cell::Cell;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;
use std::alloc::{self, Layout};

/// A reference-counted memory block
#[repr(transparent)]
pub struct Alloc {
	/// A pointer to the beginning of the data
	ptr: NonNull<u8>,
}

/// Get the layout required to represent bytes of the specified length
unsafe fn layout(len: usize) -> Layout {
	Layout::from_size_align(size_of::<Meta>() + len, align_of::<Meta>()).unwrap()
}

impl Alloc {
	/// Create a new uninitialised allocation with the specified length
	pub fn uninit(len: usize) -> Self {
		unsafe {
			// The layout will never be zero-sized, since a `Meta` structure is always appended to the beginning of it.
			let ptr = alloc::alloc(layout(len));
			// The allocator API should never return a null pointer.
			Self::from_ptr(ptr, len)
		}
	}

	/// Create a new zeroed allocation with the specified length
	pub fn zeroed(len: usize) -> Self {
		unsafe {
			// The layout will never be zero-sized, since a `Meta` structure is always appended to the beginning of it.
			let ptr = alloc::alloc_zeroed(layout(len));
			// The allocator API should never return a null pointer.
			Self::from_ptr(ptr, len)
		}
	}

	/// Initialise an allocation's reference-counting block. `ptr` must be non-null.
	unsafe fn from_ptr(ptr: *mut u8, len: usize) -> Self {
		unsafe {
			// `ptr` must be non-null.
			let ptr = NonNull::new_unchecked(ptr);
			// Write in the allocation length and initial reference count, which is 1.
			ptr.cast::<Meta>().write(Meta { rc: Cell::new(1), len });
			// Return a new instance pointing to the data section of the allocation.
			Self { ptr: ptr.add(size_of::<Meta>()) }
		}
	}

	/// Returns the base data pointer. It will be valid for whatever `len` value was passed when it was created.
	pub fn base_ptr(&self) -> NonNull<u8> {
		self.ptr
	}

	/// Get a pointer to the reference counting block
	unsafe fn meta_ptr(&self) -> NonNull<Meta> {
		self.ptr.sub(size_of::<Meta>()).cast()
	}
}

impl Clone for Alloc {
	/// Increment the reference count on this block
	fn clone(&self) -> Self {
		// Get a reference to the reference counting block
		let Meta { rc, .. } = unsafe { self.meta_ptr().as_ref() };
		// Increment the reference count
		rc.set(rc.get() + 1);
		// Duplicate the pointer
		Self { ptr: self.ptr }
	}
}

impl Drop for Alloc {
	fn drop(&mut self) {
		// Get a pointer to the reference counting block
		let ptr = unsafe { self.meta_ptr() };
		// Get a reference to that pointer
		let Meta { rc, len } = unsafe { ptr.as_ref() };

		// Decrement the reference count by one
		let cnt = rc.get() - 1;

		if cnt == 0 {
			// Deallocate the buffer if there are no remaining references to it
			unsafe { std::alloc::dealloc(ptr.as_ptr() as _, layout(*len)) };
		} else {
			// Set the new reference count
			rc.set(cnt);
		}
	}
}

struct Meta {
	/// The number of references to this memory block.
	rc: Cell<usize>,
	/// The number of bytes in this allocation after the end of the [Meta] section.
	len: usize,
}
