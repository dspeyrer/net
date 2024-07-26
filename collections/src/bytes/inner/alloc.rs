use core::alloc::Layout;
use core::cell::Cell;
use core::mem::align_of;
use core::ptr::NonNull;

#[cfg(target_endian = "little")]
#[repr(C)]
pub struct Alloc {
	ptr: NonNull<u8>,
	len: usize,
	end: NonNull<Meta>,
}

#[cfg(target_endian = "big")]
#[repr(C)]
struct Alloc {
	end: NonNull<Meta>,
	len: usize,
	ptr: NonNull<u8>,
}

impl Alloc {
	/// Returns the number of uninitialised bytes remaining.
	#[inline]
	pub fn uninit_capacity(&self) -> usize {
		unsafe { self.end.cast::<u8>().sub_ptr(self.ptr) }
	}
}

impl Drop for Alloc {
	fn drop(&mut self) {
		unsafe { Meta::drop(self.end) }
	}
}

#[repr(align(2))]
struct Meta {
	rc: Cell<usize>,
	capacity: usize,
}

impl Meta {
	const ALIGN: usize = align_of::<Meta>();

	unsafe fn drop(ptr: NonNull<Self>) {
		let this = ptr.as_ref();

		let cnt = this.rc.get() - 1;

		if cnt != 0 {
			this.rc.set(cnt);
			return;
		}

		let cap = this.capacity;

		let head = ptr.cast::<u8>().sub(cap).as_ptr();
		let layout = Layout::from_size_align_unchecked(cap, Self::ALIGN);

		std::alloc::dealloc(head, layout);
	}
}
