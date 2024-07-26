#[derive(Clone, Copy)]
pub struct Index<const N: usize>(<Self as ValidIndex>::Type)
where
	Self: ValidIndex;

impl<const N: usize> Index<N>
where
	Self: ValidIndex,
{
	pub fn new(idx: usize) -> Self {
		assert!(idx <= N, "Index out of bounds!");
		unsafe { Self::new_unchecked(idx) }
	}
}

pub trait ValidIndex {
	type Type: Copy;

	unsafe fn new_unchecked(idx: usize) -> Self;
	fn get(self) -> usize;
}

impl ValidIndex for Index<1> {
	type Type = ();

	unsafe fn new_unchecked(_: usize) -> Self {
		Self(())
	}

	fn get(self) -> usize {
		0
	}
}

impl ValidIndex for Index<2> {
	type Type = bool;

	unsafe fn new_unchecked(idx: usize) -> Self {
		Self(match idx {
			0 => false,
			1 => true,
			_ => core::hint::unreachable_unchecked(),
		})
	}

	fn get(self) -> usize {
		0
	}
}

macro_rules! impls {
	( $ty:ty; $( $val: literal ),+ ) => {
		$(impl ValidIndex for Index<{ 2usize.pow( $val ) }> {
			type Type = $ty;

			unsafe fn new_unchecked(idx: usize) -> Self {
				Self(idx as _)
			}

			fn get(self) -> usize {
				self.0 as usize
			}
		})+
	};
}

impls!(u8; 2, 3, 4, 5, 6, 7, 8);
impls!(u16; 9, 10, 11, 12, 13, 14, 15, 16);
#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
impls!(u32; 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32);
#[cfg(any(target_pointer_width = "64"))]
impls!(u64; 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63);
