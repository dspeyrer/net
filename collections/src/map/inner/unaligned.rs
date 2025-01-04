use core::mem::MaybeUninit;
use core::ptr;

type Word = u64;

const MIRROR: usize = core::mem::size_of::<Word>() - 1;

#[repr(C, align(8))]
struct Control<const N: usize> {
	_align: [Word; 0],
	bytes: [u8; N],
	wrap: [u8; MIRROR],
}

impl<const N: usize> Control<N> {
	#[inline]
	unsafe fn is_full(&self, n: usize) -> bool {
		self.bytes.get_unchecked(n) & 0x80 == 0
	}

	#[inline]
	unsafe fn is_empty(&self, n: usize) -> bool {
		*self.bytes.get_unchecked(n) == 0
	}

	#[inline]
	unsafe fn group(&self, n: usize) -> Word {
		ptr::read_unaligned(self.bytes.as_ptr().add(n).cast::<Word>())
	}

	#[inline]
	unsafe fn set(&mut self, n: usize, b: u8) {
		*self.bytes.get_unchecked_mut(n) = b;

		if n < MIRROR {
			self.set_wrap(n, b);
		}
	}

	#[cold]
	#[inline]
	unsafe fn set_wrap(&mut self, n: usize, b: u8) {
		*self.wrap.get_unchecked_mut(n) = b;
	}
}

impl<const N: usize> Default for Control<N> {
	fn default() -> Self {
		Self { _align: [], bytes: [0; N], wrap: [0; MIRROR] }
	}
}

pub struct Core<T, const N: usize> {
	slot: [MaybeUninit<T>; N],
	ctrl: Control<N>,
}

impl<T, const N: usize> Core<T, N> {}

impl<T, const N: usize> Default for Core<T, N> {
	fn default() -> Self {
		Self {
			slot: unsafe { MaybeUninit::uninit().assume_init() },
			ctrl: Control::default(),
		}
	}
}
