use core::mem::{self, MaybeUninit};

enum Slot<A, B> {
	A(A),
	B(B),
}

macro_rules! assume {
	($assumed:ident, $slot:expr) => {
		match $slot {
			Slot::$assumed(x) => x,
			_ => core::hint::unreachable_unchecked(),
		}
	};
}

pub struct Core<A, B, const N: usize> {
	arr: [Slot<A, B>; N],
}

impl<A, B, const N: usize> Core<A, B, N> {
	pub fn new(f: impl Fn(usize) -> B) -> Self {
		let mut arr = MaybeUninit::uninit();

		let ptr = arr.as_mut_ptr() as *mut Slot<A, B>;

		for i in 0..N {
			unsafe { ptr.add(i).write(Slot::B(f(i))) }
		}

		Self { arr: unsafe { arr.assume_init() } }
	}

	pub unsafe fn is_a(&self, idx: usize) -> bool {
		match self.arr.get_unchecked(idx) {
			Slot::A(_) => true,
			Slot::B(_) => false,
		}
	}

	pub unsafe fn take_a(&mut self, idx: usize, b: B) -> A {
		assume!(A, mem::replace(self.arr.get_unchecked_mut(idx), Slot::B(b)))
	}

	pub unsafe fn get_a(&self, idx: usize) -> &A {
		assume!(A, self.arr.get_unchecked(idx))
	}

	pub unsafe fn get_a_mut(&mut self, idx: usize) -> &mut A {
		assume!(A, self.arr.get_unchecked_mut(idx))
	}

	pub unsafe fn take_b(&mut self, idx: usize, a: A) -> B {
		assume!(B, mem::replace(self.arr.get_unchecked_mut(idx), Slot::A(a)))
	}

	pub unsafe fn get_b(&self, idx: usize) -> &B {
		assume!(B, self.arr.get_unchecked(idx))
	}

	pub unsafe fn get_b_mut(&mut self, idx: usize) -> &mut B {
		assume!(B, self.arr.get_unchecked_mut(idx))
	}
}
