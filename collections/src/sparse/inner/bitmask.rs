use core::mem::{self, ManuallyDrop, MaybeUninit};

union Slot<A, B> {
	a: ManuallyDrop<A>,
	b: ManuallyDrop<B>,
}

/// A core which contains type metadata in an external bitvec.
pub struct Core<A, B, const N: usize> {
	/// A bitvec indexed Lsb-first, which indicates whether the corresponding slot has an item of A in it.
	bits: [u8; N],
	/// The slots of the Core. They are arranged in groups of 8 corresponding to the bytes in the `bits` array.
	arr: [[Slot<A, B>; 8]; N],
}

impl<A, B, const N: usize> Core<A, B, N> {
	pub fn new(f: impl Fn(usize) -> B) -> Self {
		let mut arr = MaybeUninit::uninit();

		let ptr = arr.as_mut_ptr() as *mut Slot<A, B>;

		for i in 0..(N * 8) {
			unsafe { ptr.add(i).write(Slot { b: ManuallyDrop::new(f(i)) }) }
		}

		Self { bits: [0; N], arr: unsafe { arr.assume_init() } }
	}

	pub unsafe fn is_a(&self, idx: usize) -> bool {
		let byte = *self.bits.get_unchecked(idx / 8);
		(byte >> (idx % 8)) & 1 == 0
	}

	unsafe fn get(&self, idx: usize) -> &Slot<A, B> {
		let ptr = self.arr.as_ptr() as *const Slot<A, B>;
		&*ptr.add(idx)
	}

	unsafe fn get_mut(&mut self, idx: usize) -> &mut Slot<A, B> {
		let ptr = self.arr.as_mut_ptr() as *mut Slot<A, B>;
		&mut *ptr.add(idx)
	}

	pub unsafe fn take_a(&mut self, idx: usize, b: B) -> A {
		ManuallyDrop::into_inner(mem::replace(self.get_mut(idx), Slot { b: ManuallyDrop::new(b) }).a)
	}

	pub unsafe fn get_a(&self, idx: usize) -> &A {
		&self.get(idx).a
	}

	pub unsafe fn get_a_mut(&mut self, idx: usize) -> &mut A {
		&mut self.get_mut(idx).a
	}

	pub unsafe fn take_b(&mut self, idx: usize, a: A) -> B {
		ManuallyDrop::into_inner(mem::replace(self.get_mut(idx), Slot { a: ManuallyDrop::new(a) }).b)
	}

	pub unsafe fn get_b(&self, idx: usize) -> &B {
		&self.get(idx).b
	}

	pub unsafe fn get_b_mut(&mut self, idx: usize) -> &mut B {
		&mut self.get_mut(idx).b
	}
}
