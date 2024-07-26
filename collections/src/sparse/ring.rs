use core::mem;

use super::inner::Core;

pub struct Ring<T, const N: usize> {
	core: Core<T, (), N>,
}

impl<T, const N: usize> Ring<T, N> {
	#[inline]
	pub fn get(&self, idx: usize) -> Option<&T> {
		let idx = idx % N;
		unsafe { self.core.is_a(idx).then(|| self.core.get_a(idx)) }
	}

	#[inline]
	pub fn get_mut(&mut self, idx: usize) -> Option<&mut T> {
		let idx = idx % N;
		unsafe { self.core.is_a(idx).then(|| self.core.get_a_mut(idx)) }
	}

	#[inline]
	pub fn remove(&mut self, idx: usize) -> Option<T> {
		let idx = idx % N;
		unsafe { self.core.is_a(idx).then(|| self.core.take_a(idx, ())) }
	}

	#[inline]
	pub fn insert(&mut self, idx: usize, t: T) -> Option<T> {
		let idx = idx % N;

		unsafe {
			if self.core.is_a(idx) {
				Some(mem::replace(self.core.get_a_mut(idx), t))
			} else {
				self.core.take_b(idx, t);
				None
			}
		}
	}
}

impl<T, const N: usize> Default for Ring<T, N> {
	fn default() -> Self {
		Self { core: Core::new(|_| ()) }
	}
}
