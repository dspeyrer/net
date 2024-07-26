use hashbrown::HashTable;
use slab::Slab;

pub struct Core<T, const N: usize> {
	slot: Slab<(T, u64)>,
	dict: HashTable<usize>,
}

impl<T, const N: usize> Default for Core<T, N> {
	fn default() -> Self {
		Self {
			slot: Slab::with_capacity(N),
			dict: HashTable::with_capacity(N),
		}
	}
}

impl<T, const N: usize> Core<T, N> {
	/// search for exact match of item, return None if none found
	pub fn find(&self, hash: u64, mut eq: impl FnMut(&T) -> bool) -> Option<usize> {
		self.dict.find(hash, |&i| eq(&self.slot[i].0)).copied()
	}

	/// search for exact match of item, return Err with insert index for hash if none found
	pub fn find_or_find_insert(&self, hash: u64, mut eq: impl FnMut(&T) -> bool) -> Result<usize, usize> {
		self.dict
			.find(hash, |&i| eq(&self.slot[i].0))
			.copied()
			.ok_or_else(|| self.slot.vacant_key())
	}

	/// return insert index for hash
	pub fn find_insert(&self, _hash: u64) -> usize {
		self.slot.vacant_key()
	}

	/// insert to slot, overwriting previous values
	pub fn insert(&mut self, i: usize, hash: u64, t: T) {
		let k = self.slot.insert((t, hash));
		self.dict.insert_unique(hash, k, |i| self.slot[*i].1);

		assert!(k == i);
	}

	/// read from slot, marking as removed
	pub fn remove(&mut self, i: usize) -> T {
		let (t, hash) = self.slot.remove(i);
		self.dict.find_entry(hash, |j| i == *j).expect("Should be present").remove();
		t
	}

	/// check whether index is filled. must be in bounds
	pub unsafe fn contains(&self, i: usize) -> bool {
		self.slot.contains(i)
	}

	/// unchecked get. must be filled & in bounds
	pub unsafe fn get(&self, i: usize) -> &T {
		&self.slot[i].0
	}

	/// unchecked mutable get. must be filled & in bounds
	pub unsafe fn get_mut(&mut self, i: usize) -> &mut T {
		&mut self.slot[i].0
	}
}
