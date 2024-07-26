mod index;
mod inner;

use core::hash::{BuildHasher, BuildHasherDefault, Hash};
use core::ops::{Deref, DerefMut};

use ahash::AHasher;
pub use index::{Index, ValidIndex};
use inner::Core;

// get, get_mut, find, find_mut, find_or_insert,    insert
//                         hash, hash+empty/del, empty/del

pub trait Key {
	type Type: Hash + Eq;

	/// Get the contained key.
	fn key(&self) -> &Self::Type;
}

pub struct Map<T, const N: usize, S = BuildHasherDefault<AHasher>> {
	core: Core<T, N>,
	hash: S,
}

impl<T, const N: usize, S: Default> Default for Map<T, N, S> {
	fn default() -> Self {
		Self { core: Core::default(), hash: S::default() }
	}
}

impl<T: Key, const N: usize, S: BuildHasher> Map<T, N, S>
where
	Index<N>: ValidIndex,
{
	#[must_use]
	pub fn new(hash: S) -> Self {
		Self { core: Default::default(), hash }
	}

	#[must_use]
	pub fn find(&self, k: &T::Type) -> Option<&T> {
		let hash = self.hash.hash_one(k);
		let idx = self.core.find(hash, |i| i.key() == k)?;
		// SAFETY: index was just returned from `find`
		Some(unsafe { self.core.get(idx) })
	}

	#[must_use]
	pub fn find_entry(&mut self, k: &T::Type) -> Entry<T, N> {
		let hash = self.hash.hash_one(k);
		match self.core.find_or_find_insert(hash, |i| i.key() == k) {
			Ok(idx) => Entry::Filled(Filled {
				map: &mut self.core,
				idx: unsafe { Index::new_unchecked(idx) },
			}),
			Err(idx) => Entry::Empty(Empty {
				map: &mut self.core,
				idx: unsafe { Index::new_unchecked(idx) },
				hash,
			}),
		}
	}

	#[inline]
	pub fn insert_unique(&mut self, k: &T::Type) -> Empty<T, N> {
		let hash = self.hash.hash_one(k);
		let idx = self.core.find_insert(hash);

		Empty {
			map: &mut self.core,
			idx: unsafe { Index::new_unchecked(idx) },
			hash,
		}
	}
}

impl<T: Key, const N: usize, S: BuildHasher> std::ops::Index<Index<N>> for Map<T, N, S>
where
	Index<N>: ValidIndex,
{
	type Output = T;

	fn index(&self, index: Index<N>) -> &Self::Output {
		unsafe {
			let i = index.get();
			assert!(self.core.contains(i), "entry at item {} does not exist!", i);
			self.core.get(i)
		}
	}
}

impl<T: Key, const N: usize, S: BuildHasher> std::ops::IndexMut<Index<N>> for Map<T, N, S>
where
	Index<N>: ValidIndex,
{
	fn index_mut(&mut self, index: Index<N>) -> &mut Self::Output {
		unsafe {
			let i = index.get();
			assert!(self.core.contains(i), "entry at item {} does not exist!", i);
			self.core.get_mut(i)
		}
	}
}

pub enum Entry<'a, T, const N: usize>
where
	Index<N>: ValidIndex,
{
	Filled(Filled<'a, T, N>),
	Empty(Empty<'a, T, N>),
}

impl<'a, T, const N: usize> Entry<'a, T, N>
where
	Index<N>: ValidIndex,
{
	pub fn filled(self) -> Option<Filled<'a, T, N>> {
		match self {
			Self::Filled(f) => Some(f),
			_ => None,
		}
	}

	pub fn remove(self) -> Option<T> {
		match self {
			Self::Filled(f) => Some(f.remove()),
			_ => None,
		}
	}
}

pub struct Filled<'a, T, const N: usize>
where
	Index<N>: ValidIndex,
{
	map: &'a mut Core<T, N>,
	idx: Index<N>,
}

impl<'a, T, const N: usize> Filled<'a, T, N>
where
	Index<N>: ValidIndex,
{
	#[inline]
	pub fn index(&self) -> Index<N> {
		self.idx
	}

	#[inline]
	pub fn into_ref(self) -> &'a mut T {
		unsafe { self.map.get_mut(self.idx.get()) }
	}

	#[inline]
	pub fn remove(self) -> T {
		self.map.remove(self.idx.get())
	}
}

impl<'a, T, const N: usize> Deref for Filled<'a, T, N>
where
	Index<N>: ValidIndex,
{
	type Target = T;

	fn deref(&self) -> &Self::Target {
		unsafe { self.map.get(self.idx.get()) }
	}
}

impl<'a, T, const N: usize> DerefMut for Filled<'a, T, N>
where
	Index<N>: ValidIndex,
{
	fn deref_mut(&mut self) -> &mut Self::Target {
		unsafe { self.map.get_mut(self.idx.get()) }
	}
}

pub struct Empty<'a, T, const N: usize>
where
	Index<N>: ValidIndex,
{
	map: &'a mut Core<T, N>,
	idx: Index<N>,
	hash: u64,
}

impl<'a, T: Key, const N: usize> Empty<'a, T, N>
where
	Index<N>: ValidIndex,
{
	#[inline]
	pub fn insert(self, t: T) -> Filled<'a, T, N> {
		self.map.insert(self.idx.get(), self.hash, t);
		Filled { map: self.map, idx: self.idx }
	}

	#[inline]
	pub fn index(&self) -> Index<N> {
		self.idx
	}
}
