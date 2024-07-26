use core::slice;
use std::alloc::Layout;
use std::fmt::Debug;
use std::mem::{size_of, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

use serde::{Deserialize, Serialize};

#[repr(transparent)]
#[derive(Copy, Clone)]
struct Tag(u8);

impl Tag {
	#[inline]
	fn from_len(len: usize) -> Self {
		Self(((len as u8) << 1) | 1)
	}

	fn stack_len(self) -> Option<usize> {
		if self.0 & 1 == 1 {
			Some((self.0 >> 1) as usize)
		} else {
			None
		}
	}
}

#[cfg(target_endian = "little")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Boxed {
	ptr: NonNull<u8>,
	len: usize,
}

#[cfg(target_endian = "big")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Boxed {
	len: usize,
	ptr: NonNull<u8>,
}

impl Boxed {
	fn layout_for(len: usize) -> Layout {
		Layout::from_size_align(len, 2).unwrap()
	}
}

const INLINE_CAP: usize = size_of::<Boxed>() - 1;

#[cfg(target_endian = "little")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Stack {
	tag: Tag,
	buf: [MaybeUninit<u8>; INLINE_CAP],
}

#[cfg(target_endian = "big")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Stack {
	buf: [MaybeUninit<u8>; INLINE_CAP],
	tag: Tag,
}

pub union Store {
	boxed: Boxed,
	stack: Stack,
}

impl Debug for Store {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		<&[u8] as Debug>::fmt(&&**self, f)
	}
}

impl PartialEq for Store {
	fn eq(&self, other: &Self) -> bool {
		<&[u8] as PartialEq>::eq(&&**self, &&**other)
	}
}

impl Eq for Store {}

impl<'a> From<&'a [u8]> for Store {
	fn from(value: &'a [u8]) -> Self {
		let len = value.len();

		if len <= INLINE_CAP {
			let mut buf = [MaybeUninit::uninit(); INLINE_CAP];

			unsafe { (buf.as_mut_ptr() as *mut u8).copy_from_nonoverlapping(value.as_ptr(), len) };

			Self { stack: Stack { buf, tag: Tag::from_len(len) } }
		} else {
			let ptr = unsafe { std::alloc::alloc(Boxed::layout_for(len)) };

			unsafe { ptr.copy_from_nonoverlapping(value.as_ptr(), len) };

			let ptr = NonNull::new(ptr).unwrap();

			Self { boxed: Boxed { ptr, len } }
		}
	}
}

impl Deref for Store {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		unsafe {
			let (ptr, len) = match self.stack.tag.stack_len() {
				Some(len) => (self.stack.buf.as_ptr() as _, len as usize),
				None => (self.boxed.ptr.as_ptr(), self.boxed.len),
			};

			slice::from_raw_parts(ptr, len)
		}
	}
}

impl DerefMut for Store {
	fn deref_mut(&mut self) -> &mut Self::Target {
		unsafe {
			let (ptr, len) = match self.stack.tag.stack_len() {
				Some(len) => (self.stack.buf.as_mut_ptr() as _, len as usize),
				None => (self.boxed.ptr.as_ptr(), self.boxed.len),
			};

			slice::from_raw_parts_mut(ptr, len)
		}
	}
}

impl Serialize for Store {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_bytes(self)
	}
}

impl<'de> Deserialize<'de> for Store {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		struct Visitor;

		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = Store;

			fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
			where
				E: serde::de::Error,
			{
				Ok(Store::from(v))
			}

			fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
				formatter.write_str("bytes")
			}
		}

		deserializer.deserialize_bytes(Visitor)
	}
}

impl Drop for Store {
	fn drop(&mut self) {
		unsafe {
			if self.stack.tag.stack_len().is_none() {
				std::alloc::dealloc(self.boxed.ptr.as_ptr(), Boxed::layout_for(self.boxed.len));
			}
		}
	}
}

#[test]
fn test_repr() {
	let store = Store::from([0].as_slice());
	assert_eq!(unsafe { store.stack.tag.stack_len() }, Some(1));
}
