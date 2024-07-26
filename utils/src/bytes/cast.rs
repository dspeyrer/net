use core::mem::{size_of, size_of_val};
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4};
use core::slice;

use generic_array::{ArrayLength, GenericArray};
use x25519_dalek::{PublicKey, SharedSecret};

use crate::endian::u16be;

/// A marker trait indicating that a type can be used and interpreted as its raw bytes.
///
/// ### Safety
/// It is only safe to implement this trait on a type if it contains no uninitialized or padding bytes, and has no invalid states. It is recommended to use the derive macro instead.
pub unsafe trait Cast {}

/// Cast the current type as a reference to another type.
#[inline]
pub const fn cast<T: Cast, A: Cast + ?Sized>(a: &A) -> &T {
	let ptr: *const T = a as *const A as *const T;
	assert!(size_of::<T>() <= size_of_val(a) && ptr.is_aligned());
	unsafe { &*ptr }
}

/// Cast the current type as a slice of another type.
#[inline]
pub const fn as_slice<T: Cast, A: Cast + ?Sized>(a: &A) -> &[T] {
	let ptr: *const T = a as *const A as *const T;
	assert!(ptr.is_aligned());
	unsafe { slice::from_raw_parts(ptr, size_of_val(a) / size_of::<T>()) }
}

/// Mutably cast the current type as a reference to another type.
#[inline]
pub fn cast_mut<T: Cast, A: Cast + ?Sized>(a: &mut A) -> &mut T {
	let ptr: *mut T = a as *mut A as *mut T;
	assert!(size_of::<T>() <= size_of_val(a) && ptr.is_aligned());
	unsafe { &mut *ptr }
}

/// Mutably cast the current type as a slice of another type.
#[inline]
pub fn as_slice_mut<T: Cast, A: Cast + ?Sized>(a: &mut A) -> &mut [T] {
	let ptr: *mut T = a as *mut A as *mut T;
	assert!(ptr.is_aligned());
	unsafe { slice::from_raw_parts_mut(ptr, size_of_val(a) / size_of::<T>()) }
}

macro_rules! impl_trait {
	( $( $ty:ty ),+ ) => {
		$( unsafe impl Cast for $ty {} )+
	};
}

pub struct V<const X: usize>;
pub trait Eq<const X: usize> {}
impl<const X: usize> Eq<X> for V<X> {}

unsafe impl<T: Cast> Cast for [T] {}

unsafe impl<T: Cast, const N: usize> Cast for [T; N] {}
unsafe impl<T: Cast, N: ArrayLength<T>> Cast for GenericArray<T, N> {}

unsafe impl<T> Cast for core::marker::PhantomData<T> {}

impl_trait!((), i8, u8, i16, u16, i32, u32, f32, i64, u64, f64, i128, u128, isize, usize);

macro_rules! impl_expect {
	($($ty:ty: $size:literal)*) => {
		$( unsafe impl Cast for $ty where V<{ size_of::<Self>() }>: Eq<$size> {} )*
	};
}

impl_expect!(
	Ipv4Addr: 4
	Ipv6Addr: 16

	SocketAddrV4: 6

	PublicKey: 32
	SharedSecret: 32

	(Ipv4Addr, u16be): 6
	(Ipv6Addr, u16be): 18
);
