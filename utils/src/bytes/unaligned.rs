use core::mem::align_of;
use core::net::{Ipv4Addr, Ipv6Addr};

use generic_array::{ArrayLength, GenericArray};
use x25519_dalek::PublicKey;

/// A marker trait indicating that a type has an alignment of 1.
///
/// ### Safety
/// It is only safe to implement this trait on a type if it has an alignment of 1.
pub unsafe trait Unaligned {}

macro_rules! impl_trait {
	( $( $ty:ty ),+ ) => {
		$( unsafe impl Unaligned for $ty {} )+
	};
}

unsafe impl<T: Unaligned> Unaligned for [T] {}

unsafe impl<T: Unaligned, const N: usize> Unaligned for [T; N] {}
unsafe impl<T: Unaligned, N: ArrayLength<T>> Unaligned for GenericArray<T, N> {}

unsafe impl<T> Unaligned for core::marker::PhantomData<T> {}

impl_trait!((), i8, u8);

type One = super::cast::V<1>;

unsafe impl Unaligned for Ipv4Addr where One: super::cast::Eq<{ align_of::<Ipv4Addr>() }> {}
unsafe impl Unaligned for Ipv6Addr where One: super::cast::Eq<{ align_of::<Ipv6Addr>() }> {}

unsafe impl Unaligned for PublicKey where One: super::cast::Eq<{ align_of::<PublicKey>() }> {}
