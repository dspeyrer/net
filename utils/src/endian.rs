use bilge::Bitsized;

use crate::bytes::{Cast, Unaligned};

/// An integer type.
#[doc(hidden)]
pub trait SwapBytes {
	/// Swaps the bytes of the integer.
	fn swap(self) -> Self;
}

impl SwapBytes for u8 {
	#[inline(always)]
	fn swap(self) -> Self {
		self
	}
}

macro_rules! define_types {
	( $( $int:ident ($le:ident $be:ident) )* ) => {
		$(  // SwapBytes impls
			impl SwapBytes for $int {
				#[inline(always)]
				fn swap(self) -> Self {
					self.swap_bytes()
				}
			}

			#[doc = concat!("A ", stringify!($int), " represented in bytes in little-endian byteorder.")]
			#[allow(non_camel_case_types)]
			pub type $le = l<$int>;
			#[doc = concat!("A ", stringify!($int), " represented in bytes in big-endian byteorder.")]
			#[allow(non_camel_case_types)]
			pub type $be = b<$int>;
		)*
	};
	( $( $name:ident($endian:literal) $( $action:ident )? );* ) => {
		$(  // Byterepr structs
			#[doc = concat!("Represents a ", $endian, "-endian byte-sized integer value.")]
			#[repr(packed)]
			#[allow(non_camel_case_types)]
			pub struct $name<T: Bitsized>(pub T::ArbitraryInt);

			impl<T> $name<T>
			where
				T: Bitsized + From<T::ArbitraryInt>,
				T::ArbitraryInt: SwapBytes,
			{
				/// Retrieves a copy of the value being represented in native-endian, swapping bytes if needed.
				#[inline(always)]
				pub fn get(self) -> T {
					$( SwapBytes::$action )?(self.0).into()
				}
			}

			impl<T> $name<T>
			where
				T: Bitsized + TryFrom<T::ArbitraryInt>,
				T::ArbitraryInt: SwapBytes,
			{
				/// Retrieves a copy of the value being represented in native-endian, swapping bytes if needed.
				#[inline(always)]
				pub fn try_get(self) -> Result<T, T::Error> {
					$( SwapBytes::$action )?(self.0).try_into()
				}
			}

			impl<T> From<T> for $name<T>
			where
				T: Bitsized + Into<T::ArbitraryInt>,
				T::ArbitraryInt: SwapBytes,
			{
				/// Converts the value to the target endian representation.
				#[inline(always)]
				fn from(value: T) -> Self {
					Self($( SwapBytes::$action )?(value.into()))
				}
			}

			impl<T> Clone for $name<T>
			where
				T: Bitsized,
				T::ArbitraryInt: Copy {
				fn clone(&self) -> Self {
					*self
				}
			}

			impl<T> Copy for $name<T>
			where
				T: Bitsized,
				T::ArbitraryInt: Copy
			{}

			unsafe impl<T> Cast for $name<T>
			where
				T: Bitsized,
				T::ArbitraryInt: Cast
			{}

			unsafe impl<T> Unaligned for $name<T>
			where
				T: Bitsized
			{}
		)*
	};
}

define_types!( u16(u16le u16be) u32(u32le u32be) u64(u64le u64be) u128(u128le u128be) );

#[cfg(target_endian = "little")]
define_types!( l("little"); b("big") swap );
#[cfg(target_endian = "big")]
define_types!( l("little") swap; b("big") );
