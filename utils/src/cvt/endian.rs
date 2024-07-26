use super::Cvt;

// Unalign(SwapBytes())

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
	( $( $int:ident ),* ) => {
		$( impl SwapBytes for $int {
			#[inline(always)]
			fn swap(self) -> Self {
				self.swap_bytes()
			}
		} )*
	};
}

// Big<Bitfield<T>>
// Bitfield<Big<T>>

pub struct A<T: Cvt>(T::Repr);

impl<T: Cvt> Cvt for A<T>
where
	T::Repr: SwapBytes,
{
	type Repr = T::Repr;
	type Target = T::Target;

	/// External -> Internal
	fn cvt(t: Self::Target) -> Self::Repr {
		T::cvt(t).swap()
	}

	/// Internal -> External
	fn get(t: Self::Repr) -> Self::Target {
		T::get(t.swap())
	}
}

define_types!(u16, u32, u64, u128);
