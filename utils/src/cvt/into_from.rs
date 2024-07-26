use core::marker::PhantomData;

use bilge::Bitsized;

use super::Cvt;

/// Convert layer which converts to and from A and B.
pub struct IntoFrom<A, B>(PhantomData<A>, B);

impl<A, B> Cvt for IntoFrom<A, B>
where
	A: From<B> + Into<B>,
	B: From<A>,
{
	type Target = A;

	fn to(self) -> A {
		self.1.into()
	}
}

impl<A, B> From<A> for IntoFrom<A, B>
where
	B: From<A>,
{
	fn from(value: A) -> Self {
		Self(PhantomData, value.into())
	}
}

/// IntoFrom for bilge bitfields
pub type Bitfield<T> = IntoFrom<T, <T as Bitsized>::ArbitraryInt>;
