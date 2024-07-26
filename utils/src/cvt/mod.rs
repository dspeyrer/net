use bilge::prelude::*;

use self::endian::A as BE;
use self::into_from::{Bitfield, IntoFrom};

pub mod endian;
pub mod into_from;

/// This trait is implemented on structs which are internal representations of types.
pub trait Cvt {
	/// This is the internal representation of the type.
	type Repr;
	/// This is the external representation of the type.
	type Target;

	/// Convert from an external representation to an internal representation.
	fn cvt(t: Self::Target) -> Self::Repr;
	/// Convert from an internal representation to an external representation.
	fn get(t: Self::Repr) -> Self::Target;
}

// outermost struct owns the representation

// Self is the inner representation, Target is the outer

// Self is the outer representation, Target is the inner

// Unalign<BigEndian<Bitfield<T>>>

// Bitfield<BigEndian<Unalign<T>>>

#[bitsize(16)]
#[derive(FromBits)]
struct Test {
	a: u6,
	b: u5,
	c: u5,
}

fn test() {
	// let test = Test::new(u6::new(4), u5::new(10), u5::new(30));
	// let field = Bitfield::from(big_endian);
	let big_endian = BE::cvt();
}
