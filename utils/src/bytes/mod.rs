#[doc(hidden)]
pub mod cast;
mod unaligned;

pub use cast::{as_slice, as_slice_mut, cast, cast_mut, Cast};
pub use macros::Cast;
pub use unaligned::Unaligned;
