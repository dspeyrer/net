#[doc(hidden)]
pub trait Ext<T, E> {
	fn ok_or(self, f: impl FnOnce(E)) -> Option<T>;
}

impl<T, E> Ext<T, E> for result::Result<T, E> {
	fn ok_or(self, f: impl FnOnce(E)) -> Option<T> {
		match self {
			Ok(v) => Some(v),
			Err(e) => {
				f(e);
				None
			}
		}
	}
}

#[doc(hidden)]
pub trait ExtOpaque<T> {
	fn some_or(self, f: impl FnOnce()) -> Option<T>;
}

impl<T> ExtOpaque<T> for Option<T> {
	fn some_or(self, f: impl FnOnce()) -> Option<T> {
		match self {
			Some(_) => {}
			None => f(),
		}

		self
	}
}

pub type Result<T = (), E = ()> = result::Result<T, E>;

use core::result;

pub use Ext as _;
