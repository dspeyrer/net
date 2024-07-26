#![feature(const_size_of_val, const_pointer_is_aligned)]

pub mod bytes;
/// Utilities for storing integer-like data in different byteorders.
pub mod endian;
/// Error-handling utilities.
pub mod error;
