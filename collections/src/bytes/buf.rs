use super::Cursor;

pub struct Buf {
	/// The underlying allocation.
	bytes: Box<[u8]>,
	/// A type-casted pointer indicating the number of bytes which have been filled.
	filled: usize,
}

impl Buf {
	/// Constructs a new `Buf` instance from zeroed bytes.
	pub fn zeroed(len: usize) -> Self {
		// Allocate a zeroed buffer.
		let bytes = Box::new_zeroed_slice(len);
		// u8 with value 0 is always initialised.
		let bytes = unsafe { bytes.assume_init() };
		// Get the base pointer of the allocation.
		let base = bytes.as_ptr() as usize;
		// Construct the buffer.
		Self { bytes, filled: base }
	}

	/// Get a write cursor into the buffer.
	pub fn cursor(&mut self) -> Cursor<'_> {
		Cursor { slice: &mut self.bytes, pivot: &mut self.filled }
	}

	/// Gets the number of bytes which have been filled.
	fn len(&self) -> usize {
		// Get the base pointer.
		let base = self.bytes.as_ptr() as usize;
		// The difference between the base pointer and the filled pointer is the length of the filled section.
		self.filled - base
	}

	/// Get a slice of the filled part of the buffer.
	pub fn filled(&self) -> &[u8] {
		// Get the number of bytes which have been filled.
		let len = self.len();
		// Return that subslice.
		&self.bytes[..len]
	}

	/// Reset the buffer.
	pub fn clear(&mut self) {
		// Reset the filled pointer to the base allocation pointer.
		self.filled = self.bytes.as_ptr() as usize;
	}
}
