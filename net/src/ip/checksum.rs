/// An implementation of [RFC 1071]'s internet checksum, used by procotols such as TCP, IP, and UDP.
///
/// [RFC 1071]: [https://datatracker.ietf.org/doc/html/rfc1071]
#[derive(Clone, Default)]
pub struct Checksum {
	acc: u64,
}

impl Checksum {
	/// Create a new checksum calculation state.
	#[inline]
	pub fn of(buffer: &[u8]) -> Self {
		let mut csum = Self::default();
		csum.push(buffer);
		csum
	}

	/// Create a new checksum calculation state initialised with a value.
	#[inline]
	pub fn with(word: &[u8; 4]) -> Self {
		Self { acc: u32::from_ne_bytes(*word) as u64 }
	}

	/// Add bytes to the checksum calcuation.
	#[inline]
	pub fn push(&mut self, buffer: &[u8]) {
		let (chunks, rem) = buffer.as_chunks();

		for word in chunks {
			self.push_chunk(word);
		}

		if rem.len() != 0 {
			let mut buf = [0; 4];
			buf[..rem.len()].copy_from_slice(rem);
			self.push_chunk(&buf);
		}
	}

	/// Adds a single word to the checksum calculation.
	#[inline]
	pub fn push_chunk(&mut self, word: &[u8; 4]) {
		self.acc += u32::from_ne_bytes(*word) as u64;
	}

	/// Finalize checksum calculation and return its byte-representation, consuming the [`Checksum`] instance.
	#[inline]
	pub fn end(self) -> [u8; 2] {
		let acc = (self.acc >> 32) as u32 + self.acc as u32;

		let (acc, c) = (acc as u16).overflowing_add((acc >> 16) as u16);
		let acc = acc + c as u16;

		(!acc).to_ne_bytes()
	}
}
