use utils::error::*;

/// The size of each word.
type Word = u64;

const WORD_LEN: u64 = Word::BITS as u64;
/// The number of words in the window.
const LEN: usize = 128;

/// Get the bitmask to access the bit in the word indexed by `n`.
#[inline]
fn mask(n: u64) -> Word {
	// The bit positions are Lsb-ordered
	1 << (n % WORD_LEN)
}

pub struct Window {
	/// The bit vector of seen packets
	bits: [Word; LEN],
	/// The highest seen byte index.
	head: u64,
}

impl Window {
	/// Initialise a new window with no set bits.
	#[inline]
	pub fn empty() -> Self {
		Self { bits: [0; LEN], head: 0 }
	}

	/// Initialise a new instance with `n` set.
	#[inline]
	pub fn new(n: u64) -> Self {
		let mut bits = [0; LEN];

		let head = n / WORD_LEN;
		bits[head as usize % LEN] |= mask(n);

		Self { bits, head }
	}

	/// Guard the index `n` before calling the function. If the function succeeds, set it in the window.
	#[inline]
	pub fn guard<X>(&mut self, n: u64, f: impl FnOnce() -> Result<X>) -> Result<X> {
		// Get the word index.
		let index = n / WORD_LEN;

		// Get the offset backwards from the highest-seen byte index to the current byte index.
		let y = match self.head.checked_sub(index) {
			// The packet is past the highest-seen byte index.
			None => {
				// If the packet index is past the highest-seen one, it must be unseen.
				let y = f()?;

				// Iterate from the window's current head to the new one
				while self.head < index {
					// Increment the head word
					self.head += 1;
					// Set new packets as unseen, including the current word
					self.bits[self.head as usize % LEN] = 0;
				}

				y
			}
			// If the packet is farther than the window size away from the highest seen packet, it is outside of the window, so drop it.
			Some(s) if s >= LEN as u64 => {
				log::warn!("Packet is not within window (dist: {} words)", s);
				return Err(());
			}
			// If the packet is present in the bit vector, it has already been seen, so drop it.
			Some(_) if self.bits[index as usize % LEN] & mask(n) != 0 => {
				log::warn!("Packet has already been seen");
				return Err(());
			}
			// The packet has not been seen yet.
			Some(_) => f()?,
		};

		// Mark the packet as seen after consuming it is successful.
		self.bits[index as usize % LEN] |= mask(n);

		Ok(y)
	}
}
