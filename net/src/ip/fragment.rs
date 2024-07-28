//! Packet fragmentation and reassembly.

use core::net::IpAddr;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use collections::bytes::Slice;
use utils::error::*;

use super::Protocol;

/// The identifying attributes of a fragmented packet.
/// TODO: consider whether the type-of-service and IPv6 flow fields should be included as well.
#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub struct Key {
	/// The source address of the packet.
	pub addr: IpAddr,
	/// The packet transport protocol.
	pub proto: Protocol,
	/// The identification value of the header. For IPv4, only 2 bytes of this value will be used.
	pub ident: u32,
}

/// A single packet fragment.
pub struct Fragment {
	/// Whether there are more fragments.
	pub more: bool,
	/// The byte offset of the fragment.
	pub start: u16,
	/// The byte data of the fragment.
	pub buf: Slice,
}

impl Fragment {
	/// Returns the end offset of this fragment (non-inclusive).
	fn end(&self) -> u16 {
		self.start + self.buf.len() as u16
	}
}

/// A partially-reassembled packed.
struct State {
	fragments: Vec<Fragment>,
}

impl State {
	/// Attempts to insert a packet fragment into the packet state. If successful, returns the insert index of the packet.
	fn try_insert(&mut self, fragment: Fragment) -> Result<(), Fragment> {
		// Get the insert index of the new fragment.
		let idx = match self.fragments.binary_search_by_key(&fragment.start, |x| x.start) {
			Err(idx) => idx,
			// If the search finds a match for the fragment, then there is an overlap.
			Ok(_) => return Err(fragment),
		};

		// Check for overlap with the preceding fragment.
		if let Some(f) = idx.checked_sub(1).and_then(|i| self.fragments.get(i)) {
			// Check if the start offset of this fragment intersects with the end offset of the current packet.
			if fragment.start < f.end() {
				return Err(fragment);
			}
		}

		// Check for overlap with the following fragment.
		if let Some(f) = self.fragments.get(idx) {
			// Check if this fragment is marked as the final fragment, but there is another one following it.
			if fragment.more {
				return Err(fragment);
			}

			// Check if the start offset of this fragment intersects with the end offset of the current packet.
			if f.start < fragment.end() {
				return Err(fragment);
			}
		}

		// Insert the fragment into the list, using the index derived from the binary search.
		self.fragments.insert(idx, fragment);

		Ok(())
	}

	// Try to assemble the fragments into a full packet.
	fn assemble(&self) -> Option<Slice> {
		// If the last fragment in the packet has the `more` flag set, then the packet is not done.
		if self.fragments.last()?.more {
			return None;
		}

		// Track the total length of the packet to create an allocation large enough to hold it.
		let mut total_len: usize = 0;
		// Track the next expected offset of a fragment for the packet to be continuous.
		let mut expected: u16 = 0;

		for f in &self.fragments {
			// If the start offset of the fragment does not match the expected one, the packet is not done.
			if f.start != expected {
				return None;
			}

			// Increment the total observed length.
			total_len += f.buf.len();
			// The expected start offset of the next packet is the end of the current one.
			expected += f.buf.len() as u16;
		}

		// If the packet is complete, then create a new allocation to hold it.
		let mut alloc = Slice::new(total_len);

		for f in &self.fragments {
			// Write the byte slices from each packet into the buffer.
			alloc[f.start as usize..][..f.buf.len()].copy_from_slice(&f.buf);
		}

		// Return the reassembled buffer.
		Some(alloc)
	}
}

/// Stores IP packet fragments for reassembly.
#[derive(Default)]
pub struct Store {
	/// Maps fragmentated packet identifiers to reassembly states.
	map: HashMap<Key, State>,
}

impl super::Interface {
	/// Consume a packet fragment, passing completed packets to upper-layer protocols.
	pub(super) fn handle_fragment(&mut self, key: Key, fragment: Fragment) -> Result {
		match self.fragment.map.entry(key) {
			Entry::Occupied(mut slot) => {
				let state = slot.get_mut();

				state.try_insert(fragment).map_err(|_| ())?;

				if let Some(buf) = state.assemble() {
					slot.remove();
					return self.handle(key.proto, key.addr, buf);
				}
			}
			// If there are no fragments associated with the key yet, then insert a new slot.
			Entry::Vacant(slot) => {
				slot.insert(State { fragments: vec![fragment] });
			}
		}

		Ok(())
	}
}
